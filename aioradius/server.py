"""
aioradius.server

This module contain classes for creating RADIUS servers:
    RadiusService - abstract class that define interface for RADIUS packet handler
    AbstractRadiusServer - abstract subclass of RadiusService that implement basic functions of RADIUS server
    RadiusAuthProtocol, RadiusAccountingProtocol - classes that implement protocol of handling RADIUS packets

and exceptions:
    RadiusServerError - raise if an error occurred in initialize process
    RadiusResponseError - can be raised at RadiusService methods `nas_validation`, `on_auth_packet` or `on_acct_packet`
"""
from abc import ABC, abstractmethod
import asyncio
import functools
import inspect
from ipaddress import IPv4Address
import logging
import os
import signal
import socket
from random import randint

from expiringdict import ExpiringDict

try:
    import uvloop
except ImportError:
    uvloop = None
else:
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from aioradius import class_fullname, PeriodicTask, packet, RadiusClient, periodic_task, \
    async_cancel_tasks, cancel_tasks

__author__ = 'arusinov'

LOOP_TIME_MULTIPLEX = 1000
DEFAULT_HOST = '0.0.0.0'
DEFAULT_AUTH_PORT = 1812
DEFAULT_ACC_PORT = 1813
DEFAULT_DAS_PORT = 3799

class RadiusServerError(Exception):
    pass


class RadiusResponseError(Exception):
    """
    This exceptions must be raised at method `on_auth_packet` or `on_acc_packet`
    of subclass of `RadiusService`
    if handle process has problem
    """
    pass


class RadiusService(ABC):
    """
    Subclasses of abstract class `RadiusService` must implement
    methods `nad_validation`, `handle_auth_request` and `handle_acc_request`
    for concrete handle of RADIUS packet
    """
    logger = logging.getLogger('RadiusService')

    @abstractmethod
    def validate_nas(self, remote_addr):
        """
        Validate access for NAS and get shared_key
        This method can be an asyncio.coroutine or simple sync function

        Return:
            shared_secret - shared secret between NAS and client
        Raise:
            RadiusResponseError if NAS is not valid
        """
        pass

    def on_auth_packet(self, request_attributes):
        """
        Handle Access-Request packet and generate response
        This method can be an asyncio.coroutine or simple sync function

        Params:
            request_attributes - instance of AttributesSet

        Return:
            (
                response_attributes - iterable of pairs (AttributeName, AttributeValue)
                response_code - any of ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE
            )
        Raise:
            RadiusResponseError
        """
        raise NotImplementedError

    def on_acct_packet(self, request_attributes):
        """
        Handle Accounting-Request packet and generate response
        This method can be an asyncio.coroutine or simple sync function

        Params:
            request_attributes - instance of AttributesSet

        Return:
            (
                response_attributes - iterable of pairs (AttributeName, AttributeValue),
                None
            )
        Raise:
            RadiusResponseError(session_id, message)
        """
        raise NotImplementedError

    def register_exception(self, exc):
        """
        Register exception that raised at handle process
        This method can be overwritten by real implementation
        """
        pass


class _RadiusAbstractProtocol(asyncio.DatagramProtocol):
    """
    Class `_RadiusAbstractProtocol` implement common functions of all radius protocols
    You cant instantiate this class directly, use concrete implementation of protocol
    """
    SERVICE_NAME = None

    def __init__(self, radius_service, loop=None, logger=None):
        """
        Initialize RADIUS protocol

        Params:
            radius_service - it is instance of any subclass of class(interface) `RadiusService`
            loop - optional asyncio event loop if radius_service not has self.loop
            logger - optional logging.Logger object if radius_service not has self.logger

        Raise:
            RuntimeError if parameters are passed with an error
        """
        if self.SERVICE_NAME is None:
            raise RuntimeError("You cat use _RadiusAbstractProtocol directly")
        if not isinstance(radius_service, RadiusService):
            raise RuntimeError("Parameter 'RadiusService' must be an object of 'RadiusService' class")

        self.radius_service = radius_service

        if loop is None or not isinstance(loop, asyncio.AbstractEventLoop):
            if hasattr(self.radius_service, 'loop'):
                self.loop = self.radius_service.loop
            else:
                self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop

        if logger is None or not isinstance(logger, logging.Logger):
            if hasattr(self.radius_service, 'logger'):
                self.logger = self.radius_service.logger
            else:
                self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

        self.transport = None
        self.local_addr = (None, None)
        self.__wait_for_close_event = None
        self.__cache = ExpiringDict(max_len=100, max_age_seconds=5)


    def connection_made(self, transport):
        """
        Called when a connection is made.
        When the connection is closed, connection_lost() is called.
        """
        self.transport = transport
        self.local_addr = self.transport.get_extra_info('sockname')
        self.logger.info("Listen on UDP {}:{} for {service_type}".format(
            *self.local_addr,
            service_type=self.SERVICE_NAME
        ))
        self.__wait_for_close_event = asyncio.Event(loop=self.loop)

    def connection_lost(self, exc):
        """
        Called when the connection is lost or closed.

        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        if exc is not None:
            self.logger.error("Server socket {}:{} is broken for {service_type}, {exc}".format(
                *self.local_addr,
                service_type=self.SERVICE_NAME,
                exc=exc
            ))
        else:
            self.logger.info("Server socket {}:{} is closed for {service_type}".format(
                *self.local_addr,
                service_type=self.SERVICE_NAME
            ))
        if self.__wait_for_close_event is not None:
            self.__wait_for_close_event.set()

    def wait_for_close(self):
        """
        Run event loop until connection is not closed and method `connection_lost`
        is not called
        """
        if self.__wait_for_close_event is not None:
            self.loop.run_until_complete(self.__wait_for_close_event.wait())

    def is_closed(self):
        """
        Return closing status of connection
        """
        return self.__wait_for_close_event.is_set()

    def datagram_received(self, data, remote_addr):
        """
        Called when some datagram is received.
        It start the handle RADIUS packet process
        """
        remote_host, remote_port = remote_addr
        identifier = packet.get_packet_identifier(data)
        cache_key = "{}:{}/{}".format(remote_host, remote_port, identifier)
        response_from_cache, age = self.__cache.get(cache_key, with_age=True)
        if response_from_cache is None:
            self.__begin_nas_validation(data, remote_addr)
        else:
            self.logger.debug("Got response from cache for remote {}:{} and identifier {}, age - {}".format(
                remote_host, remote_port, identifier,
                age
            ))
            self.__send_response(response_from_cache, remote_addr)

    def __begin_nas_validation(self, data, remote_addr):
        """
        Begin NAS access validation
        If self.radius_service.nas_validation is a coroutine function
        that add it to event loop for executing
        If self.radius_service.nas_validation is a simple sync method
        that execute it and used pseudo task
        """
        if asyncio.iscoroutinefunction(self.radius_service.validate_nas):
            handler = asyncio.ensure_future(
                self.radius_service.validate_nas(remote_addr),
                loop=self.loop
            )
        else:
            handler = self.loop.run_in_executor(
                None,
                self.radius_service.validate_nas,
                remote_addr
            )
        handler.add_done_callback(
            functools.partial(self.__after_nas_validation,
                              data=data,
                              remote_addr=remote_addr
            )
        )
        return

    def __after_nas_validation(self, task, data, remote_addr):
        """
        Called when self.radius_service.nas_validation task is done

        If nas_validation raised exception than log it and stop handle process (not response to client)
        else continue handle process with calling method `handle_request`
        """
        task.remove_done_callback(self.__after_nas_validation)
        try:
            secret = task.result()
        except Exception as e:
            self.radius_service.register_exception(e)
        else:
            self.handle_request(data, remote_addr, secret)

    @property
    def request_class(self):
        """
        This property must return a class of RADIUS packet request (AccessRequest or AccountingRequest)
        """
        raise NotImplementedError

    @property
    def response_handler(self):
        """
        This property must return a handle method of subclass of `_RadiusAbstractProtocol`
        (on_auth_packet or on_acc_packet)
        """
        raise NotImplementedError

    def get_response_for_status(self, status_server):
        raise NotImplementedError

    def handle_request(self, data, remote_addr, secret):
        """
        Handle received from remote_addr data, decode it to RADIUS request packet
        and call self.radius_service.response_handler

        Params:
            data - received from network bytes sequence
            remote_addr - tuple. pair of remote host and port
            secret - shared secret between NAS and server
        """
        request_time = self.loop.time()
        try:
            # Trying decode and verify data as radius Access-Request packet
            request = packet.decode_request(secret, data, radius_type=self.SERVICE_NAME)
        except Exception as e:
            self.radius_service.register_exception(
                ValueError("Ignore data from {}:{}, it is not radius packet or packet is not valid".format(
                    *remote_addr
                ))
            )
            return

        self.logger.info("Received {} from {}:{}".format(
            request,
            remote_addr[0], remote_addr[1]
        ))
        self.logger.debug(packet.packet_view(request))
        if isinstance(request, packet.StatusServer):
            status_response = self.get_response_for_status(request)
            self.__send_response(status_response, remote_addr, request_time = request_time)
            return
        else:
            if asyncio.iscoroutinefunction(self.response_handler):
                handler = asyncio.ensure_future(
                    self.response_handler(request.attributes),
                    loop=self.loop
                )
            else:
                handler = self.loop.run_in_executor(
                    None,
                    self.response_handler,
                    request.attributes
                )
            handler.add_done_callback(
                functools.partial(self.handle_response,
                              request=request,
                              remote_addr=remote_addr,
                              request_time=request_time
                )
            )
            return

    def handle_response(self, response_task, request, remote_addr, request_time = 0):
        """
        Called when `handle_auth_request` or `handle_acc_request` method of self.radius_service task is done

        If handle method raised exception than register it and stop handle process (not response to client)
        else continue handle process with calling method `__send_response`
        """
        response_task.remove_done_callback(self.handle_response)
        try:
            response_attributes, response_code = response_task.result()
        except Exception as e:
            self.radius_service.register_exception(e)
        else:
            try:
                response = request.create_reply(response_code)
                response.attributes.extend(*response_attributes)
                bytes(response)
            except Exception as e:
                self.radius_service.register_exception(e)
                return
            remote_host, remote_port = remote_addr

            cache_key = "{}:{}/{}".format(remote_host, remote_port, response.identifier)
            self.__cache[cache_key] = response

            self.__send_response(response, remote_addr, request_time=request_time)

    def __send_response(self, response, response_addr, request_time=0):
        """
        Send response to the client

        Params:
            response - bytes sequence for sending to client
            response_addr - tuple, pair of host and port of client
        """
        try:
            encoded_ = bytes(response)
        except Exception as e:
            self.radius_service.register_exception(e)
            return

        try:
            response_host, response_port = response_addr
            self.transport.sendto(encoded_, response_addr)
        except Exception as e:
            self.radius_service.register_exception(e)
            self.logger.error("Cant sent response to {}:{}, {exc_message}".format(
                *response_addr,
                exc_message=str(e) or type(e).__name__
            ))
            return
        else:
            time_info = ''
            if request_time > 0:
                exec_time = (self.loop.time() - request_time) * LOOP_TIME_MULTIPLEX
                time_info = ' (processed by {:.4f} ms)'.format(exec_time)
            self.logger.debug(packet.packet_view(response))
            self.logger.info("Sent {} to {}:{}{}".format(
                response,
                response_host, response_port,
                time_info
            ))


class RadiusAuthProtocol(_RadiusAbstractProtocol):
    """
    Class `RadiusAuthProtocol` implement authentication protocol of RADIUS server
    """
    SERVICE_NAME = 'auth'

    @property
    def request_class(self):
        return packet.AccessRequest

    @property
    def response_handler(self):
        return self.radius_service.on_auth_packet

    def get_response_for_status(self, status_server):
        return packet.AccessAccept(status_server.secret_key,
                                   identifier=status_server.identifier,
                                   request_authenticator=status_server.authenticator)


class RadiusAccountingProtocol(_RadiusAbstractProtocol):
    """
    Class `RadiusAccountingProtocol` implement accounting protocol of RADIUS server
    """
    SERVICE_NAME = 'acc'

    @property
    def request_class(self):
        return packet.AccountingRequest

    @property
    def response_handler(self):
        return self.radius_service.on_acct_packet

    def get_response_for_status(self, status_server):
        return packet.AccountingResponse(status_server.secret_key,
                                   identifier=status_server.identifier,
                                   request_authenticator=status_server.authenticator)


class AbstractRadiusServer(RadiusService):

    def __init__(self,
                 host=DEFAULT_HOST,
                 auth_port=DEFAULT_AUTH_PORT,
                 acc_port=DEFAULT_ACC_PORT,
                 loop=None,
                 init_dac_client=True
    ):
        """
        Create class instance or raise RadiusServerError if cant create it
        """
        # Verifying param `host`, it must be IP-address or hostname
        # Raise ServerError if host is not IP-address and not hostname
        self.logger = logging.getLogger(self.__class__.__name__)

        self.loop = loop or asyncio.new_event_loop()

        self.host = self.__validate_host(host)
        self.auth_port = self.__validate_port(auth_port)
        self.acc_port = self.__validate_port(acc_port)

        self.process_id = os.getpid()
        self.parent_process_id = os.getppid()

        self.__is_stoped = False
        self.__start_time = 0
        self.__stop_time = 0

        self.logger.debug("Used {} as event_loop".format(class_fullname(self.loop)))

        # Get methods decorated with @periodic_task and create for it PeriodicTask instances
        self.periodic_tasks = []
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if inspect.ismethod(attr) and hasattr(attr, 'is_periodic_task') and attr.is_periodic_task:
                self.periodic_tasks.append(PeriodicTask(self.loop, attr, delay=attr.delay))

        self.__auth_transport = None
        self.__auth_proto = None

        self.__acc_transport = None
        self.__acc_proto = None

        if init_dac_client:
            self.__dac = RadiusClient(loop=self.loop)
        else:
            self.__dac = None

    @staticmethod
    def __validate_host(host):
        if host == '0.0.0.0':
            validated_host = host
        try:
            validated_host = IPv4Address(host)
        except ValueError:
            try:
                validated_host = socket.gethostbyname(host)
            except:
                raise RadiusServerError("Bad value of host '{}', use IPv4 address or hostname".format(host))
        return str(validated_host)

    @staticmethod
    def __validate_port(port):
        if port is None:
            return None
        try:
            validated_port = int(port)
        except (ValueError, TypeError):
            raise RadiusServerError("Bad value of UDP port '{}'".format(port))
        return validated_port

    @property
    def uptime(self):
        return self.__stop_time - self.__start_time

    def get_event_loop(self):
        return self.loop

    def __initialize_udp_endpoints(self):
        try:
            if asyncio.iscoroutinefunction(self.on_auth_packet):
                self.loop.run_until_complete(self.on_auth_packet(None))
            else:
                self.on_auth_packet(None)
        except NotImplementedError:
            self.logger.warning("Method `on_auth_packet` is not implemented, auth port wouldn't be listen")
            self.auth_port = None
        except Exception:
            pass
        try:
            if asyncio.iscoroutinefunction(self.on_acct_packet):
                self.loop.run_until_complete(self.on_acct_packet(None))
            else:
                self.on_acct_packet(None)
        except NotImplementedError:
            self.logger.warning("Method `on_acct_packet` is not implemented, acct port wouldn't be listen")
            self.acc_port = None
        except Exception:
            pass

        any_port_is_listen = False
        if self.auth_port is not None:
            # Listen UDP socket for auth
            try:
                self.__auth_transport, self.__auth_proto = self.loop.run_until_complete(
                    self.loop.create_datagram_endpoint(
                        lambda: RadiusAuthProtocol(self),
                        local_addr=(self.host, self.auth_port)
                    )
                )
                any_port_is_listen = True
            except OSError as e:
                raise RadiusServerError("Cant listen UDP socket for auth on port {}, {!s}".format(
                    self.auth_port, e)
                )

        if self.acc_port is not None:
            # Listen UDP socket for acc
            try:
                self.__acc_transport, self.__acc_proto = self.loop.run_until_complete(
                    self.loop.create_datagram_endpoint(
                        lambda: RadiusAccountingProtocol(self),
                        local_addr=(self.host, self.acc_port)
                    )
                )
                any_port_is_listen = True
            except OSError as e:
                raise RadiusServerError("Cant listen UDP socket for acc on port {}, {!s}".format(
                    self.acc_port, e)
                )
        if not any_port_is_listen:
            raise RadiusServerError("Server is not listen any port")

    def __close_udp_endpoints(self):
        # Close and wait_for_close UDP socket for auth
        if self.__auth_transport is not None:
            self.__auth_transport.close()
            self.__auth_proto.wait_for_close()

        # Close and wait_for_close UDP socket for acc
        if self.__acc_transport is not None:
            self.__acc_transport.close()
            self.__acc_proto.wait_for_close()

    def __schedule_periodic_task(self):
        # Starting periodic tasks
        for item in self.periodic_tasks:
            item.start()

    def __unschedule_periodic_task(self):
        # Stop periodic tasks
        for item in self.periodic_tasks:
            item.stop()

    def shutdown(self):
        self.__is_stoped = True

    @asyncio.coroutine
    def __serve(self, future=None):
        try:
            if future is not None:
                yield from future
            else:
                while not self.__is_stoped:
                    yield from asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self.register_exception(exc)
        finally:
            pass
            async_cancel_tasks(self.loop)

    @asyncio.coroutine
    def on_startup(self):
        return

    @asyncio.coroutine
    def on_shutdown(self, *args, **kwargs):
        return

    def close_dac(self):
        # Close DAC client
        if isinstance(self.__dac, RadiusClient):
            self.__dac.close()



    def run(self, future=None):
        # Log server process ID
        self.logger.info("Starting '{}' with PID {}(parent ID: {})".format(
            self.__class__.__name__,
            self.process_id,
            self.parent_process_id
        ))
        self.__start_time = self.loop.time()
        # Event loop is not running
        self.loop.run_until_complete(self.on_startup())
        if not self.__is_stoped:

            self.__initialize_udp_endpoints()
            self.__schedule_periodic_task()


            self.loop.add_signal_handler(signal.SIGTERM, self.shutdown)
            

            if future is not None:
                if asyncio.iscoroutine(future):
                    future = asyncio.ensure_future(future, loop=self.loop)

            # Start server event loop
            try:
                self.loop.run_until_complete(self.__serve(future))
            except KeyboardInterrupt:
                self.logger.info("Server '{}' process was interrupted".format(self.__class__.__name__))
                if future is not None:
                    future.cancel()
                self.shutdown()
            except asyncio.CancelledError:
                self.logger.info("Server '{}' process was interrupted".format(self.__class__.__name__))
                if future is not None:
                    future.cancel()
                self.shutdown()
        
        self.loop.remove_signal_handler(signal.SIGTERM)
        cancel_tasks(self.loop)

        self.loop.run_until_complete(self.on_shutdown())
        self.close_dac()
        self.__unschedule_periodic_task()
        self.__close_udp_endpoints()


        self.__stop_time = self.loop.time()
        # Stop event loop
        if not self.loop.is_running():
            self.loop.stop()

        if not self.loop.is_closed():
            self.loop.close()
        self.logger.info("'{}' was stopped, uptime - {:.2f} sec".format(
                self.__class__.__name__,
                self.uptime
        ))

    async def send_to_das(self, request, das_host, das_port=DEFAULT_DAS_PORT, **kwargs):
        """ Async Send Disconnect-Request or CoA-Request to DAS and async return response from DAS """
        if not isinstance(request, (packet.DisconnectRequest, packet.CoARequest)):
            raise RadiusServerError("You can send to DAS packet only of type DisconnectRequest or CoaRequest")

        if 'NAS-IP-Address' not in request.attributes and 'NAS-Identifier' not in request.attributes:
            request.attributes.extend(('NAS-IP-Address', str(das_host)),)

        # TODO: Разобраться с генерацией authenticator-а
        bytes(request)
        response_future = await self.__dac.send_packet(request, das_host, das_port, **kwargs)
        self.logger.info("Sent '{0!s}' to '{1}:{2}'".format(request, das_host, das_port))
        self.logger.debug(packet.packet_view(request))



        response, response_time = await response_future
        self.logger.info("Got '{0!s}' from '{1}:{2}' (processed by {3:.4f} ms)".format(
            response, das_host, das_port, response_time))
        self.logger.debug(packet.packet_view(response))

        return response


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    class OnlyListenServer(AbstractRadiusServer):

        @asyncio.coroutine
        def on_startup(self):
            self.logger.info("on_startup of {}".format(self.__class__.__name__))

        @asyncio.coroutine
        def on_shutdown(self, *args, **kwargs):
            self.logger.info("on_shutdown of {}".format(self.__class__.__name__))

        def validate_nas(self, remote_addr):
            pass

        def on_auth_packet(self, request_attributes):
            raise RadiusResponseError("I am not response at Access-Request")

        #def on_acct_packet(self, request_attributes):
        #    raise RadiusResponseError("I am not response at Access-Request")

        @periodic_task(delay=5)
        def periodic(self):
            self.loop.create_task(self.background_task())
            self.logger.debug("I`m alive")

        TASKS_COUNTER = 0

        @asyncio.coroutine
        def background_task(self):
            self.TASKS_COUNTER += 1
            current_id = self.TASKS_COUNTER
            self.logger.debug("Starting background task {}".format(current_id))
            try:
                yield from asyncio.sleep(randint(1, 10))
            except asyncio.CancelledError:
                self.logger.debug("Background task {} is canceled".format(current_id))
                return
            else:
                self.logger.debug("Background task {} is completed".format(current_id))

    server = OnlyListenServer()
    server.run(asyncio.sleep(30))
    #server.run()