"""
aioradius.client

This module contain two classes:
Class `ClientDatagramEndpoint` implement asyncio.DatagramProtocol with functions for sending/receiving data
Class `RadiusClient` implement client object with one or more datagram endpoints

Client simple usage example:
    # Initialize client
    client = RadiusClient(event_loop)

    # Initialize RADIUS packet
    request = packet.AccessRequest('SHARED_SECRET')
    # If need adding attributes to packet:
    requests.add_attributes(
        ('User-Name', 'username'),
        ('User-Password', 'password')
    )
    # Then we are send packet and create response future. that will be done when server send response
    # Method `send_packet` is an asyncio.coroutine and if need it async create new endpoint
    response_future =  event_loop.run_until_complete(
        client.send_packet(
            request,
            remote_host = 'server.radius', # If not set will be used client.default_server
            remote_port = 1812 # If not set will be used client.default_port
        )
    )
    # Then we are wait while response_future is done
    event_loop.run_until_complete(response_future)

    # When it is done trying to get results
    try:
        response, response_time = response_future.result()
    except Exception as e:
        print("Response is not received, ", str(e))

    # Close client
    client.close()

Client usage in coroutine:
    # Initialize client
    event_loop = asyncio.get_event_loop()
    client = RadiusClient(event_loop, default_server='localhost', default_port=1812, client_identifier='blafoo')

    @asyncio.coroutine
    def coro(client):
        # Initialize RADIUS packet
        request = packet.AccessRequest('SHARED_SECRET')
        # If need adding attributes to packet:
        requests.add_attributes(
            ('User-Name', 'username'),
            ('User-Password', 'password')
        )
        response_future = yield from client.send_packet(request)
        response, response_time = yield from response_future

    OR

    async def coro(client):
        # Initialize RADIUS packet
        request = packet.AccessRequest('SHARED_SECRET')
        # If need adding attributes to packet:
        requests.add_attributes(
            ('User-Name', 'username'),
            ('User-Password', 'password')
        )
        response_future = await client.send_packet(request)
        response, response_time = await response_future


    event_loop.run_until_complete(coro(client))
    # Close client
    client.close()
"""
import asyncio
import logging
import socket
from ipaddress import IPv4Address

from aioradius import PeriodicTask, execute_time
from aioradius.protocol import packet

__author__ = 'arusinov'

logger = logging.getLogger(__name__)

DEFAULT_RESPONSE_TIMEOUT = 3
LOOP_TIME_MULTIPLEX = 1000

class ClientDatagramEndpoint(asyncio.DatagramProtocol):
    """
    Class `ClientDatagramEndpoint` implement asyncio.DatagramProtocol for sending/receiving data

    Attributes:
        loop(asyncio.Loop) - event loop
        identifiers_counter(int) - counter of unique identifier, that added to RADIUS request,
                              its value must be unique for (client_ip, client_port and identifier).
                              For details, see RFC2865 section 3
        transport(asyncio.DatagramTransport) - current transport for this endpoint
    Instantiating:
        Object of class `ClientDatagramEndpoint` can be instantiate with fabric coroutine method `create`
    """

    @classmethod
    @asyncio.coroutine
    def create(cls, remote_host, remote_port, loop):
        """
        Fabric coroutine method for create new `ClientDatagramEndpoint` object

        Params:
            remote_host - IP-address or hostname of RADIUS server
            remote_port - port number of RADIUS server
            secret_key - shared secret for client and server
            loop - event loop

        Return object of `ClientDatagramEndpoint` (asyncio.DatagramProtocol)
        """
        transport, protocol = yield from loop.create_datagram_endpoint(
            lambda: ClientDatagramEndpoint(loop),
            remote_addr=(str(remote_host), remote_port)
        )
        return protocol

    def __init__(self, loop):
        self.loop = loop
        # Set initial value of identifier
        self.identifiers_counter = packet.MIN_IDENTIFIER
        self.__futures = dict()
        self.transport = None

    def get_enpoint_addresses(self):
        """
        Return 4 elements of datagram client endpoint:
        local address, local port, remote address and remote port
        """
        remote_addr, remote_port = self.transport.get_extra_info('peername')
        local_addr, local_port = self.transport.get_extra_info('sockname')
        return local_addr, local_port, remote_addr, remote_port

    def connection_made(self, transport):
        """ This method will be called when datagram endpoint is created
        Params:
            transport(asyncio.DatagramTransport) - transport for datagram endpoint
        """
        self.transport = transport
        logger.info("Created datagram endpoint from {}:{} to {}:{}".format(
            *self.get_enpoint_addresses()
        ))

    def connection_lost(self, exc):
        """ This method will be called when datagram endpoint will be closed or raised exception """
        if exc is not None:
            logger.error("Datagram endpoint from {}:{} to {}:{} is broken".format(
                *self.get_enpoint_addresses()
            ))
            logger.error(exc)
        else:
            logger.info("Datagram endpoint from {}:{} to {}:{} is closed".format(
                *self.get_enpoint_addresses()
            ))


    def datagram_received(self, data, remote_address):
        """
        This method will be called when client receive data from server
        It trying to "close" the future, that was created when client send request to server

        Params:
            data(bytes) - data received from server
            remote_address(pair) - IP-address and port of server
        """

        try:
            packet_class = packet.get_packet_class(data)
            packet_identifier = packet.get_packet_identifier(data)
        except packet.PacketError:
            return

        # If identifier of response in set of identifiers that we are sent,
        # get future for this identifier
        if packet_identifier in self.__futures.keys():
            future, request, start_time = self.__futures.get(packet_identifier)
            # If future is done early, that is a duplicate packet
            if future.done():
                exec_time = (self.loop.time() - start_time) * LOOP_TIME_MULTIPLEX
                logger.debug("Got RADIUS response from {} by {:.4f}ms, but it is duplicate, ignore it".format(
                    remote_address,
                    exec_time
                ))
                return
            # Trying to verify response from server
            try:
                response_packet = packet.decode_response(request.secret_key, data, request=request)
            except packet.PacketError as e:
                exec_time = (self.loop.time() - start_time) * LOOP_TIME_MULTIPLEX
                logger.warning("Got response from {} by {:.4f}ms, but it is not valid ({!s}), ignore it".format(
                    remote_address,
                    exec_time, e
                ))
                future.set_exception(packet.PacketError("Validation Error"))
            except Exception as e:
                exec_time = (self.loop.time() - start_time) * LOOP_TIME_MULTIPLEX
                logger.warning("Got {!s} from {} by {:.4f}ms, but it is not valid ({!s}), ignore it".format(
                    response_packet, remote_address,
                    exec_time, e
                ))
                future.set_exception(packet.PacketError("Validation Error"))
            else:
                exec_time = (self.loop.time() - start_time) * LOOP_TIME_MULTIPLEX
                local_addr, local_port, remote_addr, remote_port = self.get_enpoint_addresses()
                logger.debug("Got {!s} from {}:{} by {:.4f} ms".format(
                    response_packet,
                    remote_addr, remote_port,
                    exec_time
                ))
                future.set_result((response_packet, exec_time))
        else:
            # Got response packet with identifier that dont sent, ignore it
            logger.warning("Got RADIUS response from {}, but we are not send request with this ID, ignore it".format(
                remote_address
            ))


    def get_identifier(self):
        """ Return current unique identifier for this endpoint """
        used_identifier = self.identifiers_counter
        self.identifiers_counter += 1
        return used_identifier


    def send_packet_once(self, request_packet):
        """
        Send one request packet to the server
        and create future for wait response of this packet

        Params:
            request_packet(aioradius.protocol.Packet) - packet for sending
        Return:
            asyncio.Future object
        """
        local_addr, local_port, remote_addr, remote_port = self.get_enpoint_addresses()

        if request_packet.attributes.get('NAS-IP-Address') is None \
                and request_packet.attributes.get('NAS-Idenitifier') is None:
            request_packet.attributes.add('NAS-IP-Address', local_addr)

        internal_future = asyncio.Future()
        self.__futures[request_packet.identifier] = (internal_future, request_packet, self.loop.time())

        self.transport.sendto(bytes(request_packet))
        logger.debug("Sent {!s} to {}:{}".format(request_packet, remote_addr, remote_port))
        return internal_future

    @asyncio.coroutine
    def send_packet_and_watch(self, request_packet, retries=0, timeout=DEFAULT_RESPONSE_TIMEOUT):
        """
        Send request packet to the server with timeout and trying to resend it some times

        Params:
            request_packet(aioradius.protocol.Packet) - packet for sending
            retries(int) - number of resend attempts
            timeout(int) - delay between resend attempts

        Return:
            response from server
        """
        trying_idx = 0
        response = None
        if retries > 0:
            retries -= 1

        while trying_idx <= retries:
            try:
                response = yield from asyncio.wait_for(self.send_packet_once(request_packet), timeout)
            except asyncio.TimeoutError:
                trying_idx += 1
                logger.warning("Timeout for {} ({} sec)".format(request_packet, timeout))
                continue
            except packet.PacketError:
                trying_idx += 1
                logger.warning("Validation error for {}".format(request_packet))
                continue
            else:
                break
        if response is not None:
            return response
        else:
            raise asyncio.TimeoutError("All {} retries to sent {} are timed out".format(
                retries + 1,
                request_packet
            ))

    def send_packet(self, request_packet, **kwargs):
        """
        Basic send_packet method.

        Create coroutine of method `send_packet_and_watch` and add it to event loop

        Params:
            request_packet(aioradius.protocol.Packet) - packet for sending
            retries(int) - number of resend attempts
            timeout(int) - delay between resend attempts

        Return:
            asyncio.Task
        """
        if 'identifier' in kwargs:
            request_packet.identifier = kwargs.pop('identifier')
        else:
            request_packet.identifier = self.get_identifier()
        coro = self.send_packet_and_watch(request_packet, **kwargs)
        return self.loop.create_task(coro)

    def close(self):
        """ Close datagram endpoint """
        self.transport.close()

    def is_empty(self):
        return self.__futures.keys()

    def futures(self):
        return [item[0] for item in self.__futures.values()]

    def can_use(self):
        """ Return True if this endpoint has unique not used identifier """
        return self.identifiers_counter < packet.MAX_IDENTIFIER

    def __str__(self):
        return "Datagram endpoint from {}:{} to {}:{}".format(
            *self.get_enpoint_addresses()
        )


class ClientError(Exception):
    pass


# noinspection PyBroadException
class RadiusClient(object):
    """
    Class `Client` implement client object that used for send and receive RADIUS packets

    Attributes:
        loop(asyncio.Loop) - event loop

        default_server - IP-address or hostname of RADIUS server, default 'localhost'
        default_port - Port number of RADIUS server, default 1812
        client_identifier - If is not None and request packet has not attributes 'NAS-Identifier' and 'NAS-IP-Address',
                            that client add attribute 'NAS-Identifier', default None

        stat - statistic dictionary of client with keys:
            'requests' - sended requests counter,
            'responses' - received responses counter,
            'no_responses' - requests without or with bad response counter,
            'timeouts' - requests without response counter,
            'min_time' - min response time at sec,
            'max_time' - mas response time at sec,
    """

    @staticmethod
    def __validate_host(host):
        try:
            validated_host = IPv4Address(host)
        except ValueError:
            try:
                validated_host = socket.gethostbyname(host)
            except:
                raise ClientError("Bad value of host '{}', use IPv4 address or hostname".format(host))
        return validated_host

    @staticmethod
    def __validate_port(port):
        if port is None:
            return None
        try:
            validated_port = int(port)
        except (ValueError, TypeError):
            raise ClientError("Bad value of UDP port '{}'".format(port))
        return validated_port

    def __init__(self,
                 loop,
                 default_server='localhost',
                 default_port=1812,
                 client_identifier=None):
        """
        Initialize RADIUS client

        Params:
            loop - asyncio event loop
            default_server(optional) - IP-address or hostname of RADIUS server (default is 'localhost')
            default_port(optional) - Port number of RADIUS server (default is 1812)
            client_identifier(optional) - NAS-Identifier for RADIUS requests (default is None)
        """
        self.default_server = self.__validate_host(default_server)
        self.default_port = self.__validate_port(default_port)
        self.client_identifier = client_identifier

        self.loop = loop

        self.stat = dict(
            requests=0, responses=0, no_responses=0, timeouts=0,
            min_time=99999999, max_time=0, total_time=0,
            endpoints=0
        )
        self.__endpoints = dict()
        # Create and start endpoints cleaner
        self.__endpoints_cleaner = PeriodicTask(self.loop, self.__clean_endpoints, delay=5)
        self.__endpoints_cleaner.start()

    def __clean_endpoints(self):
        """
        Remove from endpoints storage endpoints that has all futures done
        """
        with execute_time('Endpoints cleaner', logger):
            for key, endpoints_list in self.__endpoints.items():
                pending_endpoints = []
                for endpoint in endpoints_list:
                    if endpoint.can_use():
                        pending_endpoints.append(endpoint)
                        continue
                    if any(map(lambda future: not future.done(), endpoint.futures())):
                        pending_endpoints.append(endpoint)
                    else:
                        logger.debug("All work at {} is done, clear".format(endpoint))
                        endpoint.close()
                self.__endpoints[key] = pending_endpoints

    @asyncio.coroutine
    def __get_endpoint_for_packet(self, remote_host, remote_port):
        remote_addr = (remote_host, remote_port)
        try:
            last_endpoint = self.__endpoints[remote_addr][-1]
        except (KeyError, IndexError):
            last_endpoint = None

        if last_endpoint is None or not last_endpoint.can_use():
            last_endpoint = yield from ClientDatagramEndpoint.create(
                remote_host,
                remote_port,
                self.loop
            )
            self.__endpoints.setdefault(remote_addr, []).append(last_endpoint)
            self.stat['endpoints'] += 1
        return last_endpoint

    @asyncio.coroutine
    def send_packet(self, request_packet, remote_host=None, remote_port=None, **kwargs):
        """
        Client `send_packet` coroutine method send packet asynchronously and return asyncio.Future,
        that will be done when server send response

        Params:
            request_packet(aioradius.protocol.Packet) - packet for sending
            remote_host - IP-address or hostname of RADIUS server, if it is not set will be used self.default_server
            remote_port - Port number of RADIUS server, if it is not set will be used self.default_port
            retries - Number of attempts to send a packet, default is 1
            timeout - Timeout of waiting response from server, default is 3 sec
        Return:
            response_future (asyncio.Future)
        """
        if remote_host is None:
            remote_host = self.default_server
        else:
            try:
                remote_host = self.__validate_host(remote_host)
            except Exception:
                remote_host = self.default_server

        if remote_port is None:
            remote_port = self.default_port
        else:
            try:
                remote_port = self.__validate_port(remote_port)
            except Exception:
                remote_port = self.default_port
        if request_packet.attributes.get('NAS-IP-Address') is None \
                and request_packet.attributes.get('NAS-Identifier') is None:
            if self.client_identifier is not None:
                request_packet.attributes.add('NAS-Identifier', self.client_identifier)

        endpoint = yield from self.__get_endpoint_for_packet(remote_host, remote_port)
        # Get future from endpoint and set it callback for statistics
        future = endpoint.send_packet(request_packet, **kwargs)
        future.add_done_callback(self.__got_reply)
        self.stat['requests'] += 1
        return future


    def __got_reply(self, future):
        """
        Callback method used for statistics, this method will called when client got response from server
        Method clear callback from future and update client statistics
        """
        future.remove_done_callback(self.__got_reply)
        try:
            response, future_time = future.result()
            self.stat['min_time'] = min(self.stat['min_time'], future_time)
            self.stat['max_time'] = max(self.stat['max_time'], future_time)
            self.stat['total_time'] += future_time
            self.stat['responses'] += 1
        except asyncio.TimeoutError:
            self.stat['timeouts'] += 1
            self.stat['no_responses'] += 1
        except Exception:
            self.stat['no_responses'] += 1


    def close(self):
        """ Close client """
        self.__endpoints_cleaner.stop()

        for key, endpoints_list in self.__endpoints.items():
            for endpoint in endpoints_list:
                endpoint.close()


def show_stat(stat):
    """
    Print client statistics
    """
    print("Created {} datagram endpoints".format(stat['endpoints']))

    print("Sent request: {}".format(stat['requests']))
    print("Got responses: {}".format(stat['responses']))
    print("Not response: {} (timeout: {})".format(stat['no_responses'], stat['timeouts']))
    if stat['responses'] != 0:
        print("\n")
        print("Total time of all responses (ms): {:.2f}".format(stat['total_time']))
        print("Min time(ms): {:.2f}".format(stat['min_time']))
        print("Max time(ms): {:.2f}".format(stat['max_time']))
        print("Avg time(ms): {:.2f}".format(stat['total_time'] / stat['responses']))