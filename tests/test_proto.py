import asyncio
import logging
import unittest

from aioradius import RadiusService, RadiusAuthProtocol, RadiusAccountingProtocol, \
    RadiusResponseError, \
    packet

__author__ = 'aruisnov'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class FakeTransport(object):

    def __init__(self, host, port, loop):
        self.local_addr = (host, port)
        self.remote_addr = (None, None)
        self.response_data = None
        self.__wait_response_lock = asyncio.Event(loop=loop)

    @asyncio.coroutine
    def wait_response(self):
        return self.__wait_response_lock.wait()

    def get_extra_info(self, name):
        return self.local_addr

    def sendto(self, data, remote_addr):
        if self.__wait_response_lock is not None:
            self.__wait_response_lock.set()
        self.remote_addr = remote_addr
        self.response_data = data


REJECT_ALL_MESSAGE = 'REJECT_ALL'


class AlwaysReject(RadiusService):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.loop = asyncio.get_event_loop()
        self.handle_exception = None

    def validate_nas(self, remote_addr):
        remote_host, remote_port = remote_addr
        if remote_host == 'localhost':
            return 'secret'
        else:
            raise RadiusResponseError("Receive data from unknown NAS '{}'".format(remote_host))

    def on_auth_packet(self, request_attributes):
        return (
            ('Reply-Message', REJECT_ALL_MESSAGE)
        ), packet.ACCESS_REJECT

    def on_acct_packet(self, request_attributes):
        raise RadiusResponseError('Accounting is not implemented')

    def register_exception(self, exc):
        self.logger.error(exc)
        self.handle_exception = exc


class SyncProtoTestCase(unittest.TestCase):

    def test_initialize_proto(self):

        # Test bad initialization
        with self.assertRaises(RuntimeError):
            proto = RadiusAuthProtocol(None)

        service = AlwaysReject()
        # Test init with RadiusService object only (object has loop and logger)
        proto = RadiusAuthProtocol(service)
        self.assertEqual(proto.loop, service.loop)
        self.assertEqual(proto.logger, service.logger)

        # Test init with RadiusService object, external event_loop and external logger
        other_loop = asyncio.new_event_loop()
        other_logger = logging.getLogger('other_logger')
        proto = RadiusAuthProtocol(service, loop=other_loop, logger=other_logger)
        self.assertEqual(proto.loop, other_loop)
        self.assertEqual(proto.logger, other_logger)
        self.assertNotEqual(proto.loop, service.loop)
        self.assertNotEqual(proto.logger, service.logger)

        # Test init with RadiusService object only (object not has loop and logger)
        delattr(service, 'loop')
        delattr(service, 'logger')
        proto = RadiusAuthProtocol(service)
        self.assertTrue(isinstance(proto.loop, asyncio.AbstractEventLoop))
        self.assertTrue(isinstance(proto.logger, logging.Logger))

    def test_auth_request(self):

        service = AlwaysReject()
        proto = RadiusAuthProtocol(service)

        transport = FakeTransport('localhost', 1812, service.loop)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        request_class = proto.request_class
        request_packet = request_class('secret')
        request_packet.attributes.extend(
            ('User-Name', 'user'),
            ('User-Password', 'password'),
            ('NAS-Identifier', 'nas_id')
        )
        encoded_ = bytes(request_packet)

        proto.datagram_received(encoded_, ('localhost', 65000))

        service.loop.run_until_complete(transport.wait_response())
        received_data = transport.response_data

        received_packet = packet.decode_response('secret', received_data, request=request_packet)
        self.assertEqual(request_packet.identifier, received_packet.identifier)
        self.assertEqual(received_packet.attributes.get('Reply-Message'), REJECT_ALL_MESSAGE)

        proto.connection_lost(None)
        proto.wait_for_close()
        self.assertTrue(proto.is_closed())

    def test_acc_request(self):

        service = AlwaysReject()
        proto = RadiusAccountingProtocol(service)

        transport = FakeTransport('localhost', 1813, service.loop)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        request_class = proto.request_class
        request_packet = request_class('secret')
        request_packet.attributes.extend(
            ('User-Name', 'user'),
            ('NAS-Identifier', 'nas-id'),
            ('Acct-Session-Id', 'session-id'),
            ('Acct-Status-Type', 'Start')
        )
        encoded_ = bytes(request_packet)

        proto.datagram_received(encoded_, ('localhost', 65000))
        with self.assertRaises(asyncio.TimeoutError):
            service.loop.run_until_complete(
                asyncio.wait_for(transport.wait_response(), 1.5)
            )

        self.assertIsNone(transport.response_data)

        proto.connection_lost(None)
        proto.wait_for_close()
        self.assertTrue(proto.is_closed())

    def test_bad_request(self):

        service = AlwaysReject()
        proto = RadiusAuthProtocol(service)

        transport = FakeTransport('localhost', 1812, service.loop)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        request_class = proto.request_class
        request_packet = request_class('secret')
        request_packet.attributes.extend(
            ('User-Name', 'user'),
            ('User-Password', 'password'),
        )
        with self.assertRaises(packet.PacketError):
            encoded_ = bytes(request_packet)

        #proto.datagram_received(encoded_, ('localhost', 65000))
        with self.assertRaises(asyncio.TimeoutError):
            service.loop.run_until_complete(
                asyncio.wait_for(transport.wait_response(), 1.5)
            )

        self.assertIsNone(transport.response_data)
        self.assertIsNone(service.handle_exception)
        proto.connection_lost(None)
        proto.wait_for_close()
        self.assertTrue(proto.is_closed())

    def test_bad_bytes(self):

        service = AlwaysReject()
        proto = RadiusAccountingProtocol(service)

        transport = FakeTransport('localhost', 1813, service.loop)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        encoded_ = bytes(64)

        proto.datagram_received(encoded_, ('localhost', 65000))
        with self.assertRaises(asyncio.TimeoutError):
            service.loop.run_until_complete(
                asyncio.wait_for(transport.wait_response(), 1.5)
            )

        self.assertIsNone(transport.response_data)
        self.assertIsInstance(service.handle_exception, ValueError)
        proto.connection_lost(None)
        proto.wait_for_close()
        self.assertTrue(proto.is_closed())

    def test_bad_nas(self):

        service = AlwaysReject()
        proto = RadiusAccountingProtocol(service)

        transport = FakeTransport('localhost', 1812, service.loop)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        request_class = proto.request_class
        request_packet = request_class('secret')
        request_packet.attributes.extend(
            ('User-Name', 'user'),
            ('NAS-Identifier', 'nas-id'),
            ('Acct-Session-Id', 'session-id'),
            ('Acct-Status-Type', 'Start')
        )
        encoded_ = bytes(request_packet)


        proto.datagram_received(encoded_, ('127.0.0.2', 65000))
        with self.assertRaises(asyncio.TimeoutError):
            service.loop.run_until_complete(
                asyncio.wait_for(transport.wait_response(), 1.5)
            )

        self.assertIsNone(transport.response_data)

        proto.connection_lost(None)
        proto.wait_for_close()
        self.assertTrue(proto.is_closed())


class FakeTransportWithProto(FakeTransport):

    def __init__(self, host, port, loop, proto):
        super().__init__(host, port, loop)
        self.proto = proto

    def sendto(self, data, remote_addr):
        super().sendto(data, remote_addr)
        self.proto.connection_lost(None)


class AsyncRadiusService(RadiusService):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.loop = asyncio.get_event_loop()
        self.handle_exception = None

    @asyncio.coroutine
    def validate_nas(self, remote_addr):
        yield from asyncio.sleep(1)
        return 'secret'

    @asyncio.coroutine
    def on_auth_packet(self, request_attributes):
        yield from asyncio.sleep(1)
        return (
            ('User-Name', 'user'),
        ), packet.ACCESS_ACCEPT

    @asyncio.coroutine
    def on_acct_packet(self, request_attributes):
        yield from asyncio.sleep(1)
        return (), None

    def register_exception(self, exc):
        raise exc

class AsyncProtoTestCase(unittest.TestCase):

    def test_async_auth_request(self):
        service = AsyncRadiusService()
        proto = RadiusAuthProtocol(service)

        transport = FakeTransportWithProto('localhost', 1812, service.loop, proto)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        request_class = proto.request_class
        request_packet = request_class('secret')
        request_packet.attributes.extend(
            ('User-Name', 'user'),
            ('User-Password', 'password'),
            ('NAS-Identifier', 'nas_id')
        )
        encoded_ = bytes(request_packet)

        proto.datagram_received(encoded_, ('localhost', 65000))

        proto.wait_for_close()
        self.assertTrue(proto.is_closed())

        received_data = transport.response_data
        received_packet = packet.decode_response('secret', received_data, request=request_packet)
        self.assertEqual(request_packet.identifier, received_packet.identifier)
        self.assertEqual(received_packet.attributes.get('User-Name'), 'user')

    def test_async_acc_request(self):
        service = AsyncRadiusService()
        proto = RadiusAccountingProtocol(service)

        transport = FakeTransportWithProto('localhost', 1812, service.loop, proto)

        proto.connection_made(transport)
        self.assertIs(proto.transport, transport)

        request_class = proto.request_class
        request_packet = request_class('secret')
        request_packet.attributes.extend(
            ('User-Name', 'user'),
            ('NAS-Identifier', 'nas_id'),
            ('Acct-Session-Id', 'session-id'),
            ('Acct-Status-Type', 'Start')
        )
        encoded_ = bytes(request_packet)

        proto.datagram_received(encoded_, ('localhost', 65000))

        proto.wait_for_close()
        self.assertTrue(proto.is_closed())

        received_data = transport.response_data
        received_packet = packet.decode_response('secret', received_data, request=request_packet)
        self.assertEqual(request_packet.identifier, received_packet.identifier)

