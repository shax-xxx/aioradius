import logging
import unittest
import asyncio
from aioradius import packet, RadiusResponseError, RadiusClient
from aioradius.server import AbstractRadiusServer, RadiusServerError, DEFAULT_AUTH_PORT, DEFAULT_ACC_PORT

__author__ = 'arusinov'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

SHARED_SECRET = 'secret'


class RadiusServerTestCase(unittest.TestCase):


    def test_bad_implemented_server(self):
        with self.assertRaises(TypeError):
            server = AbstractRadiusServer('localhost')

        class BadImplementedServer(AbstractRadiusServer):
            def validate_nas(self, remote_addr):
                return SHARED_SECRET

        with self.assertRaises(RadiusServerError):
            server = BadImplementedServer('localhost')
            server.run()

    def test_auth_only(self):
        class AuthOnlyServer(AbstractRadiusServer):
            def validate_nas(self, remote_addr):
                return SHARED_SECRET
            def on_auth_packet(self, request_attributes):
                pass

        server = AuthOnlyServer('localhost')
        server.run(asyncio.sleep(1))
        self.assertIsNotNone(server.auth_port)
        self.assertIsNone(server.acc_port)

    def test_acc_only(self):
        class AccOnlyServer(AbstractRadiusServer):
            def validate_nas(self, remote_addr):
                return SHARED_SECRET
            def on_acct_packet(self, request_attributes):
                pass

        server = AccOnlyServer('localhost')
        server.run(asyncio.sleep(1))

        self.assertIsNotNone(server.acc_port)
        self.assertIsNone(server.auth_port)



class FakeRadiusServer(AbstractRadiusServer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.acct_sessions = []
        self.last_exc = None

    def validate_nas(self, remote_addr):
        return SHARED_SECRET

    def on_acct_packet(self, request_attributes):
        acct_session_id = request_attributes.get('Acct-Session-Id')
        acct_status_type = request_attributes.get('Acct-Status-Type')
        if acct_session_id is None:
            raise RadiusResponseError("Acct-Session-Id is required")
        if acct_status_type is None or acct_status_type not in ('Start', 'Stop'):
            raise RadiusResponseError("Status type '{}' is not implemented".format(acct_status_type))

        if acct_status_type == 'Start':
            self.acct_sessions.append(acct_session_id)
            return (), None
        else:
            if acct_session_id not in self.acct_sessions:
                raise RadiusResponseError("Cant stop session '{}', it is not registered".format(acct_session_id))
            self.acct_sessions.remove(acct_session_id)
            return (), None

    @asyncio.coroutine
    def on_auth_packet(self, request_attributes):
        yield from asyncio.sleep(0.01)
        if request_attributes is None:
            return
        username = request_attributes.get('User-Name')
        password = request_attributes.get('User-Password')
        if username is None or password is None:
            raise RadiusResponseError("Username and password must be set")
        if username == 'superuser' and password == 'superpassword':
            return (
                ('User-Name', username)
            ), packet.ACCESS_ACCEPT
        else:
            return (
                ('Reply-Message', 'Access Denied')
            ), packet.ACCESS_REJECT

    def register_exception(self, exc):
        self.logger.error(exc)
        self.last_exc = exc
        raise exc

class FakeServerTestCase(unittest.TestCase):

    def test_init_bad_host(self):
        with self.assertRaises(RadiusServerError) as ctx:
            server = FakeRadiusServer('blafoo')
        self.assertIn('Bad value of host', str(ctx.exception))

    def test_bad_value_of_port(self):
        with self.assertRaises(RadiusServerError) as ctx:
            server = FakeRadiusServer('127.0.0.1', auth_port=1812, acc_port='blafoo')
        self.assertIn('Bad value of UDP port', str(ctx.exception))

    def test_auth_status_server(self):
        @asyncio.coroutine
        def client_coro(loop, server_host, server_port):
            client = RadiusClient(loop, default_server=server_host, default_port=server_port)
            request = packet.StatusServer(SHARED_SECRET)
            request.attributes.extend(
                ('NAS-Identifier', 'test_nas'),
            )
            future = yield from client.send_packet(request)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCESS_ACCEPT)
            self.assertTrue(len(response.attributes) == 0)
            client.close()

        fake = FakeRadiusServer('localhost', auth_port=65001, acc_port=65002)
        event_loop = fake.get_event_loop()
        fake.run(client_coro(event_loop, 'localhost', 65001))

    def test_acc_status_server(self):
        @asyncio.coroutine
        def client_coro(loop, server_host, server_port):
            client = RadiusClient(loop, default_server=server_host, default_port=server_port)
            request = packet.AccountingStatusServer(SHARED_SECRET)
            future = yield from client.send_packet(request)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCOUNTING_RESPONSE)
            self.assertTrue(len(response.attributes) == 0)
            client.close()

        fake = FakeRadiusServer('localhost', auth_port=65001, acc_port=65002)
        event_loop = fake.get_event_loop()
        fake.run(client_coro(event_loop, 'localhost', 65002))

    def test_auth_request(self):
        @asyncio.coroutine
        def client_coro(loop, server_host, server_port):
            client = RadiusClient(loop, default_server=server_host, default_port=server_port)
            request = packet.AccessRequest(SHARED_SECRET)
            request.attributes = (
                ('User-Name', 'username'),
                ('User-Password', 'password'),
            )
            future = yield from client.send_packet(request)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCESS_REJECT)

            request = packet.AccessRequest(SHARED_SECRET)
            request.attributes.extend(
                ('User-Name', 'superuser'),
                ('User-Password', 'superpassword'),
            )
            future = yield from client.send_packet(request)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCESS_ACCEPT)

            client.close()

        fake = FakeRadiusServer('localhost', auth_port=65001, acc_port=65002)
        event_loop = fake.get_event_loop()
        fake.run(client_coro(event_loop, 'localhost', 65001))

    def test_auth_request_with_cache(self):

        @asyncio.coroutine
        def client_coro(loop, server_host, server_port):
            client = RadiusClient(loop, default_server=server_host, default_port=server_port)
            request = packet.AccessRequest(SHARED_SECRET)
            request.attributes = (
                ('User-Name', 'username'),
                ('User-Password', 'password'),
            )
            future = yield from client.send_packet(request)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCESS_REJECT)
            future = yield from client.send_packet(request, identifier=0)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCESS_REJECT)
            client.close()

        fake = FakeRadiusServer('localhost', auth_port=65001, acc_port=65002)
        event_loop = fake.get_event_loop()
        fake.run(client_coro(event_loop, 'localhost', 65001))


    def test_acc_request(self):
        @asyncio.coroutine
        def client_coro(loop, server_host, server_port, server):
            client = RadiusClient(loop, client_identifier='test-client')
            request = packet.AccountingRequest(SHARED_SECRET)
            request.attributes.extend(
                ('User-Name', 'username'),
                ('Acct-Session-Id', 'session-test'),
                ('Acct-Status-Type', 'Start')
            )
            future = yield from client.send_packet(request, remote_host=server_host, remote_port=server_port)
            response, response_time = yield from future
            self.assertEqual(request.attributes.get('NAS-Identifier'), 'test-client')
            self.assertTrue(response.code == packet.ACCOUNTING_RESPONSE)
            self.assertIn('session-test', server.acct_sessions)

            request = packet.AccountingRequest(SHARED_SECRET)
            request.attributes.extend(
                ('User-Name', 'username'),
                ('Acct-Session-Id', 'session-test'),
                ('Acct-Status-Type', 'Stop')
            )
            future = yield from client.send_packet(request, remote_host=server_host, remote_port=server_port)
            response, response_time = yield from future
            self.assertTrue(response.code == packet.ACCOUNTING_RESPONSE)
            self.assertNotIn('session-test', server.acct_sessions)

            request = packet.AccountingRequest(SHARED_SECRET)
            request.attributes.extend(
                ('User-Name', 'username'),
                ('Acct-Session-Id', 'session-test'),
                ('Acct-Status-Type', 'Stop')
            )
            #with self.assertRaises(asyncio.TimeoutError):
            future = yield from client.send_packet(request, remote_host=server_host, remote_port=server_port)
            with self.assertRaises(asyncio.TimeoutError):
                response, response_time = yield from future
            self.assertIsInstance(server.last_exc, RadiusResponseError)
            client.close()

        fake = FakeRadiusServer('localhost', auth_port=65001, acc_port=65002)
        event_loop = fake.get_event_loop()
        fake.run(client_coro(event_loop, 'localhost', 65002, fake))


    def test_acc_bad_status(self):
        @asyncio.coroutine
        def client_coro(loop, server_host, server_port, server):
            client = RadiusClient(loop)
            request = packet.AccountingRequest(SHARED_SECRET)
            request.attributes.extend(
                ('User-Name', 'username'),
                ('Acct-Session-Id', 'session-test'),
                ('Acct-Status-Type', 'Interim-Update')
            )
            future = yield from client.send_packet(request,
                                                       remote_host=server_host, remote_port=server_port,
                                                       retries=3, timeout=1)
            with self.assertRaises(asyncio.TimeoutError):
                response, response_time = yield from future
            self.assertIsInstance(server.last_exc, RadiusResponseError)
            self.assertEqual(client.stat.get('requests'), 1)
            self.assertEqual(client.stat.get('responses'), 0)
            self.assertEqual(client.stat.get('no_responses'), 1)
            self.assertEqual(client.stat.get('timeouts'), 1)
            client.close()

        fake = FakeRadiusServer('localhost', auth_port=65001, acc_port=65002)
        event_loop = fake.get_event_loop()
        fake.run(client_coro(event_loop, 'localhost', 65002, fake))


    def test_send_to_das(self):
        @asyncio.coroutine
        def dac_coro(server):
            event_loop = server.get_event_loop()
            das_request = packet.StatusServer(SHARED_SECRET)
            with self.assertRaises(RadiusServerError) as ctx:
                yield from server.send_to_das(das_request, 'localhost')
            self.assertEqual(str(ctx.exception),
                             "You can send to DAS packet only of type DisconnectRequest or CoaRequest")
            das_request = packet.DisconnectRequest(SHARED_SECRET)
            with self.assertRaises(asyncio.TimeoutError):
                yield from server.send_to_das(das_request, '127.0.0.1', timeout=1)

            das_request = packet.CoARequest(SHARED_SECRET)
            with self.assertRaises(asyncio.TimeoutError):
                yield from server.send_to_das(das_request, '127.0.0.1', timeout=1)

            server.close_dac()

        fake = FakeRadiusServer('localhost', auth_port=65010)
        fake.run(dac_coro(fake))
