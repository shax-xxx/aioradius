import os
import ipaddress
import unittest
from unittest.mock import MagicMock
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
bidict_logger = logging.getLogger('aioradius.protocol.dictionary')
bidict_logger.setLevel(logging.ERROR)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

from aioradius.protocol.dictionary import Dictionary
from aioradius.protocol.attributes import AttributeType
import aioradius.protocol.packet as packet

__author__ = 'arusinov'


SECRET_KEY = 'Test_secret_secret_secret_key'


class AttributeSetTestCase(unittest.TestCase):

    def test_usage(self):

        attributes = packet.AttributesSet(
            ('User-Name', 'username'),
            ('User-Password', 'userpassword')
        )

        self.assertEqual(attributes.get('User-Name'), 'username')
        self.assertEqual(attributes.get('User-Password'), 'userpassword')

        attributes.add('User-Name', 'otherusername')
        self.assertEqual(attributes.get('User-Name'), 'otherusername')
        self.assertListEqual(attributes.get('User-Name', many=True), ['username', 'otherusername'])
        self.assertTrue('User-Name' in attributes)
        self.assertTrue('User-Password' in attributes)
        attributes.clear()
        self.assertIsNone(attributes.get('User-Password'))
        self.assertTrue(len(attributes) == 0)




class PacketTestCase(unittest.TestCase):

    def setUp(self):
        dictionary = Dictionary(quit=False)
        dictionary.merge(os.path.join(CURRENT_DIR, 'fixtures/dictionaries/dictionary.cisco'))
        dictionary.merge(os.path.join(CURRENT_DIR, 'fixtures/dictionaries/dictionary.dhcp'))
        AttributeType.set_dictionary(dictionary)

    def test_initialize_packet(self):
        with self.assertRaises(packet.PacketError):
            pack = packet.AccessRequest(SECRET_KEY, identifier=1024)

        with self.assertRaises(packet.PacketError):
            pack = packet.AccessRequest(SECRET_KEY, identifier='blafoo')

        with self.assertRaises(packet.PacketError) as ctx:
            pack = packet.AccessRequest(SECRET_KEY)
            pack.attributes = None

    def test_packet_decode(self):
        with self.assertRaises(packet.PacketError):
            packet.decode_request(SECRET_KEY, None)
        with self.assertRaises(packet.PacketError):
            packet.decode_request(SECRET_KEY, None)
        with self.assertRaises(packet.PacketError):
            packet.decode_request(SECRET_KEY, 123)
        with self.assertRaises(packet.PacketError) as exc:
            packet.decode_request(SECRET_KEY, b'\x01\x00')
        self.assertIn('Size of packet bytes must be equal of more than', str(exc.exception))

    def test_access_request(self):
        pack = packet.AccessRequest(SECRET_KEY)
        pack.attributes.add('User-Name', 'TestUser')
        pack.attributes.add('User-Name', 'TestUser2')
        pack.attributes.extend(
            ('User-Password', 'blafoo'),
            ('Cisco-AVPair', 'bla=foo'),
            ('NAS-IP-Address', ipaddress.IPv4Address('127.0.0.1')),
            ('Service-Type', 'Login-User'),
            ('DHCP-Your-IP-Address', ipaddress.IPv4Address('192.168.0.1')),
            'not_pair'
        )
        with self.assertRaises(KeyError):
            pack.attributes.add('Bla-Foo', 'blafoo')
        
        self.assertEqual(pack.attributes.get('User-Name'), 'TestUser2')
        self.assertEqual(pack.attributes.get('User-Password'), 'blafoo')
        self.assertEqual(pack.attributes.get('Cisco-AVPair'), 'bla=foo')
        self.assertEqual(pack.attributes.get('NAS-IP-Address'), ipaddress.IPv4Address('127.0.0.1'))
        self.assertEqual(pack.attributes.get('Service-Type'), 'Login-User')
        self.assertEqual(pack.attributes.get('DHCP-Your-IP-Address'), ipaddress.IPv4Address('192.168.0.1'))
        
        encoded_ = bytes(pack)
        decoded_pack = packet.decode_request(SECRET_KEY, encoded_)
        self.assertEqual(pack, decoded_pack)

    def test_access_accept(self):
        attributes = packet.AttributesSet(
            ('User-Name', 'username'),
            ('User-Password', 'password'),
            ('NAS-Identifier', 'nas-id')
        )
        request = packet.AccessRequest(SECRET_KEY)
        request.attributes = attributes

        encoded_ = bytes(request)
        decoded_request = packet.decode_request(SECRET_KEY, encoded_)

        self.assertEqual(request, decoded_request)

        response = decoded_request.create_reply(packet.ACCESS_ACCEPT)
        encoded_ = bytes(response)

        decoded_response = packet.decode_response(SECRET_KEY, encoded_, request=request)

        self.assertEqual(response, decoded_response)

    def test_access_reject(self):
        attributes = packet.AttributesSet(
            ('User-Name', 'username'),
            ('User-Password', 'password'),
            ('NAS-Identifier', 'nas-id')
        )
        request = packet.AccessRequest(SECRET_KEY)
        request.attributes = attributes

        encoded_ = bytes(request)
        decoded_request = packet.decode_request(SECRET_KEY, encoded_)

        self.assertEqual(request, decoded_request)

        response = decoded_request.create_reply(packet.ACCESS_REJECT)
        response.attributes.add('Reply-Message', 'ACCESS_DENIED')

        encoded_ = bytes(response)

        decoded_response = packet.decode_response(SECRET_KEY, encoded_, request=request)

        self.assertEqual(response, decoded_response)

    def test_access_challenge(self):
        request = packet.AccessRequest(SECRET_KEY)
        request.attributes.extend(
            ('User-Name', 'username'),
            ('User-Password', 'password'),
            ('NAS-Identifier', 'nas-id')
        )

        encoded_ = bytes(request)
        decoded_request = packet.decode_request(SECRET_KEY, encoded_)

        self.assertEqual(request, decoded_request)

        response = decoded_request.create_reply(packet.ACCESS_CHALLENGE)
        response.attributes.add('Reply-Message', 'ACCESS_CHALANGE')

        encoded_ = bytes(response)
        decoded_response = packet.decode_response(SECRET_KEY, encoded_, request=request)
        self.assertEqual(response, decoded_response)


        response = decoded_request.create_reply(packet.ACCESS_CHALLENGE)
        response.attributes.add('User-Name', 'username')
        with self.assertRaises(packet.PacketError):
            bytes(response)


    def test_get_packet_class(self):
        self.assertEqual(packet.get_packet_class(b'\x01\x00\x00\x00'), packet.AccessRequest)
        self.assertEqual(packet.get_packet_class(b'\x02\x00\x00\x00'), packet.AccessAccept)
        self.assertEqual(packet.get_packet_class(b'\x03\x00\x00\x00'), packet.AccessReject)
        self.assertEqual(packet.get_packet_class(b'\x0b\x00\x00\x00'), packet.AccessChallenge)
        self.assertEqual(packet.get_packet_class(b'\x04\x00\x00\x00'), packet.AccountingRequest)
        self.assertEqual(packet.get_packet_class(b'\x05\x00\x00\x00'), packet.AccountingResponse)
        with self.assertRaises(packet.PacketError):
            packet.get_packet_class(b'\x00\x00\x00\x00')

    def test_accounting_response(self):
        request = packet.AccountingRequest(SECRET_KEY)
        request.attributes.extend(
            ('User-Name', 'username'),
            ('NAS-Identifier', 'nas-id')
        )
        with self.assertRaises(packet.PacketError) as ctx:
            bytes(request)

        request = packet.AccountingRequest(SECRET_KEY)
        request.attributes = (
            ('User-Name', 'username'),
            ('NAS-Identifier', 'nas-id'),
            ('Acct-Status-Type', 'Start'),
            ('Acct-Session-Id', 'session_id')
        )

        encoded_ = bytes(request)
        decoded_request = packet.decode_request(SECRET_KEY, encoded_)


        self.assertEqual(request, decoded_request)

        response = decoded_request.create_reply()

        self.assertIsInstance(response, packet.AccountingResponse)
        self.assertEqual(response.code, packet.ACCOUNTING_RESPONSE)
        self.assertEqual(decoded_request.identifier, response.identifier)

        encoded_ = bytes(response)

        decoded_response = packet.decode_response(SECRET_KEY, encoded_, request=request)
        self.assertEqual(response, decoded_response)

    def test_disconnect(self):
        request = packet.DisconnectRequest(SECRET_KEY)
        request.attributes.extend(
            ('User-Password', 'rejected-attribute'),
            ('Error-Cause', 'rejected-attribute')
        )
        with self.assertRaises(packet.PacketError):
            encoded_ = bytes(request)
        request.attributes.extend(
            ('NAS-Identifier', 'test-nas'),
        )
        encoded_ = bytes(request)
        decoded_request = packet.decode_request(SECRET_KEY, encoded_)

        self.assertEqual(request.identifier, decoded_request.identifier)
        self.assertEqual(request.code, decoded_request.code)
        self.assertNotIn('User-Password', decoded_request.attributes)
        self.assertNotIn('Error-Cause', decoded_request.attributes)

        response = decoded_request.create_reply(packet.DISCONNECT_ACK)
        encoded_ = bytes(response)
        decoded_response = packet.decode_response(SECRET_KEY, encoded_, decoded_request)

        self.assertEqual(request.identifier, decoded_response.identifier)
        self.assertIsInstance(decoded_response, packet.DisconnectACK)

        response = decoded_request.create_reply(packet.DISCONNECT_NACK)
        encoded_ = bytes(response)
        decoded_response = packet.decode_response(SECRET_KEY, encoded_, decoded_request)

        self.assertEqual(request.identifier, decoded_response.identifier)
        self.assertIsInstance(decoded_response, packet.DisconnectNACK)

    def test_coa(self):
        request = packet.CoARequest(SECRET_KEY)
        request.attributes.extend(
            ('User-Password', 'rejected-attribute'),
            ('Error-Cause', 'rejected-attribute')
        )
        with self.assertRaises(packet.PacketError):
            encoded_ = bytes(request)
        request.attributes.extend(
            ('NAS-Identifier', 'test-nas'),
        )
        encoded_ = bytes(request)
        decoded_request = packet.decode_request(SECRET_KEY, encoded_)

        self.assertEqual(request.identifier, decoded_request.identifier)
        self.assertEqual(request.code, decoded_request.code)
        self.assertNotIn('User-Password', decoded_request.attributes)
        self.assertNotIn('Error-Cause', decoded_request.attributes)

        response = decoded_request.create_reply(packet.COA_ACK)
        encoded_ = bytes(response)
        decoded_response = packet.decode_response(SECRET_KEY, encoded_, decoded_request)

        self.assertEqual(request.identifier, decoded_response.identifier)
        self.assertIsInstance(decoded_response, packet.CoaACK)

        response = decoded_request.create_reply(packet.COA_NACK)
        encoded_ = bytes(response)
        decoded_response = packet.decode_response(SECRET_KEY, encoded_, decoded_request)

        self.assertEqual(request.identifier, decoded_response.identifier)
        self.assertIsInstance(decoded_response, packet.CoaNACK)
