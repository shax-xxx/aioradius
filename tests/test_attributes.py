import ipaddress
import os
import unittest
from aioradius.protocol import dictionary
from aioradius.protocol.attributes import AttributeType

__author__ = 'arusinov'

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

class AttributesTestCase(unittest.TestCase):

    def setUp(self):
        self.dictionary = dictionary.Dictionary(quit=True)
        self.dictionary.merge(os.path.join(CURRENT_DIR, 'fixtures/dictionaries/dictionary.cisco'))
        self.dictionary.merge(os.path.join(CURRENT_DIR, 'fixtures/dictionaries/dictionary.dhcp'))
        AttributeType.set_dictionary(self.dictionary)

    def test_encode_decode_simple_attribute(self):
        tests = (
            ('User-Name', 'My name is test'),  # Testing encode/decode simple string attribute
            ('NAS-IP-Address', ipaddress.IPv4Address('192.168.0.1')),  # Testing encode/decode simple ipv4addr attribute
            ('Service-Type', 'Login-User') # Testing encode/decode simple attribute with value
        )
        for ATTRIBUTE, VALUE in tests:
            attribute_for_encode = AttributeType.get_attribute_for_encode(ATTRIBUTE)
            encoded_ = attribute_for_encode.encode(VALUE)

            attribute_for_decode = AttributeType.get_attribute_for_decode(encoded_)
            decoded_name, decoded_value = attribute_for_decode.decode(encoded_)

            self.assertEqual(attribute_for_encode, attribute_for_decode)
            self.assertEqual(decoded_name, ATTRIBUTE)
            self.assertEqual(decoded_value, VALUE)



    def test_encode_decode_vsa_attribute(self):
        tests = (
            ('Cisco-AVPair', 'bla=foo'),  # Testing encode/decode VSA string attribute
            ('DHCP-Your-IP-Address', ipaddress.IPv4Address('192.168.0.1')),  # Testing encode/decode vsa ipv4addr
            ('DHCP-Hardware-Type', 'Ethernet') # # Testing encode/decode VSA attribute with value
        )
        for ATTRIBUTE, VALUE in tests:
            attribute_for_encode = AttributeType.get_attribute_for_encode(ATTRIBUTE)
            encoded_ = attribute_for_encode.encode(VALUE)

            attribute_for_decode = AttributeType.get_attribute_for_decode(encoded_)
            decoded_name, decoded_value = attribute_for_decode.decode(encoded_)

            self.assertEqual(attribute_for_encode, attribute_for_decode)
            self.assertEqual(decoded_name, ATTRIBUTE)
            self.assertEqual(decoded_value, VALUE)

