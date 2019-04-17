import os
import unittest
from aioradius.protocol.dictionary import Dictionary, VendorDefinition, FormatError, AttributeDefinition
from aioradius.protocol.crypt import ALLOWED_CRYPT_TYPES

__author__ = 'arusinov'

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

class VendorDefinitionTestCase(unittest.TestCase):

    def test_parse_bad_definition(self):
        definition = "   VENDOR	BadVendor"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

    def test_parse_bad_format(self):
        definition = "   VENDOR	BadVendor 1 format"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

        definition = "   VENDOR	BadVendor 1 format=1"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

        definition = "   VENDOR	BadVendor 1 format=1,1,c"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

        definition = "   VENDOR	BadVendor 1 format=a,b"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

        definition = "VENDOR	BadVendor 1 format=6,1"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

        definition = "   VENDOR	BadVendor 1 format=4,4"
        with self.assertRaises(FormatError):
            vendor = VendorDefinition.parse(definition)

    def test_parse(self):
        definition = "VENDOR		Cisco				9"
        vendor = VendorDefinition.parse(definition)
        self.assertEqual(vendor.name, 'Cisco')
        self.assertEqual(vendor.number, 9)
        self.assertEqual(vendor.format, (1,1))

        definition = "VENDOR		DHCP				54	format=2,1"
        vendor = VendorDefinition.parse(definition)
        self.assertEqual(vendor.name, 'DHCP')
        self.assertEqual(vendor.number, 54)
        self.assertEqual(vendor.format, (2,1))


class AttributeDefinitionTestCase(unittest.TestCase):

    def test_simple_attribute_parse(self):
        definition = "ATTRIBUTE	User-Name				1	string"
        attribute = AttributeDefinition.parse(definition)
        self.assertEqual(attribute.name, 'User-Name')
        self.assertEqual(attribute.number, '1')
        self.assertEqual(attribute.type, 'string')
        self.assertEqual(attribute.vendor, None)
        self.assertDictEqual(attribute.options, dict(has_tag=False, is_array=False, encrypt=0))

    def test_simple_attribute_with_encrypt_parse(self):
        definition = "ATTRIBUTE	User-Password				2	string encrypt=1"
        attribute = AttributeDefinition.parse(definition)
        self.assertEqual(attribute.name, 'User-Password')
        self.assertEqual(attribute.number, '2')
        self.assertEqual(attribute.type, 'string')
        self.assertEqual(attribute.vendor, None)
        self.assertDictEqual(attribute.options, dict(has_tag=False, is_array=False, encrypt=1))



    def test_attribute_with_values_parse(self):
        BAD_VALUE = 'VALUE	Service-Type			Login-User'
        with self.assertRaises(FormatError) as exc:
            AttributeDefinition.parse_value(BAD_VALUE)
        self.assertIn('Bad VALUE format', str(exc.exception))

        VALUES = (
            'VALUE	Service-Type			Login-User		1',
            'VALUE	Service-Type			Framed-User		2',
            'VALUE	Service-Type			Callback-Login-User	3',
            'VALUE	Service-Type			Callback-Framed-User	4',
            'VALUE	Service-Type			Outbound-User		5',
            'VALUE	Service-Type			Administrative-User	6',
            'VALUE	Service-Type			NAS-Prompt-User		7'
        )
        ATTRIBUTE = 'ATTRIBUTE Service-Type 6 integer'
        tmp_values = dict()
        for value_definition in VALUES:
            attribute_name, value_name, value = AttributeDefinition.parse_value(value_definition)
            tmp_values.setdefault(attribute_name, []).append((value_name, value))
        attribute = AttributeDefinition.parse(ATTRIBUTE)
        attribute.add_values(tmp_values.get(attribute.name))

        self.assertEqual(attribute.name, 'Service-Type')
        self.assertEqual(attribute.number, '6')
        self.assertEqual(attribute.type, 'integer')
        self.assertEqual(attribute.vendor, None)
        self.assertDictEqual(attribute.options, dict(has_tag=False, is_array=False, encrypt=0))
        self.assertEqual(len(attribute.values.keys()), len(VALUES))

    def test_simple_attribute_with_bad_encrypt_parse(self):
        if len(ALLOWED_CRYPT_TYPES) == 1:
            not_in_range_encrypt = ALLOWED_CRYPT_TYPES[0] + 1
        else:
            not_in_range_encrypt = max(*ALLOWED_CRYPT_TYPES) + 1
        definition = "ATTRIBUTE	BadEncryptAttribute 2 string encrypt={}".format(not_in_range_encrypt)
        with self.assertRaises(FormatError):
            attribute = AttributeDefinition.parse(definition)

        definition = "ATTRIBUTE	BadEncryptAttribute 2 string encrypt=a"
        with self.assertRaises(FormatError):
            attribute = AttributeDefinition.parse(definition)


    def test_simple_attribute_with_bad_type_parse(self):
        definition = "ATTRIBUTE	BadTypeAttribute 2 blafoo"
        with self.assertRaises(FormatError) as exc:
            attribute = AttributeDefinition.parse(definition)
        self.assertIn('Unsupported data type', str(exc.exception))


    def test_vsa_attribute_parse(self):
        vendor = VendorDefinition.parse("VENDOR DHCP 54 format=2,1")
        attribute_definition = "ATTRIBUTE DHCP-Relay-IP-Address 272	ipaddr"
        attribute = AttributeDefinition.parse(attribute_definition, current_vendor=vendor)
        self.assertEqual(attribute.name, 'DHCP-Relay-IP-Address')
        self.assertEqual(attribute.number, '272')
        self.assertEqual(attribute.type, 'ipaddr')
        self.assertEqual(attribute.vendor, vendor)
        self.assertDictEqual(attribute.options, dict(has_tag=False, is_array=False, encrypt=0))


class DictionaryTestCase(unittest.TestCase):

    def setUp(self):
        self.dictionary = Dictionary(quit=True)
        self.dictionary.merge(os.path.join(CURRENT_DIR, 'fixtures/dictionaries/dictionary.cisco'))
        self.dictionary.merge(os.path.join(CURRENT_DIR, 'fixtures/dictionaries/dictionary.dhcp'))

    def test_basic(self):
        cisco_vendor = self.dictionary.get_vendor_by_name('Cisco')
        self.assertEqual(cisco_vendor.name, 'Cisco')
        self.assertEqual(cisco_vendor.number, 9)
        self.assertEqual(cisco_vendor.format, (1,1))
        nine_vendor = self.dictionary.get_vendor_by_number(cisco_vendor.number)
        self.assertEqual(cisco_vendor, nine_vendor)

        attribute_by_name = self.dictionary.get_attribute_definition_by_name('Cisco-AVPair')
        self.assertEqual(attribute_by_name.name, 'Cisco-AVPair')
        vendor_id = attribute_by_name.vendor.number if attribute_by_name.vendor is not None else 0
        attribute_id = attribute_by_name.number

        attribute_by_id = self.dictionary.get_attribute_definition_by_id(vendor_id, attribute_id)
        self.assertEqual(attribute_by_name, attribute_by_id)


