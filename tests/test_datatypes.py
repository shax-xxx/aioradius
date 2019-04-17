import ipaddress
import unittest
import struct
from datetime import datetime
from aioradius.protocol import datatypes, PROTOCOL_ENCODING, DATETIME_FORMATS
from aioradius.protocol.datatypes import DataTypeEncodingError, DataTypeDecodingError

__author__ = 'arusinov'

class AttributeTypesTestCase(unittest.TestCase):

    def test_not_implemented(self):
        coder = datatypes.NotImplementedType()
        with self.assertRaises(DataTypeEncodingError):
            coder.encode('')
        with self.assertRaises(DataTypeDecodingError):
            coder.decode(b'\x00')



    def test_base_type(self):
        value = 'abcабв'.encode(encoding=PROTOCOL_ENCODING)
        coder = datatypes.BaseType()
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, value)

    def test_byte_type(self):
        value = 64
        coder = datatypes.ByteType()
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(encoded_, struct.pack('!B', value))
        self.assertEqual(decoded_, value)

        value = datatypes.ByteType.max_value + 1
        with self.assertRaises(DataTypeEncodingError):
            encoded_ = coder.encode(value)

        value = datatypes.ByteType.min_value - 1
        with self.assertRaises(DataTypeEncodingError):
            encoded_ = coder.encode(value)

        value = 'abc'
        with self.assertRaises(DataTypeEncodingError):
            encoded_ = coder.encode(value)

        value = bytes('ю', encoding=PROTOCOL_ENCODING)
        with self.assertRaises(DataTypeDecodingError):
            encoded_ = coder.decode(value)

        value = b'\x01\xff'
        with self.assertRaises(DataTypeDecodingError):
            encoded_ = coder.decode(value)


    def test_short_type(self):
        value = 64
        coder = datatypes.ShortType()
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, value)

        value = datatypes.ShortType.max_value + 1
        with self.assertRaises(DataTypeEncodingError):
            encoded_ = coder.encode(value)

        value = datatypes.ShortType.min_value - 1
        with self.assertRaises(DataTypeEncodingError):
            encoded_ = coder.encode(value)

        value = 'abc'
        with self.assertRaises(DataTypeEncodingError):
            encoded_ = coder.encode(value)

    def test_string_type(self):
        coder = datatypes.StringType()

        value = 'qwerty'
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, value)

        encoded_ = coder.encode(value.encode(encoding=PROTOCOL_ENCODING))
        self.assertEqual(encoded_, value.encode(encoding=PROTOCOL_ENCODING))

        value = 'абвгд'
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, value)

        value = 1024
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, str(value))

    def test_ipv4address_type(self):
        coder = datatypes.IPv4AddressType()

        value = '192.168.0.1'
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, ipaddress.IPv4Address(value))

        with self.assertRaises(DataTypeEncodingError):
            coder.encode('a.b.c.d')
        with self.assertRaises(DataTypeEncodingError):
            coder.encode(None)

        with self.assertRaises(DataTypeDecodingError) as exc:
            coder.decode(b'\x00\x00')


    def test_datetime_type(self):
        coder = datatypes.DateTimeType()

        value = datetime.now().replace(microsecond=0)
        encoded_ = coder.encode(value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, value)

        string_value = value.strftime(DATETIME_FORMATS[0])
        encoded_ = coder.encode(string_value)
        decoded_ = coder.decode(encoded_)
        self.assertEqual(decoded_, value)

        with self.assertRaises(DataTypeEncodingError):
            coder.encode("Bad bad time")

        with self.assertRaises(DataTypeDecodingError):
            coder.decode(b'\x00')


