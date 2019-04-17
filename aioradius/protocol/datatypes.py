"""
aioradius.protocol.datatypes

This module contains classes that implements encode/decode functions for various RADIUS data types
These classes are used for encode/decode values of attributes

For types that are not implemented yet is used special class NotImplementerType, that raise special types of exception
"""
import ipaddress
import struct
import time
from datetime import datetime
from aioradius.protocol import PROTOCOL_ENCODING, DATETIME_FORMATS

__author__ = 'arusinov'


class DataTypeEncodingError(Exception):
    pass


class DataTypeDecodingError(Exception):
    pass


class NotImplementedType(object):
    """
    Special class for mark not implemented data types

    It is raise DataTypeEncodingError for encode method and DataTypeDecodingError for decode method
    """
    def encode(self, value):
        raise DataTypeEncodingError("Not implemented")

    def decode(self, value):
        raise DataTypeDecodingError("Not implemented")


class BaseType(object):
    """
    Base data type

    It returns the same values for encode/decode methods
    """
    def encode(self, value):
        return value

    def decode(self, value):
        return value


class ComplexType(BaseType):
    """ Special Type class for mark Vendor-Specific Attribute """
    pass


class _NumericType(BaseType):
    """
    Base numeric type
    It is used for encode/decode numeric types as byte, short, integer, integer64
    """

    name = 'byte'
    fmt = '!B'
    min_value = 0
    max_value = 255

    def encode(self, value):
        if not isinstance(value, int):
            try:
                value = int(value)
            except ValueError:
                raise DataTypeEncodingError("Value for type '{}' must be numeric from {} to {}".format(
                    self.name, self.min_value, self.max_value
                ))
        if value < self.min_value or value > self.max_value:
            raise DataTypeEncodingError("Value for type '{}' must be numeric from {} to {}".format(
                self.name, self.min_value, self.max_value
            ))
        return struct.pack(self.fmt, value)

    def decode(self, value):
        if len(value) != struct.calcsize(self.fmt):
            raise DataTypeDecodingError("Size of '{}' value must be {} byte(s)".format(
                self.name,
                struct.calcsize(self.fmt)
            ))
        try:
            return int(struct.unpack(self.fmt, value)[0])
        except ValueError:
            raise DataTypeDecodingError("Cant decode value {} as {}".format(value, self.name))


class ByteType(_NumericType):
    name = 'byte'
    fmt = '!B'
    min_value = 0
    max_value = 255


class ShortType(_NumericType):
    name = 'short'
    fmt = '!H'
    min_value = 0
    max_value = 65535


class IntegerType(_NumericType):
    name = 'integer'
    fmt = '!I'
    min_value = 0
    max_value = 4294967295


class Integer64Type(_NumericType):
    name = 'integer64'
    fmt = '!Q'
    min_value = 0
    max_value = 18446744073709551615


class StringType(BaseType):
    def encode(self, value):
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode(encoding=PROTOCOL_ENCODING)
        else:
            return str(value).encode(encoding=PROTOCOL_ENCODING)

    def decode(self, value):
        try:
            return value.decode(encoding=PROTOCOL_ENCODING)
        except UnicodeDecodeError:
            return value

class IPv4AddressType(BaseType):
    """
        Data type encodes an IPv4 address in network byte order.
        Where the range of addresses for a particular attribute is
        limited to a subset of possible addresses, specifications MUST define
        the valid range(s).  Attributes with Address values outside of the
        allowed range(s) SHOULD be treated as invalid attributes.
    """
    def encode(self, value):
        if isinstance(value, ipaddress.IPv4Address):
            return value.packed
        elif isinstance(value, str):
            try:
                return ipaddress.IPv4Address(value).packed
            except ipaddress.AddressValueError:
                raise DataTypeEncodingError('Bad format of IPv4Address: {}'.format(value))
        else:
            raise DataTypeEncodingError('Bad format of IPv4Address: {}'.format(value))

    def decode(self, value):

        if len(value) != 4:  # https://tools.ietf.org/html/rfc8044#section-3.8
            raise DataTypeDecodingError("Cant decode value {} as IPv4Address, need 4 bytes".format(value))

        try:
            return ipaddress.IPv4Address(value)
        except Exception:
            raise DataTypeDecodingError("Cant decode value {} as IPv4Address".format(value))


class DateTimeType(BaseType):
    """
        Data type encodes time as a 32-bit unsigned value in
        network byte order and in seconds since 00:00:00 UTC, January 1,
        1970.  We note that dates before the year 2017 are likely to indicate
        configuration errors or lack of access to the correct time.

        Note that the "time" attribute is defined to be unsigned, which means
        that it is not subject to a signed integer overflow in the year 2038.
    """
    @staticmethod
    def __datetime_to_bytes(dt):
        try:
            seconds_from_epoch = int(time.mktime(dt.timetuple()))
            return struct.pack('!I', seconds_from_epoch)
        except ValueError:
            raise DataTypeEncodingError('Cant encode datetime object {} to 4-bytes object'.format(dt))

    def encode(self, value):
        if isinstance(value, datetime):
            return self.__datetime_to_bytes(value)

        else:
            dt = None
            value = str(value)
            # Trying parse datetime value for formats from supported DATETIME_FORMATS
            for _format in DATETIME_FORMATS:
                try:
                    dt = datetime.strptime(value, _format)
                except ValueError:
                    continue

            if isinstance(dt, datetime):
                return self.__datetime_to_bytes(dt)
            else:
                raise DataTypeEncodingError('Bad format of date|time attribute: {}'.format(value))

    def decode(self, value):
        if len(value) != 4:  # https://tools.ietf.org/html/rfc8044#section-3.3
            raise DataTypeDecodingError("Cant decode value {} as date|time, need 4 bytes".format(value))
        timestamp = int(struct.unpack('!I', value)[0])
        return datetime.fromtimestamp(timestamp)

DATATYPES = {
    # RFC 8044
    'integer': IntegerType,
    'enum': IntegerType,
    'time': DateTimeType,
    'text': StringType,
    'string': StringType,
    'concat': NotImplementedType,
    'ifid':  NotImplementedType,
    'ipv4addr': IPv4AddressType,
    'ipv6addr': NotImplementedType,
    'ipv6prefix': NotImplementedType,
    'ipv4prefix': NotImplementedType,
    'integer64': Integer64Type,
    'vsa': ComplexType,
    'tlv': NotImplementedType,
    'extended': NotImplementedType,
    'long-extended': NotImplementedType,
    'evs': NotImplementedType,

    #FreeRadius
    'octets': BaseType,
    'ipaddr': IPv4AddressType,
    'date': DateTimeType,
    'ether': NotImplementedType,
    'abinary': NotImplementedType,
    'byte': ByteType,
    'short': ShortType,
    'signed': NotImplementedType,
    'struct': NotImplementedType
}