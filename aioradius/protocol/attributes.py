"""
aioradius.protocol.attributes

This module contain class `Attribute` that implement functions for work with RADIUS attributes.
Class `Attribute` used aioradius.protocol.dictionary.basic_dictionary by default and
it can be overwriten by using classmethod `set_dictionary`

Usage:
    attribute_for_encode = Attribute.get_attribute_for_encode(ATTRIBUTE_NAME)
    encoded = attribute_for_encode.encode(VALUE)

    attribute_for_decode = Attribute.get_attribute_for_decode(BYTES)
    decoded_name, decoded_value = attribute_for_decode.decode(BYTES)
"""
import copy
import struct

from aioradius.protocol import ATTRIBUTE_TYPE_SIZE
from aioradius.protocol import ATTRIBUTE_LEN_SIZE
from aioradius.protocol.datatypes import DATATYPES
from aioradius.protocol.dictionary import basic_dictionary
from aioradius.protocol.crypt import USER_PASSWORD_CRYPT_TYPE, UserPasswordCrypt

__author__ = 'arusinov'


VENDOR_SPECIFIC_ATTRIBUTE = 26


class AttributeEncodingError(Exception):
    pass


class AttributeDecodingError(Exception):
    pass


class AttributeType(object):
    """
    Class `Attribute` implement functions for work with RADIUS attribute

    Attributes:
        used_dict(aioradius.protocol.dictionary.Dictionary) - used RADIUS dictionary for encoding/decoding attributes
        definition(aioradius.protocol.dictionary.AttributeDefinition) - definition for concrete attribute
                                                                        from dictionary
        encrypt - encryption type of attribute

    Instantiating:
        For instantiate concrete attribute used class methods:
        get_attribute_for_encode(attr_name)
        get_attribute_for_decode(attr_bytes)
    """
    used_dict = basic_dictionary

    @staticmethod
    def decode_vsa_attr_type(type_bytes, type_size):
        """ For internal usage only """
        if type_size == 1:
            vendor_attr_type = struct.unpack('!B', type_bytes)[0]
        elif type_size == 2:
            vendor_attr_type = struct.unpack('!H', type_bytes)[0]
        elif type_size == 4:
            vendor_attr_type = struct.unpack('!L', type_bytes)[0]
        else:
            raise AttributeDecodingError("Unsupported Vendor Type Format")
        return vendor_attr_type

    @staticmethod
    def decode_vsa_attr_length(length_bytes, length_size):
        """ For internal usage only """
        if length_size == 0:
            vendor_attr_length = 0
        elif length_size == 1:
            vendor_attr_length = struct.unpack('!B', length_bytes)[0]
        elif length_size == 2:
            vendor_attr_length = struct.unpack('!H', length_bytes)[0]
        else:
            raise AttributeDecodingError("Unsupported Vendor Type Format")
        return vendor_attr_length

    @classmethod
    def set_dictionary(cls, dictionary):
        """
        Set used dictionary for work with attributes

        Params:
            dictionary - instance of aioradius.protocol.dictionary.Dictionary
        """
        cls.used_dict = dictionary

    @classmethod
    def get_attribute_for_decode(cls, attr_bytes):
        """
        Fabric method for get instance of Attribute by input bytes

        Params:
            attr_bytes - bytes instance for that will be used decode function
        Return:
            Instance of Attribute
        """
        basic_attr_id = struct.unpack('!B', attr_bytes[:ATTRIBUTE_TYPE_SIZE])[0]
        basic_attr_len = struct.unpack('!B', attr_bytes[ATTRIBUTE_TYPE_SIZE:ATTRIBUTE_TYPE_SIZE+ATTRIBUTE_LEN_SIZE])[0]
        if basic_attr_id == VENDOR_SPECIFIC_ATTRIBUTE:
            vsa_bytes = attr_bytes[ATTRIBUTE_TYPE_SIZE + ATTRIBUTE_LEN_SIZE:]
            # Trying to get vendor by vendor code from dictionary
            vsa_vendor_id = struct.unpack("!I", vsa_bytes[:4])[0]
            vsa_vendor = cls.used_dict.get_vendor_by_number(vsa_vendor_id)
            if vsa_vendor is None:
                raise AttributeDecodingError('Vendor for ID {} is not found in dictionary'.format(vsa_vendor_id))
            # Get vsa_type size and vsa_length size from vendor format
            vsa_type_size, vsa_len_size = vsa_vendor.format
            # Get VendorAttrType, VendorAttrLength and VendorAttrData in bytes view
            vsa_attr_bytes = vsa_bytes[4:]
            vsa_attr_type_bytes = vsa_attr_bytes[0:vsa_type_size]
            vsa_attr_len_bytes = vsa_attr_bytes[vsa_type_size:vsa_type_size+vsa_len_size]
            vsa_attr_value_bytes = vsa_attr_bytes[vsa_type_size+vsa_len_size:]

            vsa_attr_type = cls.decode_vsa_attr_type(vsa_attr_type_bytes, vsa_type_size)
            vsa_attr_len = cls.decode_vsa_attr_length(vsa_attr_len_bytes, vsa_len_size)
            attribute_definition = cls.used_dict.get_attribute_definition_by_id(vsa_vendor_id, vsa_attr_type)
            return AttributeType(attribute_definition)
        else:
            attribute_definition = cls.used_dict.get_attribute_definition_by_id(0, basic_attr_id)
            return AttributeType(attribute_definition)

    @classmethod
    def get_attribute_for_encode(cls, attr_name):
        """
        Fabric method for get instance of Attribute by attribute name

        Params:
            attr_name - name of attribute, that will be used for encode
        Return:
            Instance of Attribute or None if attribute name is not exist in used dictionary
        """
        attribute_definition = cls.used_dict.get_attribute_definition_by_name(attr_name)
        return AttributeType(attribute_definition) if attribute_definition is not None else None

    def __init__(self, attribute_definition):
        """ For internal usage only """
        self.definition = attribute_definition

    @property
    def encrypt(self):
        """ Return encryption type of attribute """
        return self.definition.options.get('encrypt', 0)

    def encode_value(self, value):
        """ For internal usage only """
        # If this attributes has enumerate type (has set of values),
        # trying convert value from string representation to real value
        if len(self.definition.values.keys()) > 0:
            value = int(self.definition.values.get(value, None)[1])
            if value is None:
                raise AttributeEncodingError("Bad attribute value, you must use one of {!s}".format(
                    set(self.definition.values.keys()))
                )

        # Instantiating coder class for used type and encode
        attribute_coder_class = DATATYPES.get(self.definition.type)
        coder = attribute_coder_class()
        return coder.encode(value)

    @staticmethod
    def encode_vsa_attr_type(type_value, type_size):
        """ For internal usage only """
        if type_size == 1:
            encoded_vendor_attr_type = struct.pack('!B', int(type_value))
        elif type_size == 2:
            encoded_vendor_attr_type = struct.pack('!H', int(type_value))
        elif type_size == 4:
            encoded_vendor_attr_type = struct.pack('!L', int(type_value))
        else:
            raise AttributeEncodingError("Unsupported Vendor Type Format")
        return encoded_vendor_attr_type

    @staticmethod
    def encode_vsa_attr_length(length_value, length_size):
        """ For internal usage only """
        if length_size == 0:
            encoded_vendor_attr_length = None
        elif length_size == 1:
            encoded_vendor_attr_length = struct.pack('!B', length_value)
        elif length_size == 2:
            encoded_vendor_attr_length = struct.pack('!H', length_value)
        else:
            raise AttributeEncodingError("Unsupported Vendor Type Format")
        return encoded_vendor_attr_length

    def encode_vsa(self, value):
        """ For internal usage only """
        attribute_id = self.definition.number
        vendor = self.definition.vendor
        vsa_type_size, vsa_length_size = vendor.format

        encoded_vsa_value = self.encode_value(value)
        vsa_length = len(encoded_vsa_value) + vsa_type_size + vsa_length_size

        encoded_vsa_type = self.encode_vsa_attr_type(int(attribute_id), vsa_type_size)
        encoded_vsa_length = self.encode_vsa_attr_length(vsa_length, vsa_length_size)
        encoded_vsa_string = encoded_vsa_type + encoded_vsa_length + encoded_vsa_value

        encoded_length = struct.pack('!B', len(encoded_vsa_string) + 4 + ATTRIBUTE_TYPE_SIZE + ATTRIBUTE_LEN_SIZE)
        encoded_type = struct.pack('!B', VENDOR_SPECIFIC_ATTRIBUTE)

        encoded_vendor_id = b'\x00' + struct.pack('!L', vendor.number)[1:]

        return encoded_type + encoded_length + encoded_vendor_id + encoded_vsa_string

    def encode_basic(self, value):
        """ For internal usage only """
        encoded_value = self.encode_value(value)

        total_length = len(encoded_value) + ATTRIBUTE_LEN_SIZE + ATTRIBUTE_TYPE_SIZE
        encoded_header = struct.pack('!BB', int(self.definition.number), total_length)
        return encoded_header + encoded_value

    def encode(self, value):
        """
        Return encoded bytes view of value for current instance of Attribute

        Raise:
            AttributeEncodeError if encoding process has error
        """
        if self.definition.vendor is not None:
            # It is VendorSpecificAttribute
            return self.encode_vsa(value)
        else:
            # It is basic attribute
            return self.encode_basic(value)

    def decode(self, attr_bytes):
        """
        Return pair of attribute_name and decoded value from bytes view of attribute

        Raise:
            AttributeDecodeError if decoding process has error
        """
        attr_value = attr_bytes[self.definition.header_size:]
        attribute_coder_class = DATATYPES.get(self.definition.type)
        coder = attribute_coder_class()
        decoded_value = coder.decode(attr_value)
        decoded_value_view = self.definition.values.inv.get((str(self.definition.number), str(decoded_value)), None)
        if decoded_value_view is not None:
            decoded_value = decoded_value_view
        return self.definition.name, decoded_value

    def is_vendor_specific(self):
        if self.definition.vendor is None:
            return False
        else:
            return self.definition.vendor.number != 0

    @property
    def name(self):
        return self.definition.name

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        if self.definition != other.definition:
            return False

        return True


class NewAttrSet(object):

    def __init__(self, *args):
        self.crypt_secret = None
        self.crypt_authenticator = None

        self._order = list()
        self._data = dict()
        self.extend(*args)

    def __iter__(self):
        for name in self._order:
            for value in self._data.get(name, []):
                yield name, value

    def __contains__(self, item):
        return item in self._order

    def __len__(self):
        return len(self._order)

    def __str__(self):
        return "<{class_name}: {}>".format(list(self), class_name=self.__class__.__name__)

    def __eq__(self, other):
        if other is self:
            return True
        if isinstance(other, self.__class__):
            return list(other) == list(self)
        return False

    def __bytes__(self):
        attributes_bytes = bytes()
        for name in self.names():
            values = self.get(name, many=True)
            attribute_type = AttributeType.get_attribute_for_encode(name)
            for value in values:
                #If attribute definition contain field encrypt=1, value must be encrypted
                if attribute_type.encrypt == USER_PASSWORD_CRYPT_TYPE:
                    encrypted_value = UserPasswordCrypt.encrypt(value, self.crypt_secret,
                                                                    self.crypt_authenticator)
                    attributes_bytes += attribute_type.encode(encrypted_value)
                else:
                    # Store attribute to bytes view
                    attributes_bytes += attribute_type.encode(value)
        return attributes_bytes

    def from_bytes(self, attributes_bytes):
        while len(attributes_bytes) > 0:
            attribute_length = struct.unpack('!B', attributes_bytes[1:2])[0]
            attribute_bytes = attributes_bytes[:attribute_length]
            attribute_type = AttributeType.get_attribute_for_decode(attribute_bytes)
            attribute_name, attribute_value = attribute_type.decode(attribute_bytes)
            # If attribute definition contain field encrypt=1, value must be decrypted
            if attribute_type.encrypt == USER_PASSWORD_CRYPT_TYPE:
                attribute_value = UserPasswordCrypt.decrypt(attribute_value,
                                                            self.crypt_secret, self.crypt_authenticator)
            self.add(attribute_name, attribute_value)

            attributes_bytes = attributes_bytes[attribute_length:]

    def set_crypt_params(self, secret, authenticator):
        self.crypt_secret = secret
        self.crypt_authenticator = authenticator

    def clear(self):
        self._data = dict()
        self._order = list()

    def copy(self):
        return copy.deepcopy(self)

    def add(self, name, value):
        attr_type = AttributeType.get_attribute_for_encode(name)
        if attr_type is None:
            raise KeyError("Attribute with name '{}' is not exist in used dictionary".format(name))
        if name not in self._order:
            self._data.setdefault(name, [])
            self._order.append(name)
        if value not in self._data[name]:
            self._data[name].append(value)

    def extend(self, *iterable_of_pairs):
        if isinstance(iterable_of_pairs, tuple) and len(iterable_of_pairs) > 0 and \
            not isinstance(iterable_of_pairs[0], (list, tuple, set)):
            iterable_of_pairs = (iterable_of_pairs, )
        if isinstance(iterable_of_pairs, (list, tuple, set)):
            for item in iterable_of_pairs:
                try:
                    name, value = item
                except ValueError:
                    continue
                else:
                    self.add(name, value)

    def get(self, name, default=None, many=False):
        try:
            return self._data[name][-1] if not many else self._data[name]
        except (KeyError, IndexError):
            return default if not many else [default, ]

    def remove(self, key):
        if key not in self._order:
            raise KeyError(key)
        else:
            self._order.remove(key)
            self._data.pop(key)

    def names(self):
        return tuple(self._order)


class AttributesSet(NewAttrSet):
    pass


