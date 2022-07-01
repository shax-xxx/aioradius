"""
aioradus.protocol.dictionary

This module contains classes for parsing and using RADIUS Dictionary files.

http://networkradius.com/doc/3.0.10/concepts/dictionary/introduction.html

Dictionary files are used to map between the names used by people and the binary data in the RADIUS packets.
The packets sent by the NAS contain attributes that have a number, a length, and binary data.
By contrast, a dictionary file consists of a list of entries with name, number, and data type.

Each dictionary file is composed of a series of lines of text. Similarly to the other configuration files,
comments may be added via the via hash or pound character (#).
Each line starts with a keyword that instructs the server how to interpret the rest of the line,
which consists of a series of strings separated by spaces.
The format and interpretation of the strings are defined differently for each keyword.

The keywords and their descriptions are given below.
    ATTRIBUTE attribute-name number type
        Defines a dictionary mapping and type for an attribute.

    VALUE attribute-name value-name number
        Defines an enumerated value for an attribute.

    VENDOR vendor-name number
        Defines a dictionary mapping for a vendor.

    BEGIN-VENDOR vendor-name
        Starts a block of attributes that are all managed by the named vendor.

    END-VENDOR vendor-name
        Ends a block of attributes that are all managed by the named vendor.
"""

import logging
import os

from bidict import bidict, DROP_NEW, ValueDuplicationError

from aioradius.protocol import dictfile
from aioradius.protocol.datatypes import DATATYPES
from aioradius.protocol import ATTRIBUTE_TYPE_SIZE, ATTRIBUTE_LEN_SIZE
from aioradius.protocol.crypt import ALLOWED_CRYPT_TYPES

__author__ = 'arusinov'

logger = logging.getLogger(__name__)

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
ALLOWED_TYPE_SIZES = (1, 2, 4)
ALLOWED_LEN_SIZES = (0, 1, 2)


class FormatError(Exception):
    pass


class DictionaryError(Exception):
    pass


class ParseError(Exception):
    def __init__(self, message, filename, line):
        super().__init__(message)
        self.message = message
        self.filename = filename
        self.line = line

    def __str__(self):
        return "ParseError at {0.filename}(line {0.line}): {0.message}".format(self)


class VendorDefinition(object):
    """
        Class VendorDefinition
            name: is usually the corporate name of the vendor,
                     it cannot have spaces or other "special" characters in it
            number: is a decimal number taken from the Internet Assigned Number Authority,
                       Enterprise Numbers registry, for that vendor
            format: is optional and defines the encoding method used when packing or
                        unpacking attributes in a packet. If not set, the default packing method as defined
                        in the RFCs is used. If set, the contents of the field are format=t,l.
                        The t field defines the size of the "vendor type" in bytes, and can be 1, 2, or 4.
                        The l field defines the size of the "vendor length" in bytes, and can be 0, 1, or 2.
    """

    def __init__(self, name, number, _format=(1, 1)):
        self.name = name
        self.number = int(number)
        self.format = _format

    @staticmethod
    def __parse_format(format_str):
        """
        Static method for parsing format in VENDOR definition

        :param format_str: string 'format=t,l'
        :return: tuple(t, l) or raise FormatError
        """
        format_str = format_str.replace(' ', '')
        if '=' not in format_str:
            raise FormatError("Bad 'format' field for VENDOR definition")

        _, format_value = format_str.split('=')
        try:
            res = tuple(map(int, format_value.split(',')))
        except ValueError:
            raise FormatError("Bad 'format' field for VENDOR definition")
        if len(res) < 2:
            raise FormatError("Bad 'format' field for VENDOR definition")
        if res[0] not in ALLOWED_TYPE_SIZES:
            raise FormatError("Bad 'format' field for VENDOR definition")
        if res[1] not in ALLOWED_LEN_SIZES:
            raise FormatError("Bad 'format' field for VENDOR definition")
        return res

    @classmethod
    def parse(cls, definition):
        """
            The VENDOR definition consists of a single line of text with three or four fields, as shown below:

            VENDOR - the keyword that indicates the format of this entry.
            vendor - name - the name of this vendor.
            number - the private enterprise number assigned to this vendor.
            format - optionally, the format of the VSAs used by this vendor.
        """
        tokens = definition.split()
        if len(tokens) < 3:
            raise FormatError("Bad VENDOR definition format, must be 3 or 4 tokens")

        name, number = tokens[1:3]
        _format = (1, 1)
        if len(tokens) == 4:
            _format = cls.__parse_format(tokens[3])
        return VendorDefinition(name, number, _format)


class AttributeDefinition(object):
    """
        Class AttributeDefinition

            name: (string) the local name given to this attribute
            number: (number) attribute id
            vendor: (optional) VendorDefinition for VSA or None for basic attribute
            type: (string) data type for this attribute from available types (see 'attrtypes')
            options: (optional, dict) containing modifiers for this attribute (has_tag, encrypt, has_array and other)
            values: (optional, bidict) containing ValueName, (AttribiteID, Value) for enumerated types

    """

    def __init__(self, name, number, datatype, vendor=None, options=None):
        self.name = name
        self.number = number

        if datatype not in DATATYPES.keys():
            raise FormatError("Unsupported data type '{0}' for attribute '{1}'".format(datatype, name))
        self.type = datatype

        self.vendor = vendor
        self.options = options if isinstance(options, dict) else dict()
        self.values = bidict()

        self.header_size = ATTRIBUTE_TYPE_SIZE + ATTRIBUTE_LEN_SIZE
        if self.vendor is not None:
            vsa_type_size, vsa_len_size = self.vendor.format
            self.header_size += (4 + vsa_type_size + vsa_len_size)

    def add_values(self, values):
        """ Adding values for attribute to bidict (used bidict policy DROP_NEW for duplicates) """
        _values = [(item[0], (self.number, item[1])) for item in values if len(item) == 2]
        self.values.putall(_values, DROP_NEW, DROP_NEW, DROP_NEW)

    @classmethod
    def parse(cls, definition, current_vendor=None):
        """
            Parse ATTRIBUTE definition
            :param definition: ATTRIBUTE definition string
            :param current_vendor: VendorDefinition for VSA or None for basic attribute

            :return: AttributeDefinition object
            :raise: FormatError
        """
        tokens = definition.split()
        name, number, datatype = tokens[1:4]
        # Fixing Capitalize datatype
        datatype = datatype.lower()

        # Fixing datatype[count]
        datatype = datatype.split('[')[0]

        options = dict(has_tag=False, is_array=False, encrypt=0)

        if len(tokens) == 5:
            raw_options = tokens[4]
            for item in raw_options.split(','):
                item = item.lower()
                if item == 'has_tag':
                    options['has_tag'] = True
                elif item == 'array':
                    options['is_array'] = True
                elif item.startswith('encrypt'):
                    if '=' in item:
                        _, value = item.lower().split('=')
                        try:
                            value = int(value)
                        except:
                            raise FormatError("Bad value for option 'encrypt' for attribute '{1}': {0}".format(
                                item, name
                            ))
                        if value not in ALLOWED_CRYPT_TYPES:
                            raise FormatError("Bad value for option 'encrypt' for attribute '{1}': {0}".format(
                                item, name
                            ))
                        options['encrypt'] = value
                else:
                    options[item] = item
        return AttributeDefinition(name, number, datatype, vendor=current_vendor, options=options)

    @staticmethod
    def parse_value(definition):
        """
            Parse VALUE definition

            :param definition: VALUE definition
            :return: tuple(ValueName, Value)
        """
        tokens = definition.split()
        if len(tokens) < 4:
            raise FormatError("Bad VALUE format")
        else:
            return tokens[1:]


class Dictionary(object):
    """
        Class `Dictionary` implement storage of RADIUS dictionaries

            vendors_bidict: (bidict) bidict object with set of pairs (VendorName, VendorID)
            vendors_hash: (dict) hashtable for pairs (VendorName as key, Vendor as value)

            attributes_bidict: (bidict) bidict object with set of pairs (AttributeName, (VendorID, AttributeID)
            attributes_hash: (dict) hashtable for pairs (AttributeName as key, Attribute as value)

            quit: (optional, bool) if True, print warnings at parsing process, else not print
    """

    def __init__(self, quit=False):
        self.quit = bool(quit)

        self.vendors_bidict = bidict()
        self.vendors_bidict.put('', 0)
        self.vendors_hash = dict()

        self.attributes_bidict = bidict()
        self.attributes_hash = dict()

        self.ignoring_vendors = set()

        # Trying to read basic dictionaries files from rfc
        rfc_dicts_path = os.path.join(BASE_PATH, 'rfc')
        if os.path.exists(rfc_dicts_path) and os.path.isdir(rfc_dicts_path):
            for file_ in os.listdir(rfc_dicts_path):
                self.merge(os.path.join(rfc_dicts_path, file_))

    def merge(self, file):
        """
        Parse RADIUS dictionary file and merge to current Dictionary object

        :param file: dictionary file path
        :return: None
        """
        fil = dictfile.DictFile(file)

        state = dict(vendor=None)  # parsing process state
        tmp_values = {}  # temporary storage for VALUE objects

        for line in fil:
            state['file'] = fil.File()
            state['line'] = fil.Line()
            line = line.split('#', 1)[0].strip()  # cut comments at the end of line

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()

            if key == 'VENDOR':
                # Parse VENDOR definition from file
                try:
                    _vendor = VendorDefinition.parse(line)
                    self.vendors_bidict.update([(_vendor.name, _vendor.number)])
                except ValueDuplicationError:
                    existed_ = self.vendors_bidict.inv.get(_vendor.number)
                    reason = "its number is the same as number of existed vendor '{}'".format(existed_)
                    self.quit or logger.warning(
                        "Warning at {0} (line {1}): Cant add vendor '{2.name}', {3}, ignore".format(
                            state['file'], state['line'],
                            _vendor, reason
                        )
                    )
                    self.ignoring_vendors.add(tokens[1])
                except FormatError as exc:
                    self.quit or logger.warning(
                        "Warning at {0} (line {1}): Cant add vendor '{2.name}', {3}, ignore".format(
                            state['file'], state['line'],
                            _vendor, str(exc)
                        )
                    )
                    self.ignoring_vendors.add(tokens[1])
                except Exception as e:
                    raise ParseError(
                        "Unhandled exception for vendor '{0}', {1}".format(tokens[1], e),
                        state['file'], state['line']
                    )
                else:
                    self.vendors_hash[_vendor.name] = _vendor

            elif key == 'ATTRIBUTE':
                # Parse ATTRIBUTE definition from file
                if state.get('vendor') in self.ignoring_vendors:
                    continue

                try:
                    vendor = self.vendors_hash.get(state['vendor'], None)
                    _attr = AttributeDefinition.parse(line, current_vendor=vendor)
                except FormatError as e:
                    self.quit or logger.warning("Warnign at {0}(line {1}): {2!s}".format(
                        state['file'], state['line'],
                        e
                    ))
                    continue
                except Exception as e:
                    raise ParseError(
                        "Unhandled exception for attribute '{0.name}', {1}".format(_attr, e),
                        state['file'], state['line']
                    )
                if _attr.vendor is not None:
                    if _attr.vendor.name not in self.vendors_bidict.keys():
                        raise ParseError("Vendor ",
                                         "'{0.vendor.name}' for attribute '{0.name}' undefined, logical error".format(
                                             _attr
                                         ),
                                         state['file'], state['line']
                        )
                    vendor_id = self.vendors_bidict.get(_attr.vendor.name, 0)
                else:
                    vendor_id = 0

                try:
                    self.attributes_bidict.update([(_attr.name, (vendor_id, _attr.number))])
                except ValueDuplicationError:
                    existed_attr = self.attributes_bidict.inv.get((vendor_id, _attr.number))
                    reason = "its number is the same as number of existed attribute '{}'".format(existed_attr)
                    self.quit or logger.warning("Warnign at",
                                                " {0}(line {1}): Cant add attribute '{2}', {3}, ignore".format(
                                                    state['file'], state['line'],
                                                    _attr.name, reason
                                                ))
                except Exception as e:
                    raise ParseError("Unhandled exception for adding attribute '{0.name}', {1!s}".format(
                        _attr, e
                    ), state['file'], state['line'])
                else:
                    self.attributes_hash[_attr.name] = _attr

            elif key == 'VALUE':
                # Parse VALUE definition from file
                if state.get('vendor') in self.ignoring_vendors:
                    continue
                try:
                    attr_name, value_name, value = AttributeDefinition.parse_value(line)
                except FormatError as e:
                    self.quit or logger.warning(
                        "Warning at {0}(line {1}): {2!s}".format(
                            state.get('file', 'unknown'), state.get('line', 0),
                            e
                        )
                    )
                    continue
                tmp_values.setdefault(attr_name, []).append((value_name, value))

            elif key == 'BEGIN-VENDOR':
                # Parse BEGIN-VENDOR definition
                if len(tokens) < 2:
                    raise ParseError('Bad BEGIN-VENDOR format (without vendor-name)', state['file'], state['line'])
                else:
                    state['vendor'] = tokens[1]

            elif key == 'END-VENDOR':
                # Parse END-VENDOR definition
                if len(tokens) < 2:
                    raise ParseError('Bad END-VENDOR format (without vendor-name)', state['file'], state['line'])
                else:
                    vendor = tokens[1]
                    if vendor != state['vendor']:
                        raise ParseError(
                            'Logical error, END-VENDOR {0} without BEGIN-VENDOR {0}'.format(vendor),
                            state['file'], state['line']
                        )
                    state['vendor'] = ''
            else:
                pass

        # Assign values by Attribute objects
        for key, values in tmp_values.items():
            if key in self.attributes_hash.keys():
                self.attributes_hash[key].add_values(values)
        del tmp_values

    @property
    def attributes(self):
        return self.attributes_hash.values()

    def get_attribute_definition_by_id(self, vendor_number, attr_number):
        """
        Return AttributeDefinition object from dictionary storage by vendor number and attribute number
        """
        name = self.attributes_bidict.inv.get((vendor_number, str(attr_number)), None)
        return self.attributes_hash.get(name, None) if name is not None else None

    def get_attribute_definition_by_name(self, attr_name):
        """
        Return AttributeDefinition object from dictionary storage by attribute name
        """
        return self.attributes_hash.get(attr_name, None) if attr_name is not None else None

    def get_vendor_by_number(self, vendor_id):
        """ Return Vendor object from dictionary by vendor ID """
        name = self.vendors_bidict.inv.get(vendor_id, None)
        return self.vendors_hash.get(name, None) if name is not None else None

    def get_vendor_by_name(self, vendor_name):
        return self.vendors_hash.get(vendor_name, None)


basic_dictionary = Dictionary()