"""
aioradius.protocol.packet
"""
from abc import ABC, abstractmethod
import hashlib
import logging
import os
import random
import struct
import io

from aioradius.protocol.attributes import AttributeType, AttributesSet
from aioradius.protocol.crypt import cast_to_bytes

__author__ = 'arusinov'

logger = logging.getLogger(__name__)

CODE_SIZE = 1
IDENTIFIER_SIZE = 1
AUTHENTICATOR_SIZE = 16
LENGTH_SIZE = 2
HEADER_SIZE = CODE_SIZE + IDENTIFIER_SIZE + LENGTH_SIZE + AUTHENTICATOR_SIZE

MIN_IDENTIFIER = 0
MAX_IDENTIFIER = 255

# RFC 2865
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11
ACCOUNTING_REQUEST = 4
ACCOUNTING_RESPONSE = 5
STATUS_SERVER = 12
STATUS_CLIENT = 13
DISCONNECT_REQUEST = 40
DISCONNECT_ACK = 41
DISCONNECT_NACK = 42
COA_REQUEST = 43
COA_ACK = 44
COA_NACK = 45
RESERVED = 255

CODES = (
    ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE,
    ACCOUNTING_REQUEST, ACCOUNTING_RESPONSE,
    STATUS_SERVER, STATUS_CLIENT,
    DISCONNECT_REQUEST, DISCONNECT_ACK, DISCONNECT_NACK,
    COA_REQUEST, COA_ACK, COA_NACK
)


class PacketError(Exception):
    pass


def random_authenticator():
    return os.urandom(AUTHENTICATOR_SIZE)


def hashed_authenticator(secret_key, code, identifier, attributes_bytes,
                           request_authenticator=None):
    request_authenticator = request_authenticator or bytes(16)
    packet_size = HEADER_SIZE + len(attributes_bytes)
    hash_func = hashlib.md5()
    hash_func.update(struct.pack("!B", code))
    hash_func.update(struct.pack("!B", identifier))
    hash_func.update(struct.pack("!H", packet_size))
    hash_func.update(request_authenticator)
    hash_func.update(attributes_bytes)
    hash_func.update(cast_to_bytes(secret_key))
    return hash_func.digest()


class RadiusPacket(ABC):
    """
    Base abstract class `RadiusPacket` implement common functions of all types of packets

    Class attributes:
        RADIUS_CODE(int) - Radius code of packet type

    Attributes:
        code(int,property) - return code of concrete packet
        identifier(int,optional) - field is one octet, and aids in matching requests and replies
        packet_size(int,property) - return size of result packet in bytes
        authenticator(bytes,property) - return authenticator for packet
        attributes_bytes(bytes,property) - return packet attributes in bytes view

        attributes_size(int,property) - return size of bytes view of packet attributes
        secret_key(str|bytes) - shared secret between client and server
        reply_to(RadiusRequest,optional) - packet for which the response id created, used for responses only
        strict(bool,optional) - if this flag is True, `PacketError` will be raised in case of an error,
                       if this flag is False, Warning will be logged and error will be ignored
    """
    RADIUS_CODE = 0
    STRICT_MODE = True

    @classmethod
    def disable_strict_mode(cls):
        cls.STRICT_MODE = False

    def __init__(self, secret_key,
                 identifier=None):
        """
        Initialize radius packet object

        Params:
            secret_key(string|byte) - shared secret between client and server
            identifier(int,optional) - packet identifier, value from 0 to 255, default is randomized
        Raises:
            PacketError exception
        """
        self.secret_key = secret_key

        self.__code = self.RADIUS_CODE
        # Validate packet identifier
        if identifier is not None:
            try:
                identifier = int(identifier)
            except ValueError:
                raise PacketError("Field `identifier` must be an unsigned byte")
            if identifier < MIN_IDENTIFIER or identifier > MAX_IDENTIFIER:
                raise PacketError("Field `identifier` must be an unsigned byte")
            self.__identifier = identifier
        else:
            # If identifier is not set, randomize it
            self.__identifier = random.randint(MIN_IDENTIFIER - 1, MAX_IDENTIFIER + 1)

        self._authenticator = None

        self.__attributes = AttributesSet()
        self._attributes_bytes = bytes(0)

    @property
    def code(self):
        """ Return packet RADIUS code (ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT and etc)"""
        return self.__code

    @property
    def type_name(self):
        return self.__class__.__name__

    @property
    def identifier(self):
        return self.__identifier

    @identifier.setter
    def identifier(self, value):
        try:
            identifier = int(value)
        except ValueError:
            raise PacketError("Field `identifier` must be an unsigned byte")
        if identifier < MIN_IDENTIFIER or identifier > MAX_IDENTIFIER:
            raise PacketError("Field `identifier` must be an unsigned byte")
        self.__identifier = identifier

    @property
    def authenticator(self):
        return self._authenticator or bytes(16)

    @property
    def attributes(self):
        return self.__attributes

    @attributes.setter
    def attributes(self, attributes):
        if isinstance(attributes, AttributesSet):
            self.__attributes = attributes
        elif isinstance(attributes, (list, tuple, set)):
            self.__attributes = AttributesSet(*attributes)
        else:
            raise PacketError("Cant set packet attributes, parameter `attributes` must be an instance of " +
                              "`AttributesSet` class or iterable of pairs (name, value)")

    def __eq__(self, other):
        if other is self:
            return True
        if type(other) != type(self):
            return False
        if self.code != other.code:
            return False
        if self.identifier != other.identifier:
            return False
        if self.authenticator != other.authenticator:
            return False
        for key in self.attributes.names():
            if self.attributes.get(key, many=True) != other.attributes.get(key, many=True):
                return False
        return True

    def __str__(self):
        return "<RADIUS Packet '{}' Identifier {}>".format(
            self.type_name, self.identifier
        )

    def __bytes__(self):
        if self.STRICT_MODE:
            self._verify_attributes()
        self._attributes_bytes = bytes(self.attributes)
        self._authenticator = self._compute_authenticator()
        packet_size = HEADER_SIZE + len(self._attributes_bytes)
        header_bytes = struct.pack('!BBH', self.code, self.identifier, packet_size)
        return header_bytes + self._authenticator + self._attributes_bytes

    @abstractmethod
    def _compute_authenticator(self):
        pass

#    @abstractmethod
#    def _verify_authenticator(self, request=None):
#        pass

    @abstractmethod
    def _verify_attributes(self):
        pass

#    def verify(self, request=None):
#        self._verify_attributes()
#        self._verify_authenticator(request)

    def from_bytes(self, packet_bytes):
        self._authenticator = packet_bytes[4:HEADER_SIZE]
        self._attributes_bytes = packet_bytes[HEADER_SIZE:]
        attributes = AttributesSet()
        attributes.set_crypt_params(self.secret_key, self.authenticator)
        attributes.from_bytes(self._attributes_bytes)
        self.attributes = attributes


class RadiusRequest(RadiusPacket):

    def _compute_authenticator(self, **kwargs):
        secret_key = kwargs.get('secret_key', self.secret_key)
        code = kwargs.get('code', self.code)
        identifier = kwargs.get('identifier', self.identifier)
        attributes_bytes = kwargs.get('attributes_bytes', self._attributes_bytes)

        value = hashed_authenticator(secret_key, code, identifier, attributes_bytes)
        return value

    def _verify_authenticator(self, packet_bytes):
        code, identifier = struct.unpack('!BB', packet_bytes[0:2])
        request_authenticator = packet_bytes[4:HEADER_SIZE]
        attributes_bytes = packet_bytes[HEADER_SIZE:]
        computed_authenticator = self._compute_authenticator(code=code, identifier=identifier,
                                                             attributes_bytes=attributes_bytes)
        if computed_authenticator != request_authenticator:
            raise PacketError("Packet verification problem: bad Request-Authenticator")
        else:
            logger.debug("Request-Authenticator is verified for packet {!s}".format(self))

    def from_bytes(self, packet_bytes):
        self._verify_authenticator(packet_bytes)
        super(RadiusRequest, self).from_bytes(packet_bytes)



class AccessRequest(RadiusRequest):
    """ Radius Access-Request packet """
    RADIUS_CODE = ACCESS_REQUEST

    def _verify_attributes(self):
        # See RFC2865 sec 5.44 for details
        __REJECTED_ATTRIBUTES = (
            'Framed-Routing', 'Filter-Id', 'Login-Service', 'Login-TCP-Port', 'Reply-Message',
            'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Session-Timeout',
            'Idle-Timeout', 'Termination-Action', 'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network',
            'Framed-AppleTalk-Zone'
        )

        attributes_names = self.attributes.names()
        for name in attributes_names:
            if name in __REJECTED_ATTRIBUTES:
                raise PacketError("Attribute '{}' is rejected for 'Access-Request' packet".format(name))
        # Validate RFC2865 requirements (see RFC2865 sec 4.1)
        if 'User-Name' not in attributes_names:
            raise PacketError("'Access-Request' packet MUST HAVE required attribute 'User-Name'")
        # TODO: Check passwords fields exist
        if 'NAS-IP-Address' not in attributes_names and 'NAS-Identifier' not in attributes_names:
            raise PacketError("'Access-Request' packet MUST contain either a NAS-IP-Address attribute" +
                              " or a NAS-Identifier attribute (or both).")

    def _compute_authenticator(self):
        if self._authenticator is None:
            self._authenticator = random_authenticator()
        return self._authenticator

    def _verify_authenticator(self, packet_bytes):
        pass

    def __bytes__(self):
        if self.STRICT_MODE:
            self._verify_attributes()
        self._authenticator = self._compute_authenticator()
        # TODO: Freeze attributes
        self.attributes.set_crypt_params(self.secret_key, self.authenticator)
        attributes_bytes = bytes(self.attributes)
        packet_size = HEADER_SIZE + len(attributes_bytes)
        header_bytes = struct.pack('!BBH', self.code, self.identifier, packet_size)
        return header_bytes + self.authenticator + attributes_bytes

    def create_reply(self, reply_code):
        """
        Fabric method for creating radius response for this request packet

        Params:
            reply_code - any of (ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE)
        """

        if reply_code == ACCESS_ACCEPT:
            response_class = AccessAccept
        elif reply_code == ACCESS_CHALLENGE:
            response_class = AccessChallenge
        else:
            response_class = AccessReject

        return response_class(self.secret_key,
                              identifier=self.identifier,
                              request_authenticator=self.authenticator)


class StatusServer(RadiusRequest):
    """ Radius Access-Request packet """
    RADIUS_CODE = STATUS_SERVER

    def _verify_attributes(self):
        pass

    def _compute_authenticator(self):
        if self._authenticator is None:
            self._authenticator = random_authenticator()
        return self._authenticator

    def _verify_authenticator(self, packet_bytes):
        pass


class AccountingStatusServer(StatusServer):

    @property
    def type_name(self):
        super_type_name = 'StatusServer'
        return super_type_name


class AccountingRequest(RadiusRequest):
    """ Radius Access-Request packet """
    RADIUS_CODE = ACCOUNTING_REQUEST

    # See RFC2866 sec 5.13 for details
    __REJECTED_ATTRIBUTES = (
        'User-Password', 'CHAP-Password', 'Reply-Message', 'State', 'CHAP-Challenge'
    )
    __REQUIRED_ATTRIBUTES = (
        'Acct-Status-Type', 'Acct-Session-Id'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            if name in self.__REJECTED_ATTRIBUTES:
                raise PacketError("Attribute '{}' is rejected for 'Accounting-Request' packet".format(name))

        if 'NAS-IP-Address' not in attributes_names and 'NAS-Identifier' not in attributes_names:
            raise PacketError("'Accounting-Request' packet MUST contain either a NAS-IP-Address attribute" +
                              " or a NAS-Identifier attribute (or both).")
        for item in self.__REQUIRED_ATTRIBUTES:
            if item not in attributes_names:
                raise PacketError("'Accounting-Request' packet MUST contain '{}' attribute".format(item))

    def create_reply(self, *args, **kwargs):
        """
        Fabric method for creating radius accounting response for this accounting request packet
        """
        return AccountingResponse(self.secret_key,
                                      self.identifier,
                                      self.authenticator)


class DisconnectRequest(RadiusRequest):
    RADIUS_CODE = DISCONNECT_REQUEST

    # See RFC5176 sec 3.6 for details
    __REJECTED_ATTRIBUTES = (
        'User-Password', 'CHAP-Password', 'Service-Type', 'Framed-IP-Address',
        'State', 'NAS-Port-Type', 'Error-Cause'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            if name in self.__REJECTED_ATTRIBUTES:
                self.attributes.remove(name)

        if 'NAS-IP-Address' not in attributes_names and 'NAS-Identifier' not in attributes_names:
            raise PacketError("'Disconnect-Request' packet MUST contain either a NAS-IP-Address attribute" +
                              " or a NAS-Identifier attribute (or both).")

    def create_reply(self, reply_code):
        """
        Fabric method for creating radius response for this request packet

        Params:
            reply_code - any of (DISCONNECT_ACK, DISCONNECT_NACK)
        """

        if reply_code == DISCONNECT_ACK:
            response_class = DisconnectACK
        else:
            response_class = DisconnectNACK

        return response_class(self.secret_key,
                              identifier=self.identifier,
                              request_authenticator=self.authenticator)

class CoARequest(RadiusRequest):
    RADIUS_CODE = COA_REQUEST

    # See RFC5176 sec 3.6 for details
    __REJECTED_ATTRIBUTES = (
        'User-Password', 'CHAP-Password', 'Originating-Line-Info', 'Error-Cause'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            if name in self.__REJECTED_ATTRIBUTES:
                self.attributes.remove(name)

        if 'NAS-IP-Address' not in attributes_names and 'NAS-Identifier' not in attributes_names:
            raise PacketError("'CoA-Request' packet MUST contain either a NAS-IP-Address attribute" +
                              " or a NAS-Identifier attribute (or both).")

    def create_reply(self, reply_code):
        """
        Fabric method for creating radius response for this request packet

        Params:
            reply_code - any of (COA_ACK, COA_NACK)
        """

        if reply_code == COA_ACK:
            response_class = CoaACK
        else:
            response_class = CoaNACK

        return response_class(self.secret_key,
                              identifier=self.identifier,
                              request_authenticator=self.authenticator)


class RadiusResponse(RadiusPacket):

    def __init__(self,
                 secret_key,
                 identifier,
                 request_authenticator,
                 ):
        super(RadiusResponse, self).__init__(secret_key, identifier)
        self.__request_authenticator = request_authenticator

    def _compute_authenticator(self):
        return hashed_authenticator(self.secret_key, self.code, self.identifier, self._attributes_bytes,
                                    request_authenticator=self.__request_authenticator)

    def _verify_authenticator(self):
        # Compute and verify packet authenticator
        computed_authenticator = self._compute_authenticator()
        if computed_authenticator != self.authenticator:
            raise PacketError("Packet verification problem: bad authenticator of response")
        else:
            logger.debug("Response-Authenticator is verified for packet {!s}".format(self))

    def from_bytes(self, packet_bytes):
        super(RadiusResponse, self).from_bytes(packet_bytes)
        self._verify_authenticator()


class AccessAccept(RadiusResponse):
    """ Radius Access-Accept packet """
    RADIUS_CODE = ACCESS_ACCEPT
    # See RFC2865 sec 5.44 for details
    __REJECTED_ATTRIBUTES = (
        'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port',
        'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier',
        'CHAP-Challenge', 'NAS-Port-Type'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            if name in self.__REJECTED_ATTRIBUTES:
                raise PacketError("Attribute '{}' is rejected for 'Access-Accept' packet".format(name))


class AccessReject(RadiusResponse):
    """ Radius Access-Reject packet """
    RADIUS_CODE = ACCESS_REJECT
    # See RFC2865 sec 5.44 for details
    ACCEPTED_ATTRIBUTES = (
        'Reply-Message', 'State', 'Proxy-State'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            # Vendor-Specific is allowed
            if attr.is_vendor_specific():
                continue
            if name not in self.ACCEPTED_ATTRIBUTES:
                raise PacketError("Attribute '{}' is rejected for 'Access-Reject' packet".format(name))


class AccessChallenge(RadiusResponse):
    """ Radius Access-Challenge packet """
    RADIUS_CODE = ACCESS_CHALLENGE
    # See RFC2865 sec 5.44 for details
    __ACCEPTED_ATTRIBUTES = (
        'Reply-Message', 'Session-Timeout', 'Idle-Timeout', 'Proxy-State'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            # Vendor-Specific is allowed
            if attr.is_vendor_specific():
                continue
            if name not in self.__ACCEPTED_ATTRIBUTES:
                raise PacketError("Attribute '{}' is rejected for 'Access-Challenge' packet".format(name))


class AccountingResponse(RadiusResponse):
    """ Radius Accounting-Response packet """
    RADIUS_CODE = ACCOUNTING_RESPONSE

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            if attr.is_vendor_specific() or name == 'Proxy-State':
                continue
            else:
                raise PacketError("Attribute '{}' is rejected for 'Accounting-Response' packet".format(name))


class DisconnectACK(RadiusResponse):
    """ Radius Disconnect-ACK packet """
    RADIUS_CODE = DISCONNECT_ACK

    # See RFC5176 sec 3.6 for details
    ACCEPTED_ATTRIBUTES = (
        'Proxy-State', 'Acct-Terminate-Cause', 'Event-Timestamp', 'Message-Authenticator'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            # Vendor-Specific is allowed
            if attr.is_vendor_specific():
                continue
            if name not in self.ACCEPTED_ATTRIBUTES:
                self.attributes.remove(name)


class DisconnectNACK(RadiusResponse):
    """ Radius Disconnect-NACK packet """
    RADIUS_CODE = DISCONNECT_NACK

    # See RFC5176 sec 3.6 for details
    ACCEPTED_ATTRIBUTES = (
        'Proxy-State', 'Event-Timestamp', 'Message-Authenticator', 'Error-Cause'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            # Vendor-Specific is allowed
            if attr.is_vendor_specific():
                continue
            if name not in self.ACCEPTED_ATTRIBUTES:
                self.attributes.remove(name)


class CoaACK(RadiusResponse):
    """ Radius CoA-ACK packet """
    RADIUS_CODE = COA_ACK

    # See RFC5176 sec 3.6 for details
    ACCEPTED_ATTRIBUTES = (
        'State', 'Proxy-State', 'Event-Timestamp', 'Message-Authenticator'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            # Vendor-Specific is allowed
            if attr.is_vendor_specific():
                continue
            if name not in self.ACCEPTED_ATTRIBUTES:
                self.attributes.remove(name)


class CoaNACK(RadiusResponse):
    """ Radius CoA-NACK packet """
    RADIUS_CODE = COA_NACK

    # See RFC5176 sec 3.6 for details
    ACCEPTED_ATTRIBUTES = (
        'Service-Type', 'State', 'Proxy-State', 'Event-Timestamp', 'Message-Authenticator', 'Error-Cause'
    )

    def _verify_attributes(self):
        attributes_names = self.attributes.names()
        for name in attributes_names:
            attr = AttributeType.get_attribute_for_encode(name)
            # Vendor-Specific is allowed
            if attr.is_vendor_specific():
                continue
            if name not in self.ACCEPTED_ATTRIBUTES:
                self.attributes.remove(name)


def get_packet_identifier(data):
    packet_identifier = struct.unpack("!B", data[CODE_SIZE:CODE_SIZE + IDENTIFIER_SIZE])[0]
    return packet_identifier


CLASS_BY_CODE = {
    ACCESS_REQUEST: AccessRequest,
    ACCESS_ACCEPT: AccessAccept,
    ACCESS_REJECT: AccessReject,
    ACCESS_CHALLENGE: AccessChallenge,
    ACCOUNTING_REQUEST: AccountingRequest,
    ACCOUNTING_RESPONSE: AccountingResponse,
    DISCONNECT_REQUEST: DisconnectRequest,
    DISCONNECT_ACK: DisconnectACK,
    DISCONNECT_NACK: DisconnectNACK,
    COA_REQUEST: CoARequest,
    COA_ACK: CoaACK,
    COA_NACK: CoaNACK
}


def get_packet_class(data, radius_type='auth'):
    """ Return subclass of RadiusPacket by code """
    if not isinstance(data, bytes):
        raise PacketError("at `get_packet_class` function: `data` must be a `bytes` instance")
    packet_code = struct.unpack("!B", data[:1])[0]
    if packet_code == STATUS_SERVER:
        return AccountingStatusServer if radius_type == 'acc' else StatusServer
    elif packet_code in CLASS_BY_CODE.keys():
        return CLASS_BY_CODE.get(packet_code)
    else:
        raise PacketError("Bad RADIUS packet code: {}".format(packet_code))


def packet_view(packet):
    """Return packet string view for debug use"""
    view = io.StringIO()
    view.write("RADIUS Packet '{}' Identifier {}\n".format(
        packet.type_name, packet.identifier
    ))
    view.write("\tAuthenticator: {}\n".format(packet.authenticator.hex()))
    if len(packet.attributes) > 0:
        view.write("Attributes:\n")
    for key, value in packet.attributes:
        view.write("\t{} = {}\n".format(key, value))
    return view.getvalue()


def _decode(packet_class, secret_key, packet_bytes,
           request=None):
    if packet_class not in (AccessRequest, AccessAccept, AccessChallenge, AccessReject,
                            AccountingRequest, AccountingResponse, StatusServer, AccountingStatusServer,
                            DisconnectRequest, DisconnectACK, DisconnectNACK,
                            CoARequest, CoaACK, CoaNACK):
        try:
            packet_class_name = packet_class.__name__
        except AttributeError:
            packet_class_name = str(packet_class)
        raise PacketError("Unknown packet class '{}' for decoding".format(packet_class_name))
    if not isinstance(packet_bytes, bytes):
        raise PacketError("Parameter 'packet_bytes' must be a bytes object")
    if len(packet_bytes) < HEADER_SIZE:
        raise PacketError("Size of packet bytes must be equal of more than {}".format(HEADER_SIZE))
    code, identifier = struct.unpack('!BB', packet_bytes[0:2])
    if code != packet_class.RADIUS_CODE:
        raise PacketError("Error at received packet code, wait code {0}, but receive code {1}".format(
            packet_class.RADIUS_CODE,
            code
        ))
    if issubclass(packet_class, RadiusResponse):
        decoded = packet_class(secret_key, identifier=identifier, request_authenticator=request.authenticator)
    else:
        decoded = packet_class(secret_key, identifier=identifier)
    decoded.from_bytes(packet_bytes)
    return decoded


def decode_request(secret_key, packet_bytes, radius_type = 'auth'):
    if not isinstance(packet_bytes, bytes):
        raise PacketError("`packet_bytes` must be a `bytes` instance")
    packet_class = get_packet_class(packet_bytes, radius_type = radius_type)
    return _decode(packet_class, secret_key, packet_bytes)


def decode_response(secret_key, packet_bytes, request):
    packet_class = get_packet_class(packet_bytes)
    return _decode(packet_class, secret_key, packet_bytes, request=request)