"""
aioradius.protocol.crypt

This module contain classes for encrypt/decrypt some RADIUS attributes that use encryption
"""

import hashlib
md5_constructor = hashlib.md5

from aioradius.protocol import PROTOCOL_ENCODING

__author__ = 'arusinov'

USER_PASSWORD_CRYPT_TYPE = 1
TUNNEL_PASSWORD_CRYPT_TYPE = 2

ALLOWED_CRYPT_TYPES = (USER_PASSWORD_CRYPT_TYPE, )


def cast_to_bytes(value):
    """ Return bytes from different types"""
    if not isinstance(value, (str, bytes, bytearray)):
        value = str(value)
    if isinstance(value, str):
        value = bytes(value, encoding=PROTOCOL_ENCODING)
    elif isinstance(value, bytearray):
        value = bytes(value)
    return value


def xor_1(bytes_first, bytes_second):
    """ XOR implementation by using cast to int """
    int_first = int.from_bytes(bytes_first, 'big')
    int_second = int.from_bytes(bytes_second, 'big')
    int_xored = int_first ^ int_second
    return int_xored.to_bytes(len(bytes_first), 'big')


def xor_2(bytes_first, bytes_second):
    """ XOR implementation with XORing by bytes pair """
    return bytes(a ^ b for a, b in zip(bytes_first, bytes_second))

xor = xor_1


class EncryptionError(Exception): pass


class UserPasswordCrypt(object):
    """
    Class `UserPasswordCrypt` implement crypt method for User-Password RADIUS attribute
    See RFC2865 sec 5.2 for details
    Usage:
        crypted = UserPasswordCrypt.encrypt(cleartext_password, secret, authenticator)
        decrypted = UserPasswordCrypt.decrypt(crypted_password, secret, authenticator)
    """
    @staticmethod
    def encrypt(value, secret_key, authenticator):
        """
        Return encrypted value of password

        Params:
            value - cleartext password for encrypt
            secret_key - shared secret for Server and NAS
            authenticator - value of authenticator from request packet
        """
        value = cast_to_bytes(value)
        secret_key = cast_to_bytes(secret_key)
        authenticator = cast_to_bytes(authenticator)

        if len(authenticator) != 16:
            raise EncryptionError("Length of authenticator must be 16 bytes")

        result = b''
        current_chunk_result = authenticator
        idx = 0

        while idx < len(value):
            value_chunk = value[idx:idx+16]
            if len(value_chunk) < 16:
                value_chunk += bytes(16 - len(value_chunk))

            hash_func = md5_constructor()
            hash_func.update(secret_key)
            hash_func.update(current_chunk_result)

            hash_result = hash_func.digest()
            xor_result = xor(value_chunk, hash_result)

            result += xor_result
            current_chunk_result = xor_result
            idx += 16
        return result

    @staticmethod
    def decrypt(value, secret_key, authenticator):
        """
        Return decrypted value of password

        Params:
            value - encrypted password for decrypt
            secret_key - shared secret for Server and NAS
            authenticator - value of authenticator from request packet
        """
        value = cast_to_bytes(value)
        secret_key = cast_to_bytes(secret_key)
        authenticator = cast_to_bytes(authenticator)

        if len(authenticator) != 16:
            raise EncryptionError("The authenticator size must be 16 bytes")
        if len(value) % 16 != 0:
            raise EncryptionError("The encrypted password size must be a multiple of 16")

        result = b''
        current_chunk_result = authenticator
        idx = 0

        while idx < len(value) - 15:
            value_chunk = value[idx:idx+16]
            hash_func = md5_constructor()
            hash_func.update(secret_key)
            hash_func.update(current_chunk_result)
            hash_result = hash_func.digest()

            xor_result = xor(value_chunk, hash_result)
            result += xor_result
            current_chunk_result = value_chunk

            idx += 16

        result = result.rstrip(b'\x00')
        try:
            return result.decode(encoding=PROTOCOL_ENCODING)
        except UnicodeDecodeError:
            return result