import os
import random
import unittest
from aioradius.protocol.attributes import AttributeType
from aioradius.protocol.crypt import UserPasswordCrypt, USER_PASSWORD_CRYPT_TYPE, cast_to_bytes

__author__ = 'arusinov'


class CryptTestCase(unittest.TestCase):

    def test_develop(self):
        min_length = 3
        max_length = 128
        length = random.randint(min_length, max_length)
        password = os.urandom(length)
        secret = '1234567890'
        authenticator = os.urandom(16)
        crypted_ = UserPasswordCrypt.encrypt(password, secret, authenticator)
        decrypted_ = UserPasswordCrypt.decrypt(crypted_, secret, authenticator)
        self.assertEqual(decrypted_, password)

    def test_cast_to_bytes(self):
        self.assertTrue(isinstance(cast_to_bytes(b'bytes object'), bytes))
        self.assertTrue(isinstance(cast_to_bytes(bytearray(b'bytes object')), bytes))
        self.assertTrue(isinstance(cast_to_bytes('string object'), bytes))
        self.assertTrue(isinstance(cast_to_bytes(12345), bytes))
        self.assertTrue(isinstance(cast_to_bytes(None), bytes))

    def test_encode_decode_attribute_with_encrypt(self):

        secret_key = '1234567890'
        authenticator = os.urandom(16)

        tests = (
            ('User-Name', 'test'),  # Testing encode/decode simple string attribute
            # Testing encode/decode User-Password attribute
            ('User-Password', 'blafoo_vary_vary_vary_vary_vary_vary_vary_vary_vary_vary_vary_vary_vary_vary_long'),
        )
        for ATTRIBUTE, VALUE in tests:
            attribute_for_encode = AttributeType.get_attribute_for_encode(ATTRIBUTE)
            if attribute_for_encode.encrypt == USER_PASSWORD_CRYPT_TYPE:
                value_ = UserPasswordCrypt.encrypt(VALUE, secret_key, authenticator)
            else:
                value_ = VALUE
            encoded_ = attribute_for_encode.encode(value_)
            attribute_for_decode = AttributeType.get_attribute_for_decode(encoded_)
            decoded_name, decoded_value = attribute_for_decode.decode(encoded_)
            if attribute_for_decode.encrypt == USER_PASSWORD_CRYPT_TYPE:
                decoded_value = UserPasswordCrypt.decrypt(decoded_value, secret_key, authenticator)

            self.assertEqual(attribute_for_encode, attribute_for_decode)
            self.assertEqual(decoded_name, ATTRIBUTE)
            self.assertEqual(decoded_value, VALUE)