import os
import random
import statistics
from aioradius.protocol.crypt import UserPasswordCrypt

__author__ = 'arusinov'


def test_encrypt():
    min_length = 3
    max_length = 128
    length = random.randint(min_length, max_length)
    password = os.urandom(length).rstrip(b'\x00')
    secret = '1234567890'
    authenticator = os.urandom(16)
    crypted_ = UserPasswordCrypt.encrypt(password, secret, authenticator)


def test_encrypt_decrypt():
    min_length = 3
    max_length = 128
    length = random.randint(min_length, max_length)
    password = os.urandom(length).rstrip(b'\x00')
    secret = '1234567890'
    authenticator = os.urandom(16)
    crypted_ = UserPasswordCrypt.encrypt(password, secret, authenticator)
    decrypted_ = UserPasswordCrypt.decrypt(crypted_, secret, authenticator)
    if isinstance(decrypted_, str):
        decrypted_ = bytes(decrypted_, encoding='utf-8')
    assert (password == decrypted_), "Password != Decrypted\n{}\n{}".format(password, decrypted_)

if __name__ == '__main__':
    from timeit import Timer
    t = Timer(lambda: test_encrypt_decrypt())
    times = t.repeat(repeat=1000, number=1)
    print("Max: {}".format(max(*times)))
    print("Min: {}".format(min(*times)))
    print("Avg: {}".format(statistics.mean(times)))
