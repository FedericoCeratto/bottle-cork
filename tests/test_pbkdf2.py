# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2017 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
# Test PBKDF2-based password hashing
#

from base64 import b64encode
from pytest import fixture, raises
from time import time
import os
import shutil

from cork import Cork, JsonBackend, AuthException
import testutils

HASHLEN = 32


@fixture
def aaa(mytmpdir):
    aaa = Cork(
        mytmpdir,
        smtp_server="localhost",
        email_sender="test@localhost",
        preferred_hashing_algorithm="PBKDF2sha1",
        pbkdf2_iterations=100000,
    )
    return aaa


def test_password_hashing_PBKDF2(aaa):
    assert aaa.preferred_hashing_algorithm == "PBKDF2sha1"
    shash = aaa._hash(u"user_foo", u"bogus_pwd")
    assert isinstance(shash, bytes)
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith(b"="), "hash should end with '='"
    assert (
        aaa._verify_password("user_foo", "bogus_pwd", shash) == True
    ), "Hashing verification should succeed"


def test_hashlib_pbk():
    # Hashlib works under py2 and py3 producing the same output.
    # With iterations = 10 and dklen = 32 the output is also consistent with
    # beaker under py2 as in the previous versions of Cork
    import hashlib

    cleartext = b"hello"
    salt = b"hi"
    h = hashlib.pbkdf2_hmac("sha1", cleartext, salt, 10, dklen=HASHLEN)
    assert b64encode(h) == b"QTH8vcCFLLqLhxCTnkz6sq+Un3B4RQgWjMPpRC9hfEY="


def test_password_hashing_PBKDF2_known_hash(aaa):
    assert aaa.preferred_hashing_algorithm == "PBKDF2sha1"
    salt = b"s" * HASHLEN
    shash = aaa._hash(u"user_foo", u"bogus_pwd", salt=salt)
    assert (
        shash
        == b"cHNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nz9XaEVyNjrXBEKjKHSVWKcjFEaNAAm66rvwCIjDZPru0="
    )


def test_password_hashing_PBKDF2_known_hash_2(aaa):
    assert aaa.preferred_hashing_algorithm == "PBKDF2sha1"
    salt = b"\0" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt)
    assert (
        shash
        == b"cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiIL4LIVJ9DCGDQAsAQG7JYvUjm68ZKQqV/TABeWrYzs="
    )


def test_password_hashing_PBKDF2_known_hash_3(aaa):
    assert aaa.preferred_hashing_algorithm == "PBKDF2sha1"
    salt = b"x" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt)
    assert (
        shash
        == b"cHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4uaJQV+rua/emhov7hJ819Sdy6MNGiPfL+e6DbPAeQQU="
    )


def test_password_hashing_PBKDF2_incorrect_hash_len(aaa):
    salt = b"x" * 31  # Incorrect length
    with raises(AssertionError):
        shash = aaa._hash("user_foo", "bogus_pwd", salt=salt)


def test_password_hashing_PBKDF2_incorrect_hash_value(aaa):
    shash = aaa._hash("user_foo", "bogus_pwd")
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith(b"="), "hash should end with '='"
    assert (
        aaa._verify_password(u"user_foo", u"####", shash) == False
    ), "Hashing verification should fail"
    assert (
        aaa._verify_password("###", "bogus_pwd", shash) == False
    ), "Hashing verification should fail"


def test_password_hashing_PBKDF2_collision(aaa):
    salt = b"S" * HASHLEN
    hash1 = aaa._hash("user_foo", u"bogus_pwd", salt=salt)
    hash2 = aaa._hash("user_foobogus", u"_pwd", salt=salt)
    assert hash1 != hash2, "Hash collision"
