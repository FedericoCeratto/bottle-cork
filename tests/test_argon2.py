# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2017 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
# Test argon2-based password hashing
#

from pytest import fixture, raises
from time import time
import os
import shutil

from cork import Cork, JsonBackend, AuthException
import testutils

HASHLEN = 57


@fixture
def aaa(mytmpdir):
    aaa = Cork(
        mytmpdir,
        smtp_server="localhost",
        email_sender="test@localhost",
        preferred_hashing_algorithm="argon2",
    )
    return aaa


def test_password_hashing_argon2(aaa):
    shash = aaa._hash("user_foo", "bogus_pwd", algo="argon2")
    assert len(shash) == 248, "hash length should be 248 and is %d" % len(shash)
    assert (
        aaa._verify_password("user_foo", "bogus_pwd", shash) == True
    ), "Hashing verification should succeed"


def test_password_hashing_argon2_known_hash(aaa):
    salt = b"s" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="argon2")
    assert (
        shash
        == b"YXNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcwb8JjdgqJy0tZD1EAUVV3p38dw1z3UMPRq6rjIZtnlNUDnJrHQfvhj080HpkfYvK06LqpAZU2GboPNwK4C6OORgYIWuF5nNlc31rcPmIezXU44QA3usHj49cJjrqDtEQPs2uqKELTHgzO2EPSnmwhDfAEpNflfIWzRRBhncSQRV"
    )


def test_password_hashing_argon2_known_hash_2(aaa):
    salt = b"\0" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="argon2")
    assert (
        shash
        == b"YQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIQBJq48WAKKXtJ8qIJBvbSMsD/CS7UvkC3nPOcme/f6XMmkHrx/4ExnJtrEHPfpy+wnAd+lofstp5cwsM1mSA+LCUWxkWMIgz7nPDZEGPguft2Tq2xgj2gSzAZPVVKw4Gzdl5hIieh5gJ2SkT4zi6bqIIrO4YVucZWYeFeaYqIN"
    )


def test_password_hashing_argon2_known_hash_3(aaa):
    salt = b"x" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="argon2")
    assert (
        shash
        == b"YXh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eKU485dAloUtOxe9zOuxY3g4G+U+Ci+9wGrjhsQPccIw2a+DmP0r+x9I7nQSDERmx+r2xIF3QjPlAjV/AOd/8SNjxK8WzjlOTM9aDbIzYMo6KW10pLswwU2heRCspOy+cEeOzEvzlw1VHZN/iK512mRqfHUHbo7tU1PPoQEsqVTv"
    )


def test_password_hashing_argon2_incorrect_hash_len(aaa):
    salt = b"x" * 31  # Incorrect length
    with raises(AssertionError):
        shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="argon2")


def test_password_hashing_argon2_incorrect_hash_value(aaa):
    shash = aaa._hash("user_foo", "bogus_pwd", algo="argon2")
    assert len(shash) == 248, "hash length should be 248 and is %d" % len(shash)
    assert (
        aaa._verify_password("user_foo", "####", shash) == False
    ), "Hashing verification should fail"
    assert (
        aaa._verify_password("###", "bogus_pwd", shash) == False
    ), "Hashing verification should fail"


def test_password_hashing_argon2_collision(aaa):
    salt = b"S" * HASHLEN
    hash1 = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="argon2")
    hash2 = aaa._hash("user_foobogus", "_pwd", salt=salt, algo="argon2")
    assert hash1 != hash2, "Hash collision"
