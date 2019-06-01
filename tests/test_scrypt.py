# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
# Test scrypt-based password hashing
#

from pytest import fixture, raises

from cork import Cork

HASHLEN = 32


@fixture
def aaa(mytmpdir):
    aaa = Cork(
        mytmpdir,
        smtp_server="localhost",
        email_sender="test@localhost",
        preferred_hashing_algorithm="scrypt",
    )
    return aaa


def test_password_hashing_scrypt(aaa):
    shash = aaa._hash("user_foo", "bogus_pwd", algo="scrypt")
    assert len(shash) == 132, "hash length should be 132 and is %d" % len(shash)
    assert shash.endswith(b"="), "hash should end with '=': %r" % shash
    assert (
        aaa._verify_password("user_foo", "bogus_pwd", shash) == True
    ), "Hashing verification should succeed"


def test_password_hashing_scrypt_known_hash(aaa):
    salt = b"s" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="scrypt")
    assert (
        shash
        == b"c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzeLt/2Ta8vJOVqimNpN9G1WWxN1hxlUOJDPgH+0wqPpG20XQHFHLlksDIUo2BL4P8BMLBZj7F+cq6UP6pc304LQ=="
    ), repr(shash)


def test_password_hashing_scrypt_known_hash_2(aaa):
    salt = b"\0" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="scrypt")
    assert (
        shash
        == b"cwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmu5jQskr2/yX13Yxmc4TYL0MIuSxwo41SVJwn/QueiDdLGkNaEsxlKL37i98YofXxs8xJJAJlC3Xj/9Nx0RNBw=="
    )


def test_password_hashing_scrypt_known_hash_3(aaa):
    salt = b"x" * HASHLEN
    shash = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="scrypt")
    assert (
        shash
        == b"c3h4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4yKuT1e8lovFZnaaOctivIvYBPkLoKDXX72kf5/nRuGIgyyhiKxxKE4LVYFKFCeVNPQM5m/+LulQkWhO0aB89lA=="
    )


def test_password_hashing_scrypt_incorrect_hash_len(aaa):
    salt = b"x" * 31  # Incorrect length
    with raises(AssertionError):
        aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="scrypt")


def test_password_hashing_scrypt_incorrect_hash_value(aaa):
    shash = aaa._hash("user_foo", "bogus_pwd", algo="scrypt")
    assert len(shash) == 132, "hash length should be 132 and is %d" % len(shash)
    assert shash.endswith(b"="), "hash should end with '='"
    assert (
        aaa._verify_password("user_foo", "####", shash) == False
    ), "Hashing verification should fail"
    assert (
        aaa._verify_password("###", "bogus_pwd", shash) == False
    ), "Hashing verification should fail"


def test_password_hashing_scrypt_collision(aaa):
    salt = b"S" * HASHLEN
    hash1 = aaa._hash("user_foo", "bogus_pwd", salt=salt, algo="scrypt")
    hash2 = aaa._hash("user_foobogus", "_pwd", salt=salt, algo="scrypt")
    assert hash1 != hash2, "Hash collision"
