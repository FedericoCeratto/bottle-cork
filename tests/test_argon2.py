
# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2017 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
# Test argon2-based password hashing
#

from pytest import raises
from time import time
import os
import shutil

from cork import Cork, JsonBackend, AuthException
import testutils


testdir = None  # Test directory
aaa = None  # global Cork instance
cookie_name = None  # global variable to track cookie status

tmproot = testutils.pick_temp_directory()


def setup_dir():
    """Setup test directory with valid JSON files"""
    global testdir
    tstamp = "%f" % time()
    testdir = "%s/fl_%s" % (tmproot, tstamp)
    os.mkdir(testdir)
    os.mkdir(testdir + '/views')
    with open("%s/users.json" % testdir, 'w') as f:
        f.write("""{"admin": {"email_addr": null, "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596"}}""")
    with open("%s/roles.json" % testdir, 'w') as f:
        f.write("""{"special": 200, "admin": 100, "user": 50}""")
    with open("%s/register.json" % testdir, 'w') as f:
        f.write("""{}""")
    with open("%s/views/registration_email.tpl" % testdir, 'w') as f:
        f.write("""Username:{{username}} Email:{{email_addr}} Code:{{registration_code}}""")
    with open("%s/views/password_reset_email.tpl" % testdir, 'w') as f:
        f.write("""Username:{{username}} Email:{{email_addr}} Code:{{reset_code}}""")
    print("setup done in %s" % testdir)

def setUp():
    global aaa
    setup_dir()
    aaa = Cork(testdir, smtp_server='localhost', email_sender='test@localhost')

def teardown_dir():
    global cookie_name
    global testdir
    if testdir:
        shutil.rmtree(testdir)
        testdir = None
    cookie_name = None

def tearDown():
    global aaa
    aaa = None
    teardown_dir()


def test_password_hashing_argon2(aaa):
    shash = aaa._hash('user_foo', 'bogus_pwd', algo='argon2')
    assert len(shash) == 248, "hash length should be 248 and is %d" % len(shash)
    assert aaa._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"


def test_password_hashing_argon2_known_hash(aaa):
    salt = b's' * 57
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='argon2')
    assert shash == b'YXNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcwb8JjdgqJy0tZD1EAUVV3p38dw1z3UMPRq6rjIZtnlNUDnJrHQfvhj080HpkfYvK06LqpAZU2GboPNwK4C6OORgYIWuF5nNlc31rcPmIezXU44QA3usHj49cJjrqDtEQPs2uqKELTHgzO2EPSnmwhDfAEpNflfIWzRRBhncSQRV'


def test_password_hashing_argon2_known_hash_2(aaa):
    salt = b'\0' * 57
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='argon2')
    assert shash == b'YQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIQBJq48WAKKXtJ8qIJBvbSMsD/CS7UvkC3nPOcme/f6XMmkHrx/4ExnJtrEHPfpy+wnAd+lofstp5cwsM1mSA+LCUWxkWMIgz7nPDZEGPguft2Tq2xgj2gSzAZPVVKw4Gzdl5hIieh5gJ2SkT4zi6bqIIrO4YVucZWYeFeaYqIN'


def test_password_hashing_argon2_known_hash_3(aaa):
    salt = b'x' * 57
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='argon2')
    assert shash == b'YXh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eKU485dAloUtOxe9zOuxY3g4G+U+Ci+9wGrjhsQPccIw2a+DmP0r+x9I7nQSDERmx+r2xIF3QjPlAjV/AOd/8SNjxK8WzjlOTM9aDbIzYMo6KW10pLswwU2heRCspOy+cEeOzEvzlw1VHZN/iK512mRqfHUHbo7tU1PPoQEsqVTv'


def test_password_hashing_argon2_incorrect_hash_len(aaa):
    salt = b'x' * 31 # Incorrect length
    with raises(AssertionError):
        shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='argon2')


def test_password_hashing_argon2_incorrect_hash_value(aaa):
    shash = aaa._hash('user_foo', 'bogus_pwd', algo='argon2')
    assert len(shash) == 248, "hash length should be 248 and is %d" % len(shash)
    assert aaa._verify_password('user_foo', '####', shash) == False, \
        "Hashing verification should fail"
    assert aaa._verify_password('###', 'bogus_pwd', shash) == False, \
        "Hashing verification should fail"

def test_password_hashing_argon2_collision(aaa):
    salt = b'S' * 57
    hash1 = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='argon2')
    hash2 = aaa._hash('user_foobogus', '_pwd', salt=salt, algo='argon2')
    assert hash1 != hash2, "Hash collision"


