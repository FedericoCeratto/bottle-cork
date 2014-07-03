
# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
# Test scrypt-based password hashing
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


def test_password_hashing_scrypt(aaa):
    shash = aaa._hash('user_foo', 'bogus_pwd', algo='scrypt')
    assert len(shash) == 132, "hash length should be 132 and is %d" % len(shash)
    assert shash.endswith(b'='), "hash should end with '=': %r" % shash
    assert aaa._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"


def test_password_hashing_scrypt_known_hash(aaa):
    salt = b's' * 32
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='scrypt')
    assert shash == b'c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzeLt/2Ta8vJOVqimNpN9G1WWxN1hxlUOJDPgH+0wqPpG20XQHFHLlksDIUo2BL4P8BMLBZj7F+cq6UP6pc304LQ==', repr(shash)


def test_password_hashing_scrypt_known_hash_2(aaa):
    salt = b'\0' * 32
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='scrypt')
    assert shash == b'cwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmu5jQskr2/yX13Yxmc4TYL0MIuSxwo41SVJwn/QueiDdLGkNaEsxlKL37i98YofXxs8xJJAJlC3Xj/9Nx0RNBw=='


def test_password_hashing_scrypt_known_hash_3(aaa):
    salt = b'x' * 32
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='scrypt')
    assert shash == b'c3h4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4yKuT1e8lovFZnaaOctivIvYBPkLoKDXX72kf5/nRuGIgyyhiKxxKE4LVYFKFCeVNPQM5m/+LulQkWhO0aB89lA=='


def test_password_hashing_scrypt_incorrect_hash_len(aaa):
    salt = b'x' * 31 # Incorrect length
    with raises(AssertionError):
        shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='scrypt')


def test_password_hashing_scrypt_incorrect_hash_value(aaa):
    shash = aaa._hash('user_foo', 'bogus_pwd', algo='scrypt')
    assert len(shash) == 132, "hash length should be 132 and is %d" % len(shash)
    assert shash.endswith(b'='), "hash should end with '='"
    assert aaa._verify_password('user_foo', '####', shash) == False, \
        "Hashing verification should fail"
    assert aaa._verify_password('###', 'bogus_pwd', shash) == False, \
        "Hashing verification should fail"



def test_password_hashing_scrypt_collision(aaa):
    salt = b'S' * 32
    hash1 = aaa._hash('user_foo', 'bogus_pwd', salt=salt, algo='scrypt')
    hash2 = aaa._hash('user_foobogus', '_pwd', salt=salt, algo='scrypt')
    assert hash1 != hash2, "Hash collision"


