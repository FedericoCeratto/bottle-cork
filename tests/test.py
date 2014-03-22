# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
#

from base64 import b64encode, b64decode
from nose import SkipTest
from nose.tools import assert_raises, raises, with_setup
from time import time
import mock
import os
import shutil

from cork import Cork, JsonBackend, AAAException, AuthException
from cork import Mailer
from cork.base_backend import BackendIOException
import testutils

testdir = None  # Test directory
aaa = None  # global Cork instance
cookie_name = None  # global variable to track cookie status

tmproot = testutils.pick_temp_directory()


class RoAttrDict(dict):
    """Read-only attribute-accessed dictionary.
    Used to mock beaker's session objects
    """
    def __getattr__(self, name):
        return self[name]


class MockedAdminCork(Cork):
    """Mocked module where the current user is always 'admin'"""
    @property
    def _beaker_session(self):
        return RoAttrDict(username='admin')

    def _setup_cookie(self, username):
        global cookie_name
        cookie_name = username


class MockedUnauthenticatedCork(Cork):
    """Mocked module where the current user not set"""
    @property
    def _beaker_session(self):
        return RoAttrDict()

    def _setup_cookie(self, username):
        global cookie_name
        cookie_name = username


def setup_empty_dir():
    """Setup test directory without JSON files"""
    global testdir
    tstamp = "%f" % time()
    testdir = "%s/fl_%s" % (tmproot, tstamp)
    os.mkdir(testdir)
    os.mkdir(testdir + '/view')
    print("setup done in %s" % testdir)


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


def setup_mockedadmin():
    """Setup test directory and a MockedAdminCork instance"""
    global aaa
    global cookie_name
    setup_dir()
    aaa = MockedAdminCork(testdir, smtp_server='localhost', email_sender='test@localhost')
    cookie_name = None


def setup_mocked_unauthenticated():
    """Setup test directory and a MockedAdminCork instance"""
    global aaa
    global cookie_name
    setup_dir()
    aaa = MockedUnauthenticatedCork(testdir)
    cookie_name = None


def teardown_dir():
    global cookie_name
    global testdir
    if testdir:
        shutil.rmtree(testdir)
        testdir = None
    cookie_name = None


@with_setup(setup_dir, teardown_dir)
def test_init():
    Cork(testdir)


@with_setup(setup_dir, teardown_dir)
def test_initialize_storage():
    jb = JsonBackend(testdir, initialize=True)
    Cork(backend=jb)
    with open("%s/users.json" % testdir) as f:
        assert f.readlines() == ['{}']
    with open("%s/roles.json" % testdir) as f:
        assert f.readlines() == ['{}']
    with open("%s/register.json" % testdir) as f:
        assert f.readlines() == ['{}']
    with open("%s/views/registration_email.tpl" % testdir) as f:
        assert f.readlines() == [
            'Username:{{username}} Email:{{email_addr}} Code:{{registration_code}}']
    with open("%s/views/password_reset_email.tpl" % testdir) as f:
        assert f.readlines() == [
            'Username:{{username}} Email:{{email_addr}} Code:{{reset_code}}']


@raises(BackendIOException)
@with_setup(setup_dir, teardown_dir)
def test_unable_to_save():
    bogus_dir = '/___inexisting_directory___'
    Cork(bogus_dir, initialize=True)


@with_setup(setup_mockedadmin, teardown_dir)
def test_mockedadmin():
    assert len(aaa._store.users) == 1, repr(aaa._store.users)
    assert 'admin' in aaa._store.users, repr(aaa._store.users)

@raises(BackendIOException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_loadjson_missing_file():
    aaa._store._loadjson('nonexistent_file', {})

@raises(BackendIOException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_loadjson_broken_file():
    with open(testdir + '/broken_file.json', 'w') as f:
        f.write('-----')
    aaa._store._loadjson('broken_file', {})


@with_setup(setup_mockedadmin, teardown_dir)
def test_loadjson_unchanged():
    # By running _refresh with unchanged files the files should not be reloaded
    mtimes = aaa._store._mtimes
    aaa._store._refresh()
    # The test simply ensures that no mtimes have been updated
    assert mtimes == aaa._store._mtimes


# Test PBKDF2-based password hashing

@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2():
    shash = aaa._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith('='), "hash should end with '='"
    assert aaa._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"

@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2_known_hash():
    salt = 's' * 32
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt)
    assert shash == 'cHNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzax44AxQgK6uD9q1YWxLos1ispCe1Z7T7pOFK1PwdWEs='

@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2_known_hash_2():
    salt = '\0' * 32
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt)
    assert shash == 'cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/8Uh4pyEOHoRz4j0lDzAmqb7Dvmo8GpeXwiKTDsuYFw='

@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2_known_hash_3():
    salt = 'x' * 32
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt)
    assert shash == 'cHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4MEaIU5Op97lmvwX5NpVSTBP8jg8OlrN7c2K8K8tnNks='

@raises(AssertionError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2_incorrect_hash_len():
    salt = 'x' * 31 # Incorrect length
    shash = aaa._hash('user_foo', 'bogus_pwd', salt=salt)

@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2_incorrect_hash_value():
    shash = aaa._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith('='), "hash should end with '='"
    assert aaa._verify_password('user_foo', '####', shash) == False, \
        "Hashing verification should fail"
    assert aaa._verify_password('###', 'bogus_pwd', shash) == False, \
        "Hashing verification should fail"

@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_PBKDF2_collision():
    salt = 'S' * 32
    hash1 = aaa._hash('user_foo', 'bogus_pwd', salt=salt)
    hash2 = aaa._hash('user_foobogus', '_pwd', salt=salt)
    assert hash1 != hash2, "Hash collision"


# Test password hashing for inexistent algorithms

@raises(RuntimeError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_bogus_algo():
    aaa._hash('user_foo', 'bogus_pwd', algo='bogus_algo')

@raises(RuntimeError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_password_hashing_bogus_algo_during_verify():
    # Incorrect hash type (starts with "X")
    shash = b64encode('X' + 'bogusstring')
    aaa._verify_password('user_foo', 'bogus_pwd', shash)

# End of password hashing tests


@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_create_role():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.create_role, 'user', 33)


@with_setup(setup_mockedadmin, teardown_dir)
def test_create_existing_role():
    assert_raises(AAAException, aaa.create_role, 'user', 33)


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_create_role_with_incorrect_level():
    aaa.create_role('new_user', 'not_a_number')


@with_setup(setup_mockedadmin, teardown_dir)
def test_create_role():
    assert len(aaa._store.roles) == 3, repr(aaa._store.roles)
    aaa.create_role('user33', 33)
    assert len(aaa._store.roles) == 4, repr(aaa._store.roles)
    fname = "%s/%s.json" % (aaa._store._directory, aaa._store._roles_fname)
    with open(fname) as f:
        data = f.read()
        assert 'user33' in data, repr(data)

@SkipTest
@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_create_empty_role():
    aaa.create_role('', 42)

@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_delete_role():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.delete_role, 'user')


@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_nonexistent_role():
    assert_raises(AAAException, aaa.delete_role, 'user123')


@with_setup(setup_mockedadmin, teardown_dir)
def test_create_delete_role():
    assert len(aaa._store.roles) == 3, repr(aaa._store.roles)
    aaa.create_role('user33', 33)
    assert len(aaa._store.roles) == 4, repr(aaa._store.roles)
    fname = "%s/%s.json" % (aaa._store._directory, aaa._store._roles_fname)
    with open(fname) as f:
        data = f.read()
        assert 'user33' in data, repr(data)
    assert aaa._store.roles['user33'] == 33
    aaa.delete_role('user33')
    assert len(aaa._store.roles) == 3, repr(aaa._store.roles)


@with_setup(setup_mockedadmin, teardown_dir)
def test_list_roles():
    roles = list(aaa.list_roles())
    assert len(roles) == 3, "Incorrect. Users are: %s" % repr(aaa._store.roles)


@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_create_user():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.create_user, 'phil', 'user', 'hunter123')

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_existing_user():
    assert_raises(AAAException, aaa.create_user, 'admin', 'admin', 'bogus')


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_create_user_with_wrong_role():
    aaa.create_user('admin2', 'nonexistent_role', 'bogus')


@with_setup(setup_mockedadmin, teardown_dir)
def test_create_user():
    assert len(aaa._store.users) == 1, repr(aaa._store.users)
    aaa.create_user('phil', 'user', 'user')
    assert len(aaa._store.users) == 2, repr(aaa._store.users)
    fname = "%s/%s.json" % (aaa._store._directory, aaa._store._users_fname)
    with open(fname) as f:
        data = f.read()
        assert 'phil' in data, repr(data)


@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_delete_user():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.delete_user, 'phil')


@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_nonexistent_user():
    assert_raises(AAAException, aaa.delete_user, 'not_an_user')


@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_user():
    assert len(aaa._store.users) == 1, repr(aaa._store.users)
    aaa.delete_user('admin')
    assert len(aaa._store.users) == 0, repr(aaa._store.users)
    fname = "%s/%s.json" % (aaa._store._directory, aaa._store._users_fname)
    with open(fname) as f:
        data = f.read()
        assert 'admin' not in data, "'admin' must not be in %s" % repr(data)


@with_setup(setup_mockedadmin, teardown_dir)
def test_list_users():
    users = list(aaa.list_users())
    assert len(users) == 1, "Incorrect. Users are: %s" % repr(aaa._store.users)


@with_setup(setup_mockedadmin, teardown_dir)
def test_failing_login():
    login = aaa.login('phil', 'hunter123')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None


@with_setup(setup_mockedadmin, teardown_dir)
def test_login_nonexistent_user_empty_password():
    login = aaa.login('IAmNotHome', '')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None


@with_setup(setup_mockedadmin, teardown_dir)
def test_login_existing_user_empty_password():
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._store.users
    assert aaa._store.users['phil']['role'] == 'user'
    login = aaa.login('phil', '')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None


@with_setup(setup_mockedadmin, teardown_dir)
def test_create_and_validate_user():
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._store.users
    assert aaa._store.users['phil']['role'] == 'user'
    login = aaa.login('phil', 'hunter123')
    assert login == True, "Login must succeed"
    global cookie_name
    assert cookie_name == 'phil'


@with_setup(setup_mockedadmin, teardown_dir)
def test_require_failing_username():
    # The user exists, but I'm 'admin'
    aaa.create_user('phil', 'user', 'hunter123')
    assert_raises(AuthException, aaa.require, username='phil')


@with_setup(setup_mockedadmin, teardown_dir)
def test_require_nonexistent_username():
    assert_raises(AAAException, aaa.require, username='no_such_user')


@with_setup(setup_mockedadmin, teardown_dir)
def test_require_failing_role_fixed():
    assert_raises(AuthException, aaa.require, role='user', fixed_role=True)


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_require_missing_parameter():
    aaa.require(fixed_role=True)


@with_setup(setup_mockedadmin, teardown_dir)
def test_require_nonexistent_role():
    assert_raises(AAAException, aaa.require, role='clown')


@with_setup(setup_mockedadmin, teardown_dir)
def test_require_failing_role():
    # Requesting level >= 100
    assert_raises(AuthException, aaa.require, role='special')


@with_setup(setup_mockedadmin, teardown_dir)
def test_successful_require_role():
    aaa.require(username='admin')
    aaa.require(username='admin', role='admin')
    aaa.require(username='admin', role='admin', fixed_role=True)
    aaa.require(username='admin', role='user')


@with_setup(setup_mockedadmin, teardown_dir)
def test_authenticated_is_not__anonymous():
    assert not aaa.user_is_anonymous


@with_setup(setup_mockedadmin, teardown_dir)
def test_update_nonexistent_role():
    assert_raises(AAAException, aaa.current_user.update, role='clown')


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_update_nonexistent_user():
    aaa._store.users.pop('admin')
    aaa.current_user.update(role='user')


@with_setup(setup_mockedadmin, teardown_dir)
def test_update_role():
    aaa.current_user.update(role='user')
    assert aaa._store.users['admin']['role'] == 'user'


@with_setup(setup_mockedadmin, teardown_dir)
def test_update_pwd():
    aaa.current_user.update(pwd='meow')


@with_setup(setup_mockedadmin, teardown_dir)
def test_update_email():
    aaa.current_user.update(email_addr='foo')
    assert aaa._store.users['admin']['email_addr'] == 'foo'


@raises(AAAException)
@with_setup(setup_mocked_unauthenticated, teardown_dir)
def test_get_current_user_unauth():
    aaa.current_user['username']


@with_setup(setup_mocked_unauthenticated, teardown_dir)
def test_unauth_is_anonymous():
    assert aaa.user_is_anonymous


@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_get_current_user_nonexistent():
    # The current user 'admin' is not in the user table
    aaa._store.users.pop('admin')
    aaa.current_user


@with_setup(setup_mockedadmin, teardown_dir)
def test_get_nonexistent_user():
    assert aaa.user('nonexistent_user') is None


@with_setup(setup_mockedadmin, teardown_dir)
def test_get_user_description_field():
    admin = aaa.user('admin')
    for field in ['description', 'email_addr']:
        assert field in admin.__dict__


@with_setup(setup_mockedadmin, teardown_dir)
def test_register_no_user():
    assert_raises(AssertionError, aaa.register, None, 'pwd', 'a@a.a')


@with_setup(setup_mockedadmin, teardown_dir)
def test_register_no_pwd():
    assert_raises(AssertionError, aaa.register, 'foo', None, 'a@a.a')


@with_setup(setup_mockedadmin, teardown_dir)
def test_register_no_email():
    assert_raises(AssertionError, aaa.register, 'foo', 'pwd', None)


@with_setup(setup_mockedadmin, teardown_dir)
def test_register_already_existing():
    assert_raises(AAAException, aaa.register, 'admin', 'pwd', 'a@a.a')


@with_setup(setup_mockedadmin, teardown_dir)
def test_register_no_role():
    assert_raises(AAAException, aaa.register, 'foo', 'pwd', 'a@a.a', role='clown')


@with_setup(setup_mockedadmin, teardown_dir)
def test_register_role_too_high():
    assert_raises(AAAException, aaa.register, 'foo', 'pwd', 'a@a.a', role='admin')


# Patch the mailer _send() method to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_register(mocked):
    old_dir = os.getcwd()
    os.chdir(testdir)
    aaa.register('foo', 'pwd', 'a@a.a')
    os.chdir(old_dir)
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)


@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_1():
    c = aaa.mailer._parse_smtp_url('')
    assert c['proto'] == 'smtp'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == ''
    assert c['port'] == 25


@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_2():
    c = aaa.mailer._parse_smtp_url('starttls://foo')
    assert c['proto'] == 'starttls'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == 'foo'
    assert c['port'] == 25

@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_3():
    c = aaa.mailer._parse_smtp_url('foo:443')
    assert c['proto'] == 'smtp'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443

@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_4():
    c = aaa.mailer._parse_smtp_url('ssl://user:pass@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'user'
    assert c['pass'] == 'pass'
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443

@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_5():
    c = aaa.mailer._parse_smtp_url('smtp://smtp.magnet.ie')
    assert c['proto'] == 'smtp'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == 'smtp.magnet.ie'
    assert c['port'] == 25


@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_email_as_username_no_password():
    # the username contains an at sign '@'
    c = aaa.mailer._parse_smtp_url('ssl://us.er@somewhere.net@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'us.er@somewhere.net', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == None
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_email_as_username():
    # the username contains an at sign '@'
    c = aaa.mailer._parse_smtp_url('ssl://us.er@somewhere.net:pass@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'us.er@somewhere.net', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == 'pass'
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_at_sign_in_password():
    # the password contains at signs '@'
    c = aaa.mailer._parse_smtp_url('ssl://username:pass@w@rd@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'username', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == 'pass@w@rd', \
        "Password is incorrectly parsed as '%s'" % c['pass']
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_email_as_username_2():
    # both the username and the password contains an at sign '@'
    c = aaa.mailer._parse_smtp_url('ssl://us.er@somewhere.net:pass@word@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'us.er@somewhere.net', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == 'pass@word', \
        "Password is incorrectly parsed as '%s'" % c['pass']
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443

@raises(RuntimeError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_incorrect_URL_port():
    c = aaa.mailer._parse_smtp_url(':99999')

@raises(RuntimeError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_incorrect_URL_port_len():
    c = aaa.mailer._parse_smtp_url(':123456')

@raises(RuntimeError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_incorrect_URL_len():
    c = aaa.mailer._parse_smtp_url('a' * 256)

@raises(RuntimeError)
@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_incorrect_URL_syntax():
    c = aaa.mailer._parse_smtp_url('::')

@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_IPv4():
    c = aaa.mailer._parse_smtp_url('127.0.0.1')
    assert c['fqdn'] == '127.0.0.1'

@with_setup(setup_mockedadmin, teardown_dir)
def test_smtp_url_parsing_IPv6():
    c = aaa.mailer._parse_smtp_url('[2001:0:0123:4567:89ab:cdef]')
    assert c['fqdn'] == '[2001:0:0123:4567:89ab:cdef]'


# Patch the SMTP class to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch('cork.cork.SMTP')
def test_send_email_SMTP(SMTP):
    SMTP.return_value = msession = mock.Mock() # session instance

    aaa.mailer.send_email('address', ' sbj', 'text')
    aaa.mailer.join()

    SMTP.assert_called_once_with('localhost', 25)
    assert msession.sendmail.call_count == 1
    assert msession.quit.call_count == 1
    assert len(msession.method_calls) == 2

# Patch the SMTP_SSL class to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch('cork.cork.SMTP_SSL')
def test_send_email_SMTP_SSL(SMTP_SSL):
    SMTP_SSL.return_value = msession = mock.Mock() # session instance

    aaa.mailer._conf['proto'] = 'ssl'
    aaa.mailer.send_email('address', ' sbj', 'text')
    aaa.mailer.join()

    SMTP_SSL.assert_called_once_with('localhost', 25)
    assert msession.sendmail.call_count == 1
    assert msession.quit.call_count == 1
    assert len(msession.method_calls) == 2

# Patch the SMTP_SSL class to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch('cork.cork.SMTP_SSL')
def test_send_email_SMTP_SSL_with_login(SMTP_SSL):
    SMTP_SSL.return_value = msession = mock.Mock() # session instance

    aaa.mailer._conf['proto'] = 'ssl'
    aaa.mailer._conf['user'] = 'username'
    aaa.mailer.send_email('address', ' sbj', 'text')
    aaa.mailer.join()

    SMTP_SSL.assert_called_once_with('localhost', 25)
    assert msession.login.call_count == 1
    assert msession.sendmail.call_count == 1
    assert msession.quit.call_count == 1
    assert len(msession.method_calls) == 3

# Patch the SMTP_SSL class to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch('cork.cork.SMTP')
def test_send_email_SMTP_STARTTLS(SMTP):
    SMTP.return_value = msession = mock.Mock() # session instance

    aaa.mailer._conf['proto'] = 'starttls'
    aaa.mailer.send_email('address', ' sbj', 'text')
    aaa.mailer.join()

    SMTP.assert_called_once_with('localhost', 25)
    assert msession.ehlo.call_count == 2
    assert msession.starttls.call_count == 1
    assert msession.sendmail.call_count == 1
    assert msession.quit.call_count == 1
    assert len(msession.method_calls) == 5


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_do_not_send_email():
    aaa.mailer._conf['fqdn'] = None  # disable email delivery
    aaa.mailer.send_email('address', 'sbj', 'text')
    aaa.mailer.join()


@with_setup(setup_mockedadmin, teardown_dir)
def test_validate_registration_no_code():
    assert_raises(AAAException, aaa.validate_registration, 'not_a_valid_code')


# Patch the mailer _send() method to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_validate_registration(mocked):
    # create registration
    old_dir = os.getcwd()
    os.chdir(testdir)
    aaa.register('user_foo', 'pwd', 'a@a.a')
    os.chdir(old_dir)
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)
    # get the registration code, and run validate_registration
    code = aaa._store.pending_registrations.keys()[0]
    user_data = aaa._store.pending_registrations[code]
    aaa.validate_registration(code)
    assert user_data['username'] in aaa._store.users, "Account should have been added"
    # test login
    login = aaa.login('user_foo', 'pwd')
    assert login == True, "Login must succeed"
    # The registration should have been removed
    assert len(aaa._store.pending_registrations) == 0, repr(aaa._store.pending_registrations)


# Patch the mailer _send() method to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_purge_expired_registration(mocked):
    old_dir = os.getcwd()
    os.chdir(testdir)
    aaa.register('foo', 'pwd', 'a@a.a')
    os.chdir(old_dir)
    assert len(aaa._store.pending_registrations) == 1, "The registration should" \
        " be present"
    aaa._purge_expired_registrations()
    assert len(aaa._store.pending_registrations) == 1, "The registration should " \
        "be still there"
    aaa._purge_expired_registrations(exp_time=0)
    assert len(aaa._store.pending_registrations) == 0, "The registration should " \
        "have been removed"


# Patch the mailer _send() method to prevent network interactions
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_prevent_double_registration(mocked):
    # Create two registration requests, then validate them.
    # The first should succeed, the second one fail as the account has been created.

    # create first registration
    old_dir = os.getcwd()
    os.chdir(testdir)
    aaa.register('user_foo', 'first_pwd', 'a@a.a')
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)
    first_registration_code = aaa._store.pending_registrations.keys()[0]

    # create second registration
    aaa.register('user_foo', 'second_pwd', 'b@b.b')
    os.chdir(old_dir)
    assert len(aaa._store.pending_registrations) == 2, repr(aaa._store.pending_registrations)
    registration_codes = aaa._store.pending_registrations.keys()
    if first_registration_code == registration_codes[0]:
        second_registration_code = registration_codes[1]
    else:
        second_registration_code = registration_codes[0]

    # Only the 'admin' account exists
    assert len(aaa._store.users) == 1

    # Run validate_registration with the first registration
    aaa.validate_registration(first_registration_code)
    assert 'user_foo' in aaa._store.users, "Account should have been added"
    assert len(aaa._store.users) == 2

    # After the first registration only one pending registration should be left
    # The registration having 'a@a.a' email address should be gone
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)
    pr_code, pr_data = aaa._store.pending_registrations.items()[0]
    assert pr_data['email_addr'] == 'b@b.b', "Incorrect registration in the datastore"

    # Logging in using the first login should succeed
    login = aaa.login('user_foo', 'first_pwd')
    assert login == True, "Login must succed"
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)

    # Run validate_registration with the second registration code
    # The second registration should fail as the user account exists
    assert_raises(AAAException, aaa.validate_registration, second_registration_code)
    # test login
    login = aaa.login('user_foo', 'second_pwd')
    assert login == False, "Login must fail"


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_no_params(mocked):
    aaa.send_password_reset_email()


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_incorrect_addr(mocked):
    aaa.send_password_reset_email(email_addr='incorrect_addr')


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_incorrect_user(mocked):
    aaa.send_password_reset_email(username='bogus_name')


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_missing_email_addr(mocked):
    aaa.send_password_reset_email(username='admin')


@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_incorrect_pair(mocked):
    aaa.send_password_reset_email(username='admin', email_addr='incorrect_addr')


@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_by_email_addr(mocked):
    aaa._store.users['admin']['email_addr'] = 'admin@localhost.local'
    old_dir = os.getcwd()
    os.chdir(testdir)
    aaa.send_password_reset_email(email_addr='admin@localhost.local')
    os.chdir(old_dir)
    #TODO: add UT


@with_setup(setup_mockedadmin, teardown_dir)
@mock.patch.object(Mailer, '_send')
def test_send_password_reset_email_by_username(mocked):
    old_dir = os.getcwd()
    os.chdir(testdir)
    aaa._store.users['admin']['email_addr'] = 'admin@localhost.local'
    assert not mocked.called
    aaa.send_password_reset_email(username='admin')
    aaa.mailer.join()
    os.chdir(old_dir)
    assert mocked.called
    assert mocked.call_args[0][0] == 'admin@localhost.local'


@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset_invalid():
    aaa.reset_password('bogus', 'newpassword')


@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset_timed_out():
    aaa.password_reset_timeout = 0
    token = aaa._reset_code('admin', 'admin@localhost.local')
    aaa.reset_password(token, 'newpassword')


@raises(AAAException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset_nonexistent_user():
    token = aaa._reset_code('admin_bogus', 'admin@localhost.local')
    aaa.reset_password(token, 'newpassword')


# The following test should fail
# an user can change the password reset timestamp by b64-decoding the token,
# editing the field and b64-encoding it
@SkipTest
@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset_mangled_timestamp():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    tstamp = str(int(tstamp) + 100)
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    aaa.reset_password(mangled_token, 'newpassword')


@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset_mangled_username():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    username += "mangled_username"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    aaa.reset_password(mangled_token, 'newpassword')


@raises(AuthException)
@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset_mangled_email():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    email_addr += "mangled_email"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    aaa.reset_password(mangled_token, 'newpassword')


@with_setup(setup_mockedadmin, teardown_dir)
def test_perform_password_reset():
    old_dir = os.getcwd()
    os.chdir(testdir)
    token = aaa._reset_code('admin', 'admin@localhost.local')
    aaa.reset_password(token, 'newpassword')
    os.chdir(old_dir)
