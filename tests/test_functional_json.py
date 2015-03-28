# -*- coding: utf-8 -*
# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing - test the Cork module against a Json-based db using the
# JsonBackend backend module

from base64 import b64encode, b64decode
from pytest import raises
import bottle
import mock
import pytest

from cork import Cork, AAAException, AuthException
from cork.backends import JsonBackend
from conftest import MockedSession, MockedSessionCork, assert_is_redirect



@pytest.fixture
def tmpdir_with_json(tmpdir):
    """Setup test directory with valid JSON files"""
    tmpdir.mkdir('views')
    tmpdir.join('users.json').write("""{"admin": {"email_addr": "admin@localhost.local", "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596"}}""")
    tmpdir.join('roles.json').write("""{"special": 200, "admin": 100, "user": 50, "editor": 60}""")
    tmpdir.join('register.json').write("""{}""")
    tmpdir.join('registration_email.tpl').write("""Username:{{username}} Email:{{email_addr}} Code:{{registration_code}}""")
    tmpdir.join('password_reset_email.tpl').write("""Username:{{username}} Email:{{email_addr}} Code:{{reset_code}}""")
    #tmpdir.join('users.json').write("""{"admin": {"email_addr": null, "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596"}}""")
    #tmpdir.join('roles.json').write("""{"special": 200, "admin": 100, "user": 50}""")
    return tmpdir


@pytest.fixture
def json_backend(tmpdir_with_json):
    return JsonBackend(tmpdir_with_json)


@pytest.fixture
def aaa_admin(json_backend, tmpdir_with_json):
    aaa = MockedSessionCork(
        tmpdir_with_json,
        backend=json_backend,
        email_sender='test@localhost',
        smtp_server='localhost',
    )
    aaa._mocked_beaker_session = MockedSession(username='admin')
    return aaa




class Foo:
    def test_iteritems_on_users(self, aaa):
        for k, v in aaa._store.users.iteritems():
            expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date',
                'desc'))
            dkeys = set(v.keys())

            extra = dkeys - expected_dkeys
            assert not extra, "Unexpected extra keys: %s" % repr(extra)

            missing = expected_dkeys - dkeys
            assert not missing, "Missing keys: %s" % repr(missing)


## Unauthenticated user

def test_unauth_basic(aaa_unauth):
    assert aaa_unauth._beaker_session.get('username', None) == None

def test_get_current_user_unauth(aaa_unauth):
    with raises(AAAException):
        aaa_unauth.current_user['username']


def test_unauth_is_anonymous(aaa_unauth):
    assert aaa_unauth.user_is_anonymous


## Logged in as admin

def test_mockedadmin(aaa_admin):
    assert len(aaa_admin._store.users) == 1,  len(aaa_admin._store.users)
    assert 'admin' in aaa_admin._store.users, repr(aaa_admin._store.users)


def test_password_hashing(aaa_admin):
    shash = aaa_admin._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith('='), "hash should end with '='"
    assert aaa_admin._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"


def test_incorrect_password_hashing(aaa_admin):
    shash = aaa_admin._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith('='), "hash should end with '='"
    assert aaa_admin._verify_password('user_foo', '####', shash) == False, \
        "Hashing verification should fail"
    assert aaa_admin._verify_password('###', 'bogus_pwd', shash) == False, \
        "Hashing verification should fail"


def test_password_hashing_collision(aaa_admin):
    salt = 'S' * 32
    hash1 = aaa_admin._hash('user_foo', 'bogus_pwd', salt=salt)
    hash2 = aaa_admin._hash('user_foobogus', '_pwd', salt=salt)
    assert hash1 != hash2, "Hash collision"


def test_unauth_create_role(aaa_admin):
    assert len(aaa_admin._store.users) == 1, "Only the admin user should be present"
    aaa_admin._store.roles['admin'] = 10  # lower admin level
    assert aaa_admin._store.roles['admin'] == 10, aaa_admin._store.roles['admin']
    assert len(aaa_admin._store.users) == 1, "Only the admin user should be present"
    with raises(AuthException):
        aaa_admin.create_role('user', 33)

def assert_raises(ex, f, *a, **kw):
    with raises(ex):
        f(*a, **kw)

def test_create_existing_role(aaa_admin):
    assert_raises(AAAException, aaa_admin.create_role, 'user', 33)

def test_access_nonexisting_role(aaa_admin):
    with raises(KeyError):
        aaa_admin._store.roles['NotThere']

def test_create_role_with_incorrect_level(aaa_admin):
    with raises(AAAException):
        aaa_admin.create_role('new_user', 'not_a_number')


def test_create_role(aaa_admin):
    assert len(aaa_admin._store.roles) == 4, repr(aaa_admin._store.roles)
    aaa_admin.create_role('user33', 33)
    assert len(aaa_admin._store.roles) == 5, repr(aaa_admin._store.roles)


def test_unauth_delete_role(aaa_admin):
    aaa_admin._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa_admin.delete_role, 'user')


def test_delete_nonexistent_role(aaa_admin):
    assert_raises(AAAException, aaa_admin.delete_role, 'user123')


def test_create_delete_role(aaa_admin):
    assert len(aaa_admin._store.roles) == 4, repr(aaa_admin._store.roles)
    aaa_admin.create_role('user33', 33)
    assert len(aaa_admin._store.roles) == 5, repr(aaa_admin._store.roles)

    assert aaa_admin._store.roles['user33'] == 33
    aaa_admin.delete_role('user33')
    assert len(aaa_admin._store.roles) == 4, repr(aaa_admin._store.roles)


def test_list_roles(aaa_admin):
    roles = list(aaa_admin.list_roles())
    assert len(roles) == 4, "Incorrect. Users are: %s" % repr(aaa_admin._store.roles)


def test_unauth_create_user(aaa_admin):
    aaa_admin._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa_admin.create_user, 'phil', 'user', 'hunter123')


def test_create_existing_user(aaa_admin):
    assert_raises(AAAException, aaa_admin.create_user, 'admin', 'admin', 'bogus')


def test_create_user_with_wrong_role(aaa_admin):
    with raises(AAAException):
        aaa_admin.create_user('admin2', 'nonexistent_role', 'bogus')


def test_create_user(aaa_admin):
    assert len(aaa_admin._store.users) == 1, repr(aaa_admin._store.users)
    aaa_admin.create_user('phil', 'user', 'user')
    assert len(aaa_admin._store.users) == 2, repr(aaa_admin._store.users)
    assert 'phil' in aaa_admin._store.users


def test_unauth_delete_user(aaa_admin):
    aaa_admin._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa_admin.delete_user, 'phil')


def test_delete_nonexistent_user(aaa_admin):
    assert_raises(AAAException, aaa_admin.delete_user, 'not_an_user')


def test_delete_user(aaa_admin):
    assert len(aaa_admin._store.users) == 1, repr(aaa_admin._store.users)
    aaa_admin.delete_user('admin')
    assert len(aaa_admin._store.users) == 0, repr(aaa_admin._store.users)
    assert 'admin' not in aaa_admin._store.users



def test_list_users(aaa_admin):
    users = list(aaa_admin.list_users())
    assert len(users) == 1, "Incorrect. Users are: %s" % repr(aaa_admin._store.users)

def test_iteritems_on_users(aaa_admin):
    for k, v in aaa_admin._store.users.iteritems():
        #assert isinstance(k, str)
        #assert isinstance(v, dict)
        expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date',
            'desc', 'last_login'))
        dkeys = set(v.keys())

        extra = dkeys - expected_dkeys
        assert not extra, "Unexpected extra keys: %s" % repr(extra)

        missing = expected_dkeys - dkeys
        assert not missing, "Missing keys: %s" % repr(missing)


def test_failing_login(aaa_admin):
    login = aaa_admin.login('phil', 'hunter123')
    assert login == False, "Login must fail"
    assert aaa_admin._beaker_session.get('username', None) == None


def test_login_nonexistent_user_empty_password(aaa_admin):
    login = aaa_admin.login('IAmNotHome', '')
    assert login == False, "Login must fail"
    assert aaa_admin._beaker_session.get('username', None) == None


def test_login_existing_user_empty_password(aaa_admin):
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa_admin._store.users
    assert aaa_admin._store.users['phil']['role'] == 'user'
    login = aaa_admin.login('phil', '')
    assert login == False, "Login must fail"
    assert aaa_admin._beaker_session.get('username', None) == None


def test_create_and_validate_user(aaa_admin):
    assert len(aaa_admin._store.users) == 1, "Only the admin user should be present"
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert len(aaa_admin._store.users) == 2, "Two users should be present"
    assert 'phil' in aaa_admin._store.users
    assert aaa_admin._store.users['phil']['role'] == 'user'
    login = aaa_admin.login('phil', 'hunter123')
    assert login == True, "Login must succeed"
    assert aaa_admin._beaker_session['username'] == 'phil'

def test_create_and_validate_user_unicode(aaa_admin):
    assert len(aaa_admin._store.users) == 1, "Only the admin user should be present"
    aaa_admin.create_user(u'phil_åöॐ', 'user', u'neko_猫')
    assert len(aaa_admin._store.users) == 2, "Two users should be present"
    assert u'phil_åöॐ' in aaa_admin._store.users
    assert aaa_admin._store.users[u'phil_åöॐ']['role'] == 'user'
    login = aaa_admin.login(u'phil_åöॐ', u'neko_猫')
    assert login == True, "Login must succeed"
    assert aaa_admin._beaker_session['username'] == u'phil_åöॐ'

def test_create_user_login_logout(aaa_admin):
    assert 'phil' not in aaa_admin._store.users
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa_admin._store.users
    login = aaa_admin.login('phil', 'hunter123')
    assert login == True, "Login must succeed"
    assert aaa_admin._beaker_session['username'] == 'phil'
    try:
        aaa_admin.logout(fail_redirect='/failed_logout')
    except bottle.HTTPResponse, e:
        assert_is_redirect(e, 'login')

    assert aaa_admin._beaker_session.get('username', None) == None

def test_modify_user_using_overwrite(aaa_admin):
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa_admin._store.users
    u = aaa_admin._store.users['phil']
    u.update(role='editor')
    aaa_admin._store.users['phil'] = u
    assert aaa_admin._store.users['phil']['role'] == 'editor'

def test_modify_user(aaa_admin):
    aaa_admin.create_user('phil', 'user', 'hunter123')
    aaa_admin._store.users['phil']['role'] = 'editor'
    assert aaa_admin._store.users['phil']['role'] == 'editor', aaa_admin._store.users['phil']


def test_modify_user_using_local_change(aaa_admin):
    aaa_admin.create_user('phil', 'user', 'hunter123')
    u = aaa_admin._store.users['phil']
    u['role'] = 'editor'
    assert u['role'] == 'editor', repr(u)
    assert aaa_admin._store.users['phil']['role'] == 'editor'


def test_require_failing_username(aaa_admin):
    # The user exists, but I'm 'admin'
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert_raises(AuthException, aaa_admin.require, username='phil')


def test_require_nonexistent_username(aaa_admin):
    assert_raises(AAAException, aaa_admin.require, username='no_such_user')


def test_require_failing_role_fixed(aaa_admin):
    assert_raises(AuthException, aaa_admin.require, role='user', fixed_role=True)


def test_require_missing_parameter(aaa_admin):
    with raises(AAAException):
        aaa_admin.require(fixed_role=True)


def test_require_nonexistent_role(aaa_admin):
    assert_raises(AAAException, aaa_admin.require, role='clown')

def test_require_failing_role(aaa_admin):
    # Requesting level >= 100
    assert_raises(AuthException, aaa_admin.require, role='special')


def test_successful_require_role(aaa_admin):
    aaa_admin.require(username='admin')
    aaa_admin.require(username='admin', role='admin')
    aaa_admin.require(username='admin', role='admin', fixed_role=True)
    aaa_admin.require(username='admin', role='user')


def test_authenticated_is_not_anonymous(aaa_admin):
    assert not aaa_admin.user_is_anonymous


def test_update_nonexistent_role(aaa_admin):
    assert_raises(AAAException, aaa_admin.current_user.update, role='clown')


def test_update_nonexistent_user(aaa_admin):
    with raises(AAAException):
        aaa_admin._store.users.pop('admin')
        aaa_admin.current_user.update(role='user')


def test_update_role(aaa_admin):
    aaa_admin.current_user.update(role='user')
    assert aaa_admin._store.users['admin']['role'] == 'user'


def test_update_pwd(aaa_admin):
    aaa_admin.current_user.update(pwd='meow')


def test_update_email(aaa_admin):
    print aaa_admin._store.users['admin']
    aaa_admin.current_user.update(email_addr='foo')
    assert aaa_admin._store.users['admin']['email_addr'] == 'foo', aaa_admin._store.users['admin']


def test_get_current_user_nonexistent(aaa_admin):
    # The current user 'admin' is not in the user table
    with raises(AuthException):
        aaa_admin._store.users.pop('admin')
        aaa_admin.current_user


def test_get_nonexistent_user(aaa_admin):
    assert aaa_admin.user('nonexistent_user') is None


def test_get_user_description_field(aaa_admin):
    admin = aaa_admin.user('admin')
    for field in ['description', 'email_addr']:
        assert field in admin.__dict__


def test_register_no_user(aaa_admin):
    assert_raises(AssertionError, aaa_admin.register, None, 'pwd', 'a@a.a')


def test_register_no_pwd(aaa_admin):
    assert_raises(AssertionError, aaa_admin.register, 'foo', None, 'a@a.a')


def test_register_no_email(aaa_admin):
    assert_raises(AssertionError, aaa_admin.register, 'foo', 'pwd', None)


def test_register_already_existing(aaa_admin):
    assert_raises(AAAException, aaa_admin.register, 'admin', 'pwd', 'a@a.a')


def test_register_no_role(aaa_admin):
    assert_raises(AAAException, aaa_admin.register, 'foo', 'pwd', 'a@a.a', role='clown')


def test_register_role_too_high(aaa_admin):
    assert_raises(AAAException, aaa_admin.register, 'foo', 'pwd', 'a@a.a', role='admin')


def test_register_valid(aaa_admin):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.register('foo', 'pwd', 'email@email.org', role='user',
        email_template='examples/views/registration_email.tpl'
    )
    assert aaa_admin.mailer.send_email.called
    r = aaa_admin._store.pending_registrations
    assert len(r) == 1
    reg_code = list(r)[0]
    assert r[reg_code]['username'] == 'foo'
    assert r[reg_code]['email_addr'] == 'email@email.org'
    assert r[reg_code]['role'] == 'user'


def test_validate_registration_no_code(aaa_admin):
    assert_raises(AAAException, aaa_admin.validate_registration, 'not_a_valid_code')

def test_validate_registration(aaa_admin):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.register('foo', 'pwd', 'email@email.org', role='user',
        email_template='examples/views/registration_email.tpl'
    )
    r = aaa_admin._store.pending_registrations
    reg_code = list(r)[0]

    assert len(aaa_admin._store.users) == 1, "Only the admin user should be present"
    aaa_admin.validate_registration(reg_code)
    assert len(aaa_admin._store.users) == 2, "The new user should be present"
    assert len(aaa_admin._store.pending_registrations) == 0, \
        "The registration entry should be removed"



def test_send_password_reset_email_no_data(aaa_admin):
    with raises(AAAException):
        aaa_admin.send_password_reset_email()

def test_send_password_reset_email_incorrect_data(aaa_admin):
    with raises(AAAException):
        aaa_admin.send_password_reset_email(username='NotThere', email_addr='NoEmail')

def test_send_password_reset_email_incorrect_data2(aaa_admin):
    with raises(AAAException):
        # The username is valid but the email address is not matching
        aaa_admin.send_password_reset_email(username='admin', email_addr='NoEmail')

def test_send_password_reset_email_only_incorrect_email(aaa_admin):
    with raises(AAAException):
        aaa_admin.send_password_reset_email(email_addr='NoEmail')

def test_send_password_reset_email_only_incorrect_username(aaa_admin):
    with raises(AAAException):
        aaa_admin.send_password_reset_email(username='NotThere')

def test_send_password_reset_email_only_email(aaa_admin):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.send_password_reset_email(email_addr='admin@localhost.local',
        email_template='examples/views/password_reset_email')

def test_send_password_reset_email_only_username(aaa_admin):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.send_password_reset_email(username='admin',
        email_template='examples/views/password_reset_email')



def test_perform_password_reset_invalid(aaa_admin):
    with raises(AuthException):
        aaa_admin.reset_password('bogus', 'newpassword')


def test_perform_password_reset_timed_out(aaa_admin):
    aaa_admin.password_reset_timeout = 0
    token = aaa_admin._reset_code('admin', 'admin@localhost.local')
    with raises(AuthException):
        aaa_admin.reset_password(token, 'newpassword')


def test_perform_password_reset_nonexistent_user(aaa_admin):
    token = aaa_admin._reset_code('admin_bogus', 'admin@localhost.local')
    with raises(AAAException):
        aaa_admin.reset_password(token, 'newpassword')


# The following test should fail
# an user can change the password reset timestamp by b64-decoding the token,
# editing the field and b64-encoding it
# FIXME
def test_perform_password_reset_mangled_timestamp(aaa_admin):
    token = aaa_admin._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    tstamp = str(int(tstamp) + 100)
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    with raises(AuthException):
        aaa_admin.reset_password(mangled_token, 'newpassword')


def test_perform_password_reset_mangled_username(aaa_admin):
    token = aaa_admin._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    username += "mangled_username"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    with raises(AuthException):
        aaa_admin.reset_password(mangled_token, 'newpassword')


def test_perform_password_reset_mangled_email(aaa_admin):
    token = aaa_admin._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    email_addr += "mangled_email"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    with raises(AuthException):
        aaa_admin.reset_password(mangled_token, 'newpassword')


def test_perform_password_reset(aaa_admin):
    token = aaa_admin._reset_code('admin', 'admin@localhost.local')
    aaa_admin.reset_password(token, 'newpassword')



