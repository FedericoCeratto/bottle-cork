# Cork - Authentication module for tyyhe Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under GPLv3+ license, see LICENSE.txt
#
# Unit testing - test the Cork module against a real MongoDB instance
# running on localhost.

from base64 import b64encode, b64decode
from nose import SkipTest
from nose.tools import assert_raises, raises, with_setup
from time import time
import mock
import os
import shutil

from cork import Cork, AAAException, AuthException
from cork.backends import MongoDBBackend
import testutils

testdir = None  # Test directory
aaa = None  # global Cork instance
cookie_name = None  # global variable to track cookie status

class RoAttrDict(dict):
    """Read-only attribute-accessed dictionary.
    Used to mock beaker's session objects
    """
    def __getattr__(self, name):
        return self[name]

    def delete(self):
        """Used during logout to delete the current session"""
        global cookie_name
        cookie_name = None



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

def setup_test_db():
    mb = MongoDBBackend(db_name='cork-functional-test', initialize=True)

    # Purge DB
    mb.users._coll.drop()
    mb.roles._coll.drop()
    mb.pending_registrations._coll.drop()

    # Create admin
    mb.users._coll.insert({
        "login": "admin",
        "email_addr": "admin@localhost.local",
        "desc": "admin test user",
        "role": "admin",
        "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
        "creation_date": "2012-10-28 20:50:26.286723"
    })

    # Create users
    mb.roles._coll.insert({'role': 'special', 'val': 200})
    mb.roles._coll.insert({'role': 'admin', 'val': 100})
    mb.roles._coll.insert({'role': 'editor', 'val': 60})
    mb.roles._coll.insert({'role': 'user', 'val': 50})

    return mb

def purge_test_db():
    # Purge DB
    mb = MongoDBBackend(db_name='cork-functional-test', initialize=True)
    mb.users._coll.drop()
    mb.roles._coll.drop()
    mb.pending_registrations._coll.drop()

def setup_mockedadmin():
    """Setup test directory and a MockedAdminCork instance"""
    global aaa
    global cookie_name
    mb = setup_test_db()
    aaa = MockedAdminCork(backend=mb, smtp_server='localhost', email_sender='test@localhost')
    cookie_name = None

def setup_mocked_unauthenticated():
    """Setup test directory and a MockedAdminCork instance"""
    global aaa
    global cookie_name
    mb = setup_test_db()
    aaa = MockedUnauthenticatedCork(backend=mb, smtp_server='localhost', email_sender='test@localhost')
    cookie_name = None


@with_setup(setup_test_db, purge_test_db)
def test_initialize_storage():
    mb = MongoDBBackend(db_name='cork-functional-test', initialize=True)
    Cork(backend=mb)


@with_setup(setup_mockedadmin, purge_test_db)
def test_mockedadmin():
    assert len(aaa._store.users) == 1, repr(aaa._store.users)
    assert 'admin' in aaa._store.users, repr(aaa._store.users)


@with_setup(setup_mockedadmin, purge_test_db)
def test_password_hashing():
    shash = aaa._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith('='), "hash should end with '='"
    assert aaa._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"


@with_setup(setup_mockedadmin, purge_test_db)
def test_incorrect_password_hashing():
    shash = aaa._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith('='), "hash should end with '='"
    assert aaa._verify_password('user_foo', '####', shash) == False, \
        "Hashing verification should fail"
    assert aaa._verify_password('###', 'bogus_pwd', shash) == False, \
        "Hashing verification should fail"


@with_setup(setup_mockedadmin, purge_test_db)
def test_password_hashing_collision():
    salt = 'S' * 32
    hash1 = aaa._hash('user_foo', 'bogus_pwd', salt=salt)
    hash2 = aaa._hash('user_foobogus', '_pwd', salt=salt)
    assert hash1 != hash2, "Hash collision"


@with_setup(setup_mockedadmin, purge_test_db)
def test_unauth_create_role():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.create_role, 'user', 33)


@with_setup(setup_mockedadmin, purge_test_db)
def test_create_existing_role():
    assert_raises(AAAException, aaa.create_role, 'user', 33)

@raises(KeyError)
@with_setup(setup_mockedadmin, purge_test_db)
def test_access_nonexisting_role():
    aaa._store.roles['NotThere']

@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_create_role_with_incorrect_level():
    aaa.create_role('new_user', 'not_a_number')


@with_setup(setup_mockedadmin, purge_test_db)
def test_create_role():
    assert len(aaa._store.roles) == 4, repr(aaa._store.roles)
    aaa.create_role('user33', 33)
    assert len(aaa._store.roles) == 5, repr(aaa._store.roles)


@with_setup(setup_mockedadmin, purge_test_db)
def test_unauth_delete_role():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.delete_role, 'user')


@with_setup(setup_mockedadmin, purge_test_db)
def test_delete_nonexistent_role():
    assert_raises(AAAException, aaa.delete_role, 'user123')


@with_setup(setup_mockedadmin, purge_test_db)
def test_create_delete_role():
    assert len(aaa._store.roles) == 4, repr(aaa._store.roles)
    aaa.create_role('user33', 33)
    assert len(aaa._store.roles) == 5, repr(aaa._store.roles)

    assert aaa._store.roles['user33'] == 33
    aaa.delete_role('user33')
    assert len(aaa._store.roles) == 4, repr(aaa._store.roles)


@with_setup(setup_mockedadmin, purge_test_db)
def test_list_roles():
    roles = list(aaa.list_roles())
    assert len(roles) == 4, "Incorrect. Users are: %s" % repr(aaa._store.roles)


@with_setup(setup_mockedadmin, purge_test_db)
def test_unauth_create_user():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.create_user, 'phil', 'user', 'hunter123')


@with_setup(setup_mockedadmin, purge_test_db)
def test_create_existing_user():
    assert_raises(AAAException, aaa.create_user, 'admin', 'admin', 'bogus')


@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_create_user_with_wrong_role():
    aaa.create_user('admin2', 'nonexistent_role', 'bogus')


@with_setup(setup_mockedadmin, purge_test_db)
def test_create_user():
    assert len(aaa._store.users) == 1, repr(aaa._store.users)
    aaa.create_user('phil', 'user', 'user')
    assert len(aaa._store.users) == 2, repr(aaa._store.users)
    assert 'phil' in aaa._store.users


@with_setup(setup_mockedadmin, purge_test_db)
def test_unauth_delete_user():
    aaa._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa.delete_user, 'phil')


@with_setup(setup_mockedadmin, purge_test_db)
def test_delete_nonexistent_user():
    assert_raises(AAAException, aaa.delete_user, 'not_an_user')


@with_setup(setup_mockedadmin, purge_test_db)
def test_delete_user():
    assert len(aaa._store.users) == 1, repr(aaa._store.users)
    aaa.delete_user('admin')
    assert len(aaa._store.users) == 0, repr(aaa._store.users)
    assert 'admin' not in aaa._store.users



@with_setup(setup_mockedadmin, purge_test_db)
def test_list_users():
    users = list(aaa.list_users())
    assert len(users) == 1, "Incorrect. Users are: %s" % repr(aaa._store.users)

@with_setup(setup_mockedadmin, purge_test_db)
def test_iteritems_on_users():
    for k, v in aaa._store.users.iteritems():
        assert isinstance(v, dict)
        expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date', 'desc'))
        dkeys = set(v.keys())

        extra = dkeys - expected_dkeys
        assert not extra, "Unexpected extra keys: %s" % repr(extra)

        missing = expected_dkeys - dkeys
        assert not missing, "Missing keys: %s" % repr(missing)


@with_setup(setup_mockedadmin, purge_test_db)
def test_failing_login():
    login = aaa.login('phil', 'hunter123')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None


@with_setup(setup_mockedadmin, purge_test_db)
def test_login_nonexistent_user_empty_password():
    login = aaa.login('IAmNotHome', '')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None


@with_setup(setup_mockedadmin, purge_test_db)
def test_login_existing_user_empty_password():
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._store.users
    assert aaa._store.users['phil']['role'] == 'user'
    login = aaa.login('phil', '')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None


@with_setup(setup_mockedadmin, purge_test_db)
def test_create_and_validate_user():
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._store.users
    assert aaa._store.users['phil']['role'] == 'user'
    login = aaa.login('phil', 'hunter123')
    assert login == True, "Login must succeed"
    global cookie_name
    assert cookie_name == 'phil'

@with_setup(setup_mockedadmin, purge_test_db)
def test_create_user_login_logout():
    global cookie_name
    assert 'phil' not in aaa._store.users
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._store.users
    login = aaa.login('phil', 'hunter123')
    assert login == True, "Login must succeed"
    assert cookie_name == 'phil'
    try:
        aaa.logout(fail_redirect='/failed_logout')
    except Exception, e:
        assert e.status_code == 302
        redir_location = e._headers['Location'][0]
        assert redir_location == 'http://127.0.0.1/login', redir_location

    assert cookie_name == None

@with_setup(setup_mockedadmin, purge_test_db)
def test_modify_user_using_overwrite():
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._store.users
    u = aaa._store.users['phil']
    u.update(role='fool')
    aaa._store.users['phil'] = u
    assert aaa._store.users['phil']['role'] == 'fool'

@with_setup(setup_mockedadmin, purge_test_db)
def test_modify_user():
    aaa.create_user('phil', 'user', 'hunter123')
    aaa._store.users['phil']['role'] = 'fool'
    assert aaa._store.users['phil']['role'] == 'fool'

@with_setup(setup_mockedadmin, purge_test_db)
def test_modify_user_using_local_change():
    aaa.create_user('phil', 'user', 'hunter123')
    u = aaa._store.users['phil']
    u['role'] = 'fool'
    assert u['role'] == 'fool', repr(u)
    assert aaa._store.users['phil']['role'] == 'fool'


@with_setup(setup_mockedadmin, purge_test_db)
def test_require_failing_username():
    # The user exists, but I'm 'admin'
    aaa.create_user('phil', 'user', 'hunter123')
    assert_raises(AuthException, aaa.require, username='phil')


@with_setup(setup_mockedadmin, purge_test_db)
def test_require_nonexistent_username():
    assert_raises(AAAException, aaa.require, username='no_such_user')


@with_setup(setup_mockedadmin, purge_test_db)
def test_require_failing_role_fixed():
    assert_raises(AuthException, aaa.require, role='user', fixed_role=True)


@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_require_missing_parameter():
    aaa.require(fixed_role=True)


@with_setup(setup_mockedadmin, purge_test_db)
def test_require_nonexistent_role():
    assert_raises(AAAException, aaa.require, role='clown')

@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_require_failing_role():
    # Requesting level >= 100
    aaa.require(role='special')


@with_setup(setup_mockedadmin, purge_test_db)
def test_successful_require_role():
    aaa.require(username='admin')
    aaa.require(username='admin', role='admin')
    aaa.require(username='admin', role='admin', fixed_role=True)
    aaa.require(username='admin', role='user')


@with_setup(setup_mockedadmin, purge_test_db)
def test_authenticated_is_not__anonymous():
    assert not aaa.user_is_anonymous


@with_setup(setup_mockedadmin, purge_test_db)
def test_update_nonexistent_role():
    assert_raises(AAAException, aaa.current_user.update, role='clown')


@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_update_nonexistent_user():
    aaa._store.users.pop('admin')
    aaa.current_user.update(role='user')


@with_setup(setup_mockedadmin, purge_test_db)
def test_update_role():
    aaa.current_user.update(role='user')
    assert aaa._store.users['admin']['role'] == 'user'


@with_setup(setup_mockedadmin, purge_test_db)
def test_update_pwd():
    aaa.current_user.update(pwd='meow')


@with_setup(setup_mockedadmin, purge_test_db)
def test_update_email():
    print aaa._store.users['admin']
    aaa.current_user.update(email_addr='foo')
    assert aaa._store.users['admin']['email_addr'] == 'foo'


@raises(AAAException)
@with_setup(setup_mocked_unauthenticated, purge_test_db)
def test_get_current_user_unauth():
    aaa.current_user['username']


@with_setup(setup_mocked_unauthenticated, purge_test_db)
def test_unauth_is_anonymous():
    assert aaa.user_is_anonymous


@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_get_current_user_nonexistent():
    # The current user 'admin' is not in the user table
    aaa._store.users.pop('admin')
    aaa.current_user


@with_setup(setup_mockedadmin, purge_test_db)
def test_get_nonexistent_user():
    assert aaa.user('nonexistent_user') is None


@with_setup(setup_mockedadmin, purge_test_db)
def test_get_user_description_field():
    admin = aaa.user('admin')
    for field in ['description', 'email_addr']:
        assert field in admin.__dict__


@with_setup(setup_mockedadmin, purge_test_db)
def test_register_no_user():
    assert_raises(AssertionError, aaa.register, None, 'pwd', 'a@a.a')


@with_setup(setup_mockedadmin, purge_test_db)
def test_register_no_pwd():
    assert_raises(AssertionError, aaa.register, 'foo', None, 'a@a.a')


@with_setup(setup_mockedadmin, purge_test_db)
def test_register_no_email():
    assert_raises(AssertionError, aaa.register, 'foo', 'pwd', None)


@with_setup(setup_mockedadmin, purge_test_db)
def test_register_already_existing():
    assert_raises(AAAException, aaa.register, 'admin', 'pwd', 'a@a.a')


@with_setup(setup_mockedadmin, purge_test_db)
def test_register_no_role():
    assert_raises(AAAException, aaa.register, 'foo', 'pwd', 'a@a.a', role='clown')


@with_setup(setup_mockedadmin, purge_test_db)
def test_register_role_too_high():
    assert_raises(AAAException, aaa.register, 'foo', 'pwd', 'a@a.a', role='admin')

@with_setup(setup_mockedadmin, purge_test_db)
def test_register_valid():
    aaa.mailer.send_email = mock.Mock()
    aaa.register('foo', 'pwd', 'email@email.org', role='user',
        email_template='examples/views/registration_email.tpl'
    )
    assert aaa.mailer.send_email.called
    r = aaa._store.pending_registrations
    assert len(r) == 1
    reg_code = list(r)[0]
    assert r[reg_code]['username'] == 'foo'
    assert r[reg_code]['email_addr'] == 'email@email.org'
    assert r[reg_code]['role'] == 'user'


@with_setup(setup_mockedadmin, purge_test_db)
def test_validate_registration_no_code():
    assert_raises(AAAException, aaa.validate_registration, 'not_a_valid_code')

@with_setup(setup_mockedadmin, purge_test_db)
def test_validate_registration():
    aaa.mailer.send_email = mock.Mock()
    aaa.register('foo', 'pwd', 'email@email.org', role='user',
        email_template='examples/views/registration_email.tpl'
    )
    r = aaa._store.pending_registrations
    reg_code = list(r)[0]

    assert len(aaa._store.users) == 1, "Only the admin user should be present"
    aaa.validate_registration(reg_code)
    assert len(aaa._store.users) == 2, "The new user should be present"
    assert len(aaa._store.pending_registrations) == 0, \
        "The registration entry should be removed"



@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_no_data():
    aaa.send_password_reset_email()

@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_incorrect_data():
    aaa.send_password_reset_email(username='NotThere', email_addr='NoEmail')

@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_incorrect_data2():
    # The username is valid but the email address is not matching
    aaa.send_password_reset_email(username='admin', email_addr='NoEmail')

@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_only_incorrect_email():
    aaa.send_password_reset_email(email_addr='NoEmail')

@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_only_incorrect_username():
    aaa.send_password_reset_email(username='NotThere')

@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_only_email():
    aaa.mailer.send_email = mock.Mock()
    aaa.send_password_reset_email(email_addr='admin@localhost.local',
        email_template='examples/views/password_reset_email')

@with_setup(setup_mockedadmin, purge_test_db)
def test_send_password_reset_email_only_username():
    aaa.mailer.send_email = mock.Mock()
    aaa.send_password_reset_email(username='admin',
        email_template='examples/views/password_reset_email')



@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset_invalid():
    aaa.reset_password('bogus', 'newpassword')


@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset_timed_out():
    aaa.password_reset_timeout = 0
    token = aaa._reset_code('admin', 'admin@localhost.local')
    aaa.reset_password(token, 'newpassword')


@raises(AAAException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset_nonexistent_user():
    token = aaa._reset_code('admin_bogus', 'admin@localhost.local')
    aaa.reset_password(token, 'newpassword')


# The following test should fail
# an user can change the password reset timestamp by b64-decoding the token,
# editing the field and b64-encoding it
@SkipTest
@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset_mangled_timestamp():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    tstamp = str(int(tstamp) + 100)
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    aaa.reset_password(mangled_token, 'newpassword')


@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset_mangled_username():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    username += "mangled_username"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    aaa.reset_password(mangled_token, 'newpassword')


@raises(AuthException)
@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset_mangled_email():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    username, email_addr, tstamp, h = b64decode(token).split(':', 3)
    email_addr += "mangled_email"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token)
    aaa.reset_password(mangled_token, 'newpassword')


@with_setup(setup_mockedadmin, purge_test_db)
def test_perform_password_reset():
    token = aaa._reset_code('admin', 'admin@localhost.local')
    aaa.reset_password(token, 'newpassword')



