# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing - utility functions.
#
import bottle
import os
import shutil
import sys
import mock
import tempfile
from base64 import b64encode, b64decode
from nose.tools import assert_raises, raises, with_setup
from nose import SkipTest

from cork import Cork, AAAException, AuthException

cookie_name = None

def pick_temp_directory():
    """Select a temporary directory for the test files.
    Set the tmproot global variable.
    """
    if os.environ.get('TRAVIS', False):
        return tempfile.mkdtemp()

    if sys.platform == 'linux2':
        # In-memory filesystem allows faster testing.
        return tempfile.mkdtemp(dir='/dev/shm')

    return tempfile.mkdtemp()


def purge_temp_directory(test_dir):
    """Remove the test directory"""
    assert test_dir
    shutil.rmtree(test_dir)

def assert_is_redirect(e, path):
    """Check if an HTTPResponse is a redirect.

    :param path: relative path without leading slash.
    :type path: str
    """
    assert isinstance(e, bottle.HTTPResponse), "Incorrect exception type passed to assert_is_redirect"
    assert e.status_code == 302, "HTTPResponse status should be 302 but is '%s'" % e.status
    redir_location = e.headers['Location'].rsplit('/', 1)[1]
    assert redir_location == path, "Redirected to %s instead of %s" % (redir_location, path)







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
        cookie_name = username



class DatabaseInteractionAsUnauthenticated(object):

    def setUp(self):
        """Setup test directory and a MockedAdminCork instance"""
        global cookie_name
        print 'Performing MockedUnauthenticatedCork setup'
        mb = self.setup_test_db()
        self.aaa = MockedUnauthenticatedCork(backend=mb,
            smtp_server='localhost', email_sender='test@localhost')
        cookie_name = None

    def tearDown(self):
        if hasattr(self, 'purge_test_db'):
            self.purge_test_db()

        del(self.aaa)
        cookie_name = None

    @raises(AAAException)
    def test_get_current_user_unauth(self):
        print self.aaa.current_user
        self.aaa.current_user['username']

    def test_unauth_is_anonymous(self):
        assert self.aaa.user_is_anonymous




class DatabaseInteractionAsAdmin(object):

    def setUp(self):
        """Setup test database and a MockedAdminCork instance"""
        global cookie_name
        mb = self.setup_test_db()
        print 'Performing MockedAdminCork setup'
        self.aaa = MockedAdminCork(backend=mb, smtp_server='localhost',
            email_sender='test@localhost')
        cookie_name = None


    def tearDown(self):
        if hasattr(self, 'purge_test_db'):
            self.purge_test_db()

        del(self.aaa)
        cookie_name = None


    def test_mockedadmin(self):
        assert len(self.aaa._store.users) == 1,  len(self.aaa._store.users)
        assert 'admin' in self.aaa._store.users, repr(self.aaa._store.users)


    def test_password_hashing(self):
        shash = self.aaa._hash('user_foo', 'bogus_pwd')
        assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
        assert shash.endswith('='), "hash should end with '='"
        assert self.aaa._verify_password('user_foo', 'bogus_pwd', shash) == True, \
            "Hashing verification should succeed"


    def test_incorrect_password_hashing(self):
        shash = self.aaa._hash('user_foo', 'bogus_pwd')
        assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
        assert shash.endswith('='), "hash should end with '='"
        assert self.aaa._verify_password('user_foo', '####', shash) == False, \
            "Hashing verification should fail"
        assert self.aaa._verify_password('###', 'bogus_pwd', shash) == False, \
            "Hashing verification should fail"


    def test_password_hashing_collision(self):
        salt = 'S' * 32
        hash1 = self.aaa._hash('user_foo', 'bogus_pwd', salt=salt)
        hash2 = self.aaa._hash('user_foobogus', '_pwd', salt=salt)
        assert hash1 != hash2, "Hash collision"


    def test_unauth_create_role(self):
        assert len(self.aaa._store.users) == 1, "Only the admin user should be present"
        self.aaa._store.roles['admin'] = 10  # lower admin level
        assert self.aaa._store.roles['admin'] == 10, self.aaa._store.roles['admin']
        assert len(self.aaa._store.users) == 1, "Only the admin user should be present"
        assert_raises(AuthException, self.aaa.create_role, 'user', 33)


    def test_create_existing_role(self):
        assert_raises(AAAException, self.aaa.create_role, 'user', 33)

    @raises(KeyError)
    def test_access_nonexisting_role(self):
        self.aaa._store.roles['NotThere']

    @raises(AAAException)
    def test_create_role_with_incorrect_level(self):
        self.aaa.create_role('new_user', 'not_a_number')


    def test_create_role(self):
        assert len(self.aaa._store.roles) == 4, repr(self.aaa._store.roles)
        self.aaa.create_role('user33', 33)
        assert len(self.aaa._store.roles) == 5, repr(self.aaa._store.roles)


    def test_unauth_delete_role(self):
        self.aaa._store.roles['admin'] = 10  # lower admin level
        assert_raises(AuthException, self.aaa.delete_role, 'user')


    def test_delete_nonexistent_role(self):
        assert_raises(AAAException, self.aaa.delete_role, 'user123')


    def test_create_delete_role(self):
        assert len(self.aaa._store.roles) == 4, repr(self.aaa._store.roles)
        self.aaa.create_role('user33', 33)
        assert len(self.aaa._store.roles) == 5, repr(self.aaa._store.roles)

        assert self.aaa._store.roles['user33'] == 33
        self.aaa.delete_role('user33')
        assert len(self.aaa._store.roles) == 4, repr(self.aaa._store.roles)


    def test_list_roles(self):
        roles = list(self.aaa.list_roles())
        assert len(roles) == 4, "Incorrect. Users are: %s" % repr(self.aaa._store.roles)


    def test_unauth_create_user(self):
        self.aaa._store.roles['admin'] = 10  # lower admin level
        assert_raises(AuthException, self.aaa.create_user, 'phil', 'user', 'hunter123')


    def test_create_existing_user(self):
        assert_raises(AAAException, self.aaa.create_user, 'admin', 'admin', 'bogus')


    @raises(AAAException)
    def test_create_user_with_wrong_role(self):
        self.aaa.create_user('admin2', 'nonexistent_role', 'bogus')


    def test_create_user(self):
        assert len(self.aaa._store.users) == 1, repr(self.aaa._store.users)
        self.aaa.create_user('phil', 'user', 'user')
        assert len(self.aaa._store.users) == 2, repr(self.aaa._store.users)
        assert 'phil' in self.aaa._store.users


    def test_unauth_delete_user(self):
        self.aaa._store.roles['admin'] = 10  # lower admin level
        assert_raises(AuthException, self.aaa.delete_user, 'phil')


    def test_delete_nonexistent_user(self):
        assert_raises(AAAException, self.aaa.delete_user, 'not_an_user')


    def test_delete_user(self):
        assert len(self.aaa._store.users) == 1, repr(self.aaa._store.users)
        self.aaa.delete_user('admin')
        assert len(self.aaa._store.users) == 0, repr(self.aaa._store.users)
        assert 'admin' not in self.aaa._store.users



    def test_list_users(self):
        users = list(self.aaa.list_users())
        assert len(users) == 1, "Incorrect. Users are: %s" % repr(self.aaa._store.users)

    def test_iteritems_on_users(self):
        for k, v in self.aaa._store.users.iteritems():
            #assert isinstance(k, str)
            #assert isinstance(v, dict)
            expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date',
                'desc', 'last_login'))
            dkeys = set(v.keys())

            extra = dkeys - expected_dkeys
            assert not extra, "Unexpected extra keys: %s" % repr(extra)

            missing = expected_dkeys - dkeys
            assert not missing, "Missing keys: %s" % repr(missing)


    def test_failing_login(self):
        login = self.aaa.login('phil', 'hunter123')
        assert login == False, "Login must fail"
        assert cookie_name == None


    def test_login_nonexistent_user_empty_password(self):
        login = self.aaa.login('IAmNotHome', '')
        assert login == False, "Login must fail"
        assert cookie_name == None


    def test_login_existing_user_empty_password(self):
        self.aaa.create_user('phil', 'user', 'hunter123')
        assert 'phil' in self.aaa._store.users
        assert self.aaa._store.users['phil']['role'] == 'user'
        login = self.aaa.login('phil', '')
        assert login == False, "Login must fail"
        assert cookie_name == None


    def test_create_and_validate_user(self):
        assert len(self.aaa._store.users) == 1, "Only the admin user should be present"
        self.aaa.create_user('phil', 'user', 'hunter123')
        assert len(self.aaa._store.users) == 2, "Two users should be present"
        assert 'phil' in self.aaa._store.users
        assert self.aaa._store.users['phil']['role'] == 'user'
        login = self.aaa.login('phil', 'hunter123')
        assert login == True, "Login must succeed"
        assert cookie_name == 'phil'

    def test_create_user_login_logout(self):
        assert 'phil' not in self.aaa._store.users
        self.aaa.create_user('phil', 'user', 'hunter123')
        assert 'phil' in self.aaa._store.users
        login = self.aaa.login('phil', 'hunter123')
        assert login == True, "Login must succeed"
        assert cookie_name == 'phil'
        try:
            self.aaa.logout(fail_redirect='/failed_logout')
        except bottle.HTTPResponse, e:
            assert_is_redirect(e, 'login')

        assert cookie_name == None

    def test_modify_user_using_overwrite(self):
        self.aaa.create_user('phil', 'user', 'hunter123')
        assert 'phil' in self.aaa._store.users
        u = self.aaa._store.users['phil']
        u.update(role='editor')
        self.aaa._store.users['phil'] = u
        assert self.aaa._store.users['phil']['role'] == 'editor'

    def test_modify_user(self):
        self.aaa.create_user('phil', 'user', 'hunter123')
        self.aaa._store.users['phil']['role'] = 'editor'
        assert self.aaa._store.users['phil']['role'] == 'editor', self.aaa._store.users['phil']


    def test_modify_user_using_local_change(self):
        self.aaa.create_user('phil', 'user', 'hunter123')
        u = self.aaa._store.users['phil']
        u['role'] = 'editor'
        assert u['role'] == 'editor', repr(u)
        assert self.aaa._store.users['phil']['role'] == 'editor'


    def test_require_failing_username(self):
        # The user exists, but I'm 'admin'
        self.aaa.create_user('phil', 'user', 'hunter123')
        assert_raises(AuthException, self.aaa.require, username='phil')


    def test_require_nonexistent_username(self):
        assert_raises(AAAException, self.aaa.require, username='no_such_user')


    def test_require_failing_role_fixed(self):
        assert_raises(AuthException, self.aaa.require, role='user', fixed_role=True)


    @raises(AAAException)
    def test_require_missing_parameter(self):
        self.aaa.require(fixed_role=True)


    def test_require_nonexistent_role(self):
        assert_raises(AAAException, self.aaa.require, role='clown')

    def test_require_failing_role(self):
        # Requesting level >= 100
        assert_raises(AuthException, self.aaa.require, role='special')


    def test_successful_require_role(self):
        self.aaa.require(username='admin')
        self.aaa.require(username='admin', role='admin')
        self.aaa.require(username='admin', role='admin', fixed_role=True)
        self.aaa.require(username='admin', role='user')


    def test_authenticated_is_not_anonymous(self):
        assert not self.aaa.user_is_anonymous


    def test_update_nonexistent_role(self):
        assert_raises(AAAException, self.aaa.current_user.update, role='clown')


    @raises(AAAException)
    def test_update_nonexistent_user(self):
        self.aaa._store.users.pop('admin')
        self.aaa.current_user.update(role='user')


    def test_update_role(self):
        self.aaa.current_user.update(role='user')
        assert self.aaa._store.users['admin']['role'] == 'user'


    def test_update_pwd(self):
        self.aaa.current_user.update(pwd='meow')


    def test_update_email(self):
        print self.aaa._store.users['admin']
        self.aaa.current_user.update(email_addr='foo')
        assert self.aaa._store.users['admin']['email_addr'] == 'foo', self.aaa._store.users['admin']


    @raises(AuthException)
    def test_get_current_user_nonexistent(self):
        # The current user 'admin' is not in the user table
        self.aaa._store.users.pop('admin')
        self.aaa.current_user


    def test_get_nonexistent_user(self):
        assert self.aaa.user('nonexistent_user') is None


    def test_get_user_description_field(self):
        admin = self.aaa.user('admin')
        for field in ['description', 'email_addr']:
            assert field in admin.__dict__


    def test_register_no_user(self):
        assert_raises(AssertionError, self.aaa.register, None, 'pwd', 'a@a.a')


    def test_register_no_pwd(self):
        assert_raises(AssertionError, self.aaa.register, 'foo', None, 'a@a.a')


    def test_register_no_email(self):
        assert_raises(AssertionError, self.aaa.register, 'foo', 'pwd', None)


    def test_register_already_existing(self):
        assert_raises(AAAException, self.aaa.register, 'admin', 'pwd', 'a@a.a')


    def test_register_no_role(self):
        assert_raises(AAAException, self.aaa.register, 'foo', 'pwd', 'a@a.a', role='clown')


    def test_register_role_too_high(self):
        assert_raises(AAAException, self.aaa.register, 'foo', 'pwd', 'a@a.a', role='admin')


    def test_register_valid(self):
        self.aaa.mailer.send_email = mock.Mock()
        self.aaa.register('foo', 'pwd', 'email@email.org', role='user',
            email_template='examples/views/registration_email.tpl'
        )
        assert self.aaa.mailer.send_email.called
        r = self.aaa._store.pending_registrations
        assert len(r) == 1
        reg_code = list(r)[0]
        assert r[reg_code]['username'] == 'foo'
        assert r[reg_code]['email_addr'] == 'email@email.org'
        assert r[reg_code]['role'] == 'user'


    def test_validate_registration_no_code(self):
        assert_raises(AAAException, self.aaa.validate_registration, 'not_a_valid_code')

    def test_validate_registration(self):
        self.aaa.mailer.send_email = mock.Mock()
        self.aaa.register('foo', 'pwd', 'email@email.org', role='user',
            email_template='examples/views/registration_email.tpl'
        )
        r = self.aaa._store.pending_registrations
        reg_code = list(r)[0]

        assert len(self.aaa._store.users) == 1, "Only the admin user should be present"
        self.aaa.validate_registration(reg_code)
        assert len(self.aaa._store.users) == 2, "The new user should be present"
        assert len(self.aaa._store.pending_registrations) == 0, \
            "The registration entry should be removed"



    @raises(AAAException)
    def test_send_password_reset_email_no_data(self):
        self.aaa.send_password_reset_email()

    @raises(AAAException)
    def test_send_password_reset_email_incorrect_data(self):
        self.aaa.send_password_reset_email(username='NotThere', email_addr='NoEmail')

    @raises(AAAException)
    def test_send_password_reset_email_incorrect_data2(self):
        # The username is valid but the email address is not matching
        self.aaa.send_password_reset_email(username='admin', email_addr='NoEmail')

    @raises(AAAException)
    def test_send_password_reset_email_only_incorrect_email(self):
        self.aaa.send_password_reset_email(email_addr='NoEmail')

    @raises(AAAException)
    def test_send_password_reset_email_only_incorrect_username(self):
        self.aaa.send_password_reset_email(username='NotThere')

    def test_send_password_reset_email_only_email(self):
        self.aaa.mailer.send_email = mock.Mock()
        self.aaa.send_password_reset_email(email_addr='admin@localhost.local',
            email_template='examples/views/password_reset_email')

    def test_send_password_reset_email_only_username(self):
        self.aaa.mailer.send_email = mock.Mock()
        self.aaa.send_password_reset_email(username='admin',
            email_template='examples/views/password_reset_email')



    @raises(AuthException)
    def test_perform_password_reset_invalid(self):
        self.aaa.reset_password('bogus', 'newpassword')


    @raises(AuthException)
    def test_perform_password_reset_timed_out(self):
        self.aaa.password_reset_timeout = 0
        token = self.aaa._reset_code('admin', 'admin@localhost.local')
        self.aaa.reset_password(token, 'newpassword')


    @raises(AAAException)
    def test_perform_password_reset_nonexistent_user(self):
        token = self.aaa._reset_code('admin_bogus', 'admin@localhost.local')
        self.aaa.reset_password(token, 'newpassword')


    # The following test should fail
    # an user can change the password reset timestamp by b64-decoding the token,
    # editing the field and b64-encoding it
    @SkipTest
    @raises(AuthException)
    def test_perform_password_reset_mangled_timestamp(self):
        token = self.aaa._reset_code('admin', 'admin@localhost.local')
        username, email_addr, tstamp, h = b64decode(token).split(':', 3)
        tstamp = str(int(tstamp) + 100)
        mangled_token = ':'.join((username, email_addr, tstamp, h))
        mangled_token = b64encode(mangled_token)
        self.aaa.reset_password(mangled_token, 'newpassword')


    @raises(AuthException)
    def test_perform_password_reset_mangled_username(self):
        token = self.aaa._reset_code('admin', 'admin@localhost.local')
        username, email_addr, tstamp, h = b64decode(token).split(':', 3)
        username += "mangled_username"
        mangled_token = ':'.join((username, email_addr, tstamp, h))
        mangled_token = b64encode(mangled_token)
        self.aaa.reset_password(mangled_token, 'newpassword')


    @raises(AuthException)
    def test_perform_password_reset_mangled_email(self):
        token = self.aaa._reset_code('admin', 'admin@localhost.local')
        username, email_addr, tstamp, h = b64decode(token).split(':', 3)
        email_addr += "mangled_email"
        mangled_token = ':'.join((username, email_addr, tstamp, h))
        mangled_token = b64encode(mangled_token)
        self.aaa.reset_password(mangled_token, 'newpassword')


    def test_perform_password_reset(self):
        token = self.aaa._reset_code('admin', 'admin@localhost.local')
        self.aaa.reset_password(token, 'newpassword')


