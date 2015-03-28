# -*- coding: utf-8 -*
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
import json
import mock
import tempfile
from base64 import b64encode, b64decode
from pytest import raises
import pytest

from datetime import datetime
from cork import Cork, AAAException, AuthException

SkipTest = pytest.mark.skipif(True, reason='skipped')
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










REDIR = 302



class WebFunctional(object):

    def __init__(self):
        self._tmpdir = None
        self._app = None
        self._starting_dir = os.getcwd()

    def populate_conf_directory(self):
        """Populate a directory with valid configuration files, to be run just once
        The files are not modified by each test
        """
        self._tmpdir = os.path.join(self._tmproot, "cork_functional_test_source")

        # only do this once, as advertised
        if os.path.exists(self._tmpdir):
            return

        os.mkdir(self._tmpdir)
        os.mkdir(self._tmpdir + "/example_conf")

        cork = Cork(os.path.join(self._tmpdir, "example_conf"), initialize=True)

        cork._store.roles['admin'] = 100
        cork._store.roles['editor'] = 60
        cork._store.roles['user'] = 50
        cork._store.save_roles()

        tstamp = str(datetime.utcnow())
        username = password = 'admin'
        cork._store.users[username] = {
            'role': 'admin',
            'hash': cork._hash(username, password),
            'email_addr': username + '@localhost.local',
            'desc': username + ' test user',
            'creation_date': tstamp
        }
        username = password = ''
        cork._store.users[username] = {
            'role': 'user',
            'hash': cork._hash(username, password),
            'email_addr': username + '@localhost.local',
            'desc': username + ' test user',
            'creation_date': tstamp
        }
        cork._store.save_users()

    def populate_temp_dir(self):
        """populate the temporary test dir"""
        assert self._tmpdir is not None

        # copy the needed files
        shutil.copytree(
            os.path.join(self._starting_dir, 'tests/example_conf'),
            os.path.join(self._tmpdir, 'example_conf')
        )
        shutil.copytree(
            os.path.join(self._starting_dir, 'tests/views'),
            os.path.join(self._tmpdir, 'views')
        )

        print("Test directory set up")

    def remove_temp_dir(self):
        p = os.path.join(self._tmproot, 'cork_functional_test_wd')
        for f in glob.glob('%s*' % p):
            #shutil.rmtree(f)
            pass


    def teardown(self):
        print("Doing teardown")
        try:
            self._app.post('/logout')
        except:
            pass

        # drop the cookie
        self._app.reset()
        assert 'beaker.session.id' not in self._app.cookies, "Unexpected cookie found"
        # drop the cookie
        self._app.reset()

        #assert self._app.get('/admin').status != '200 OK'
        os.chdir(self._starting_dir)

        self._app.app.options['timeout'] = self._default_timeout
        self._app = None
        shutil.rmtree(self._tmpdir)
        self._tmpdir = None
        print("Teardown done")

    def setup(self):
        # create test dir and populate it using the example files

        # save the directory where the unit testing has been run
        if self._starting_dir is None:
            self._starting_dir = os.getcwd()

        # create json files to be used by Cork
        self._tmpdir = pick_temp_directory()
        assert self._tmpdir is not None
        self.populate_temp_dir()

        # change to the temporary test directory
        # cork relies on this being the current directory
        os.chdir(self._tmpdir)
        self.create_app_instance()
        self._app.reset()
        print("Reset done")
        self._default_timeout = self._app.app.options['timeout']
        print("Setup completed")



    # Utility functions


    def assert_200(self, path, match):
        """Assert that a page returns 200"""
        p = self._app.get(path)
        assert p.status_int == 200, "Status: %d, Location: %s" % \
            (p.status_int, p.location)

        if match is not None:
            assert match in p.body, "'%s' not found in body: '%s'" % (match, p.body)

        return p

    def assert_redirect(self, page, redir_page, post=None):
        """Assert that a page redirects to another one"""

        # perform GET or POST
        if post is None:
            p = self._app.get(page, status=302)
        else:
            assert isinstance(post, dict)
            p = self._app.post(page, post, status=302)

        dest = p.location.split(':80/')[-1]
        dest = "/%s" % dest
        assert dest == redir_page, "%s redirects to %s instead of %s" % \
            (page, dest, redir_page)

        return p

    # Tests

    def test_functional_login(self):
        assert self._app
        self._app.get('/admin', status=302)
        self._app.get('/my_role', status=302)

        self.login_as_admin()

        # fetch a page successfully
        r = self._app.get('/admin')
        assert r.status_int == 200, repr(r)

    def test_login_existing_user_none_password(self):
        p = self._app.post('/login', {'username': 'admin', 'password': None})
        assert p.status_int == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_nonexistent_user_none_password(self):
        p = self._app.post('/login', {'username': 'IAmNotHere', 'password': None})
        assert p.status_int == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_existing_user_empty_password(self):
        p = self._app.post('/login', {'username': 'admin', 'password': ''})
        assert p.status_int == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_nonexistent_user_empty_password(self):
        p = self._app.post('/login', {'username': 'IAmNotHere', 'password': ''})
        assert p.status_int == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_existing_user_wrong_password(self):
        p = self._app.post('/login', {'username': 'admin', 'password': 'BogusPassword'})
        assert p.status_int == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_functional_login_logout(self):
        # Incorrect login
        p = self._app.post('/login', {'username': 'admin', 'password': 'BogusPassword'})
        assert p.status_int == REDIR
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

        # log in and get a cookie
        p = self._app.post('/login', {'username': 'admin', 'password': 'admin'})
        assert p.status_int == REDIR
        assert p.location == 'http://localhost:80/', \
            "Incorrect redirect to %s" % p.location

        self.assert_200('/my_role', 'admin')

        # fetch a page successfully
        assert self._app.get('/admin').status_int == 200, "Admin page should be served"

        # log out
        assert self._app.get('/logout').status_int == REDIR

        # drop the cookie
        self._app.reset()
        assert self._app.cookies == {}, "The cookie should be gone"

        # fetch the same page, unsuccessfully
        assert self._app.get('/admin').status_int == REDIR

    def test_functional_user_creation_login_deletion(self):
        assert self._app.cookies == {}, "The cookie should be not set"

        # Log in as Admin
        p = self._app.post('/login', {'username': 'admin', 'password': 'admin'})
        assert p.status_int == REDIR
        assert p.location == 'http://localhost:80/', \
            "Incorrect redirect to %s" % p.location

        self.assert_200('/my_role', 'admin')

        username = 'BrandNewUser'

        # Delete the user
        ret = self._app.post('/delete_user', {
            'username': username,
        })

        # Create new user
        password = '42IsTheAnswer'
        ret = self._app.post('/create_user', {
            'username': username,
            'password': password,
            'role': 'user'
        })
        retj = json.loads(ret.body)
        assert 'ok' in retj and retj['ok'] == True, "Failed user creation: %s" % \
            ret.body

        # log out
        assert self._app.get('/logout').status_int == REDIR
        self._app.reset()
        assert self._app.cookies == {}, "The cookie should be gone"

        # Log in as user
        p = self._app.post('/login', {'username': username, 'password': password})
        assert p.status_int == REDIR and p.location == 'http://localhost:80/', \
            "Failed user login"

        # log out
        assert self._app.get('/logout').status_int == REDIR
        self._app.reset()
        assert self._app.cookies == {}, "The cookie should be gone"

        # Log in as user with empty password
        p = self._app.post('/login', {'username': username, 'password': ''})
        assert p.status_int == REDIR and p.location == 'http://localhost:80/login', \
            "User login should fail"
        assert self._app.cookies == {}, "The cookie should not be set"

        # Log in as Admin, again
        p = self._app.post('/login', {'username': 'admin', 'password': 'admin'})
        assert p.status_int == REDIR
        assert p.location == 'http://localhost:80/', \
            "Incorrect redirect to %s" % p.location

        self.assert_200('/my_role', 'admin')

        # Delete the user
        ret = self._app.post('/delete_user', {
            'username': username,
        })
        retj = json.loads(ret.body)
        assert 'ok' in retj and retj['ok'] == True, "Failed user deletion: %s" % \
            ret.body

    #def test_functional_user_registration(self):
    #    assert self._app.cookies == {}, "The cookie should be not set"
    #
    #    # Register new user
    #    username = 'BrandNewUser'
    #    password = '42IsTheAnswer'
    #    ret = self._app.post('/register', {
    #        'username': username,
    #        'password': password,
    #        'email_address': 'test@localhost.local'
    #    })


    def test_functional_expiration(self):
        raise NotImplementedError

