# Cork - Authentication module for tyyhe Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Functional test for decorators-based webapp using Json backend
#
# Requires WebTest http://webtest.pythonpaste.org/
#
# Run as: nosetests tests/test_functional_decorated.py
#

from nose import SkipTest
from time import time
from datetime import datetime
from webtest import TestApp
import glob
import json
import os
import shutil

import testutils
from cork import Cork

REDIR = '302 Found'

class Test(object):
    def __init__(self):
        self._tmpdir = None
        self._tmproot = None
        self._app = None
        self._starting_dir = os.getcwd()

    def remove_temp_dir(self):
        p = os.path.join(self._tmproot, 'cork_functional_test_wd')
        for f in glob.glob('%s*' % p):
            #shutil.rmtree(f)
            pass

    @classmethod
    def setUpClass(cls):
        print("Setup class")

    def populate_temp_dir(self):
        """populate the temporary test dir"""
        assert self._tmproot is not None
        assert self._tmpdir is None

        tstamp = str(time())[5:]
        self._tmpdir = os.path.join(self._tmproot, "cork_functional_test_wd_%s" % tstamp)

        try:
            os.mkdir(self._tmpdir)
        except OSError:
            # The directory is already there, purge it
            print("Deleting %s" % self._tmpdir)
            shutil.rmtree(self._tmpdir)
            os.mkdir(self._tmpdir)

            #p = os.path.join(self._tmproot, 'cork_functional_test_wd')
            #for f in glob.glob('%s*' % p):
            #    shutil.rmtree(f)

        # copy the needed files
        shutil.copytree(
            os.path.join(self._starting_dir, 'tests/example_conf'),
            os.path.join(self._tmpdir, 'example_conf')
        )
        shutil.copytree(
            os.path.join(self._starting_dir, 'tests/views'),
            os.path.join(self._tmpdir, 'views')
        )

        # change to the temporary test directory
        # cork relies on this being the current directory
        os.chdir(self._tmpdir)

        print("Test directory set up")

    def create_app_instance(self):
        """create TestApp instance"""
        assert self._app is None
        import simple_webapp_decorated
        self._bottle_app = simple_webapp_decorated.app
        env = {'REMOTE_ADDR': '127.0.0.1'}
        self._app = TestApp(self._bottle_app, extra_environ=env)
        print("Test App created")

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
        #if self._tmproot is not None:
        #    testutils.purge_temp_directory(self._tmproot)

        self._app.app.options['timeout'] = self._default_timeout
        self._app = None
        self._tmproot = None
        self._tmpdir = None
        print("Teardown done")

    def setup(self):
        # create test dir and populate it using the example files

        # save the directory where the unit testing has been run
        if self._starting_dir is None:
            self._starting_dir = os.getcwd()

        # create json files to be used by Cork
        self._tmproot = testutils.pick_temp_directory()
        assert self._tmproot is not None

        # purge the temporary test directory
        self.remove_temp_dir()

        self.populate_temp_dir()
        self.create_app_instance()
        self._app.reset()
        print("Reset done")
        self._default_timeout = self._app.app.options['timeout']
        print("Setup completed")

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

    def login_as_admin(self):
        """perform log in"""
        assert self._app is not None
        assert 'beaker.session.id' not in self._app.cookies, "Unexpected cookie found"

        self.assert_200('/login', 'Please insert your credentials')
        assert 'beaker.session.id' not in self._app.cookies, "Unexpected cookie found"

        self.assert_redirect('/admin', '/sorry_page')

        self.assert_200('/user_is_anonymous', 'True')
        assert 'beaker.session.id' not in self._app.cookies, "Unexpected cookie found"

        post = {'username': 'admin', 'password': 'admin'}
        self.assert_redirect('/login', '/', post=post)
        assert 'beaker.session.id' in self._app.cookies, "Cookie not found"

        self.assert_200('/my_role', 'admin')
        assert 'beaker.session.id' in self._app.cookies, "Cookie not found"

        import bottle
        session = bottle.request.environ.get('beaker.session')
        print("Session from func. test", repr(session))

        self.assert_200('/login', 'Please insert your credentials')


        p = self._app.get('/admin')
        assert 'Welcome' in p.body, repr(p)

        p = self._app.get('/my_role', status=200)
        assert p.status == '200 OK'
        assert p.body == 'admin', "Sta"

        print("Login performed")



    def test_functional_login(self):
        assert self._app
        self._app.get('/admin', status=302)
        self._app.get('/my_role', status=302)

        self.login_as_admin()

        # fetch a page successfully
        r = self._app.get('/admin')
        assert r.status == '200 OK', repr(r)

    def test_login_existing_user_none_password(self):
        p = self._app.post('/login', {'username': 'admin', 'password': None})
        assert p.status == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_nonexistent_user_none_password(self):
        p = self._app.post('/login', {'username': 'IAmNotHere', 'password': None})
        assert p.status == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_existing_user_empty_password(self):
        p = self._app.post('/login', {'username': 'admin', 'password': ''})
        assert p.status == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_nonexistent_user_empty_password(self):
        p = self._app.post('/login', {'username': 'IAmNotHere', 'password': ''})
        assert p.status == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_login_existing_user_wrong_password(self):
        p = self._app.post('/login', {'username': 'admin', 'password': 'BogusPassword'})
        assert p.status == REDIR, "Redirect expected"
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

    def test_functional_login_logout(self):
        # Incorrect login
        p = self._app.post('/login', {'username': 'admin', 'password': 'BogusPassword'})
        assert p.status == REDIR
        assert p.location == 'http://localhost:80/login', \
            "Incorrect redirect to %s" % p.location

        # log in and get a cookie
        p = self._app.post('/login', {'username': 'admin', 'password': 'admin'})
        assert p.status == REDIR
        assert p.location == 'http://localhost:80/', \
            "Incorrect redirect to %s" % p.location

        self.assert_200('/my_role', 'admin')

        # fetch a page successfully
        assert self._app.get('/admin').status == '200 OK', "Admin page should be served"

        # log out
        assert self._app.get('/logout').status == REDIR

        # drop the cookie
        self._app.reset()
        assert self._app.cookies == {}, "The cookie should be gone"

        # fetch the same page, unsuccessfully
        assert self._app.get('/admin').status == REDIR

    def test_functional_user_creation_login_deletion(self):
        assert self._app.cookies == {}, "The cookie should be not set"

        # Log in as Admin
        p = self._app.post('/login', {'username': 'admin', 'password': 'admin'})
        assert p.status == REDIR
        assert p.location == 'http://localhost:80/', \
            "Incorrect redirect to %s" % p.location

        self.assert_200('/my_role', 'admin')

        # Create new user
        username = 'BrandNewUser'
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
        assert self._app.get('/logout').status == REDIR
        self._app.reset()
        assert self._app.cookies == {}, "The cookie should be gone"

        # Log in as user
        p = self._app.post('/login', {'username': username, 'password': password})
        assert p.status == REDIR and p.location == 'http://localhost:80/', \
            "Failed user login"

        # log out
        assert self._app.get('/logout').status == REDIR
        self._app.reset()
        assert self._app.cookies == {}, "The cookie should be gone"

        # Log in as user with empty password
        p = self._app.post('/login', {'username': username, 'password': ''})
        assert p.status == REDIR and p.location == 'http://localhost:80/login', \
            "User login should fail"
        assert self._app.cookies == {}, "The cookie should not be set"

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

    def test_functionalxxx(self):
        assert self._app is not None

    def test_functional_expiration(self):
        self.login_as_admin()
        r = self._app.get('/admin')
        assert r.status == '200 OK', repr(r)
        # change the cookie expiration in order to expire it
        self._app.app.options['timeout'] = 0
        assert self._app.get('/admin').status == REDIR, "The cookie should have expired"
