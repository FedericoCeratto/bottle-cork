# Cork - Authentication module for the Flask web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Functional test using Json backend
#
# Requires WebTest http://webtest.pythonpaste.org/
#
# Run as: nosetests functional_test.py
#

from nose import SkipTest
from webtest import TestApp
from datetime import timedelta
import shutil
import os

import testutils
from cork import FlaskCork

REDIR = 302

class Test(testutils.WebFunctional):

    def create_app_instance(self):
        """create TestApp instance"""
        assert self._app is None
        import simple_webapp_flask
        self._bottle_app = simple_webapp_flask.app
        self._app = TestApp(self._bottle_app)
        #simple_webapp_flask.flask.session.secret_key = 'bogus'
        simple_webapp_flask.SECRET_KEY = 'bogus'
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
        self._tmpdir = testutils.pick_temp_directory()
        assert self._tmpdir is not None
        self.populate_temp_dir()

        # change to the temporary test directory
        # cork relies on this being the current directory
        os.chdir(self._tmpdir)
        self.create_app_instance()
        self._app.reset()
        print("Reset done")
        #self._default_timeout = self._app.app.options['timeout']
        self._default_timeout = 30
        #FIXME: reset
        print("Setup completed")


    def login_as_admin(self):
        """perform log in"""
        assert self._app is not None
        assert 'session' not in self._app.cookies, "Unexpected cookie found"

        self.assert_200('/login', 'Please insert your credentials')
        assert 'session' not in self._app.cookies, "Unexpected cookie found"

        self.assert_redirect('/admin', '/sorry_page')

        self.assert_200('/user_is_anonymous', 'True')
        assert 'session' not in self._app.cookies, "Unexpected cookie found"

        post = {'username': 'admin', 'password': 'admin'}
        self.assert_redirect('/login', '/', post=post)
        assert 'session' in self._app.cookies, "Cookie not found"

        import bottle
        session = bottle.request.environ.get('beaker.session')
        print("Session from func. test", repr(session))

        self.assert_200('/login', 'Please insert your credentials')


        p = self._app.get('/admin')
        assert 'Welcome' in p.body, repr(p)

        p = self._app.get('/my_role', status=200)
        assert p.status_int == 200
        assert p.body == 'admin', "Sta"

        print("Login performed")


    def test_functional_expiration(self):
        self.login_as_admin()
        r = self._app.get('/admin')
        assert r.status_int == 200, repr(r)

        # change the cookie expiration in order to expire it
        saved = self._bottle_app.permanent_session_lifetime
        try:
            self._bottle_app.permanent_session_lifetime = timedelta(seconds=-1)

            # change the cookie expiration in order to expire it
            self._app.app.options['timeout'] = 0

            assert self._app.get('/admin').status_int == REDIR, "The cookie should have expired"


        finally:
            self._bottle_app.permanent_session_lifetime = saved


