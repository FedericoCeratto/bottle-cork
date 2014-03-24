# Cork - Authentication module for the Bottle web framework
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
from webtest import TestApp
import shutil
import os

import testutils
from cork import Cork

REDIR = 302

class Test(testutils.WebFunctional):

    def create_app_instance(self):
        """create TestApp instance"""
        assert self._app is None
        import simple_webapp_decorated
        self._bottle_app = simple_webapp_decorated.app
        env = {'REMOTE_ADDR': '127.0.0.1'}
        self._app = TestApp(self._bottle_app, extra_environ=env)
        print("Test App created")



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
        assert p.status_int == 200
        assert p.body == 'admin', "Sta"

        print("Login performed")


    def test_functional_expiration(self):
        self.login_as_admin()
        r = self._app.get('/admin')
        assert r.status == '200 OK', repr(r)
        # change the cookie expiration in order to expire it
        self._app.app.options['timeout'] = 0
        assert self._app.get('/admin').status_int == REDIR, "The cookie should have expired"

