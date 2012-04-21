#
# Functional test
#
# Requires WebTest http://webtest.pythonpaste.org/
# sudo aptitude install python-webtest
#
# Run as: nosetests functional_test.py
#

from nose.tools import assert_raises, raises, with_setup
from time import time
from webtest import TestApp
import glob
import os
import shutil

import simple_webapp

REDIR = '302 Found'
app = None
tmpdir = None

def setup_app():
    # create test dir and populate it using the example files
    global tmpdir
    tstamp = str(time())[5:]
    tmpdir = "/dev/shm/cork_functional_test_%s" % tstamp
    os.mkdir(tmpdir)
    os.mkdir(tmpdir + '/example_conf')
    # copy the needed files
    globs = ['example_conf/*.json']
    for g in globs:
        for f in glob.glob(g):
            shutil.copy(f, tmpdir)

    # create global TestApp instance
    global app
    app = TestApp(simple_webapp.app)

def login():
    """run setup_app and log in"""
    global app
    setup_app()
    p = app.post('/login', {'user': 'admin', 'pwd': 'admin'})

def teardown():
    global tmpdir
    if tmpdir is not None:
        assert tmpdir.startswith('/dev/shm/cork_functional_test_')
        shutil.rmtree(tmpdir)
        tmpdir = None
    app = None


@with_setup(login, teardown)
def test_functional_login():
    # fetch a page successfully
    assert app.get('/admin').status == '200 OK'

@with_setup(setup_app, teardown)
def test_functional_login_logout():

    # log in and get a cookie
    p = app.post('/login', {'user': 'admin', 'pwd': 'admin'})
    assert p.status == REDIR

    # fetch a page successfully
    assert app.get('/admin').status == '200 OK'

    # log out
    assert app.get('/logout').status == REDIR

    # drop the cookie
    app.reset()
    assert app.cookies == {}, "The cookie should be gone"

    # fetch the same page, unsuccessfully
    assert app.get('/admin').status == REDIR

@with_setup(login, teardown)
def test_functional_expiration():
    assert app.get('/admin').status == '200 OK'
    # change the cookie expiration in order to expire it
    app.app.options['timeout'] = 0
    assert app.get('/admin').status == REDIR, "The cookie should have expired"

