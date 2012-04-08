from nose.tools import assert_raises, with_setup
from os import listdir, mkdir
from tempfile import mkdtemp
from time import time
import shutil

from cork import Cork, AAAException, AuthException

testdir = None # Test directory
aaa = None # global Cork instance

class MockedAdminCork(Cork):
    @property
    def _beaker_session_username(self):
        return 'admin'

def setup_dir():
    """Setup test directory with empty JSON files"""
    global testdir
    tstamp = "%f" % time()
    testdir = "/dev/shm/fl_%s" % tstamp
    mkdir(testdir)
    with open("%s/users.json" % testdir, 'w') as f:
        f.write('{}')
    with open("%s/roles.json" % testdir, 'w') as f:
        f.write('{}')
    print "setup done in %s" % testdir

def setup_mockedadmin():
    """Setup test directory and a MockedAdminCork instance"""
    global aaa
    setup_dir()
    aaa = MockedAdminCork(testdir)
    aaa._users['admin'] = {'role': 'admin', 'email': 'foo@foo.org'}
    aaa._roles = {'admin': 100, 'user': 50, 'readonly': 20}

def teardown_dir():
    global testdir
    if testdir:
        shutil.rmtree(testdir)
        testdir = None

@with_setup(setup_dir, teardown_dir)
def test_init():
    aaa = Cork(testdir)

@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_create_role():
    aaa._roles['admin'] = 10 # lower admin level
    assert_raises(AuthException, aaa.create_role, 'user', 33)

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_existing_role():
    assert_raises(AAAException, aaa.create_role, 'user', 33)

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_role():
    assert len(aaa._roles) == 3, repr(aaa._roles)
    aaa.create_role('user33', 33)
    assert len(aaa._roles) == 4, repr(aaa._roles)
    fname = "%s/%s.json" % (aaa._directory, aaa._roles_fname)
    with open(fname) as f:
        data = f.read()
        assert 'user33' in data, repr(data)


@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_delete_role():
    aaa._roles['admin'] = 10 # lower admin level
    assert_raises(AuthException, aaa.delete_role, 'user')

@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_nonexisting_role():
    assert_raises(AAAException, aaa.delete_role, 'user123')

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_delete_role():
    assert len(aaa._roles) == 3, repr(aaa._roles)
    aaa.create_role('user33', 33)
    assert len(aaa._roles) == 4, repr(aaa._roles)
    fname = "%s/%s.json" % (aaa._directory, aaa._roles_fname)
    with open(fname) as f:
        data = f.read()
        assert 'user33' in data, repr(data)
    assert aaa._roles['user33'] == 33
    aaa.delete_role('user33')
    assert len(aaa._roles) == 3, repr(aaa._roles)


@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_create_user():
    aaa._roles['admin'] = 10 # lower admin level
    assert_raises(AuthException, aaa.create_user, 'phil', 'user', 'hunter123')

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_existing_user():
    assert_raises(AAAException, aaa.create_user, 'admin', 'admin', 'bogus')

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_user():
    assert len(aaa._users) == 1, repr(aaa._users)
    aaa.create_user('phil', 'user', 'hunter123')
    assert len(aaa._users) == 2, repr(aaa._users)
    fname = "%s/%s.json" % (aaa._directory, aaa._users_fname)
    with open(fname) as f:
        data = f.read()
        assert 'phil' in data, repr(data)


@with_setup(setup_mockedadmin, teardown_dir)
def test_unauth_delete_user():
    aaa._roles['admin'] = 10 # lower admin level
    assert_raises(AuthException, aaa.delete_user, 'phil')

@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_nonexisting_user():
    assert_raises(AAAException, aaa.delete_user, 'not_an_user')

@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_user():
    assert len(aaa._users) == 1, repr(aaa._users)
    aaa.delete_user('admin')
    assert len(aaa._users) == 0, repr(aaa._users)
    fname = "%s/%s.json" % (aaa._directory, aaa._users_fname)
    with open(fname) as f:
        data = f.read()
        assert 'admin' not in data, repr(data)
