from nose.tools import assert_raises, with_setup
from os import listdir, mkdir
from tempfile import mkdtemp
from time import time
import shutil

from cork import Cork, AAAException, AuthException

testdir = None # Test directory
aaa = None # global Cork instance
cookie_name = None # global variable to track cookie status

class MockedAdminCork(Cork):
    """Mocked module where the current user is always 'admin'"""
    @property
    def _beaker_session_username(self):
        return 'admin'

    def _setup_cookie(self, username):
        global cookie_name
        print 'setting cookie'
        cookie_name = username

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
    global cookie_name
    setup_dir()
    aaa = MockedAdminCork(testdir)
    aaa._users['admin'] = {'role': 'admin', 'email': 'foo@foo.org'}
    aaa._roles = {'special': 200, 'admin': 100, 'user': 50}
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
def test_delete_nonexistent_role():
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
def test_delete_nonexistent_user():
    assert_raises(AAAException, aaa.delete_user, 'not_an_user')

@with_setup(setup_mockedadmin, teardown_dir)
def test_delete_user():
    assert len(aaa._users) == 1, repr(aaa._users)
    aaa.delete_user('admin')
    assert len(aaa._users) == 0, repr(aaa._users)
    fname = "%s/%s.json" % (aaa._directory, aaa._users_fname)
    with open(fname) as f:
        data = f.read()
        assert 'admin' not in data, "'admin' must not be in %s" % repr(data)


@with_setup(setup_mockedadmin, teardown_dir)
def test_failing_login():
    login = aaa.login('phil', 'hunter123')
    assert login == False, "Login must fail"
    global cookie_name
    assert cookie_name == None

@with_setup(setup_mockedadmin, teardown_dir)
def test_create_and_validate_user():
    aaa.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa._users
    assert aaa._users['phil']['role'] == 'user'
    login = aaa.login('phil', 'hunter123')
    assert login == True, "Login must succed"
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
def test_update_nonexistent_role():
    assert_raises(AAAException, aaa.current_user.update, role='clown')

@with_setup(setup_mockedadmin, teardown_dir)
def test_update_role():
    aaa.current_user.update(role='user')
    assert aaa._users['admin']['role'] == 'user'

@with_setup(setup_mockedadmin, teardown_dir)
def test_update_email():
    aaa.current_user.update(email_addr='foo')
    assert aaa._users['admin']['email'] == 'foo'











