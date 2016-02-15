# -*- coding: utf-8 -*
# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Functional testing - test the Cork module against diffent database backends

from base64 import b64encode, b64decode
from pytest import raises
import bottle
import mock
import os
import pytest
import time

from cork import Cork, AAAException, AuthException
from cork.backends import JsonBackend
from cork.backends import MongoDBBackend
from cork.backends import SQLiteBackend
from cork.backends import SqlAlchemyBackend
from conftest import assert_is_redirect

try:
    import pymongo
    pymongo_available = True
except ImportError:
    pymongo_available = False

try:
    import MySQLdb
    MySQLdb_available = True
except ImportError:
    MySQLdb_available = False


### Mocked classes

class MockedSession(object):
    """Mock Beaker session
    """
    def __init__(self, username=None):
        self.__username = username
        self.__saved = False

    def get(self, k, default):
        assert k in ('username')
        if self.__username is None:
            return default

        return self.__username

    def __getitem__(self, k):
        assert k in ('username')
        if self.__username is None:
            raise KeyError()

        return self.__username

    def __setitem__(self, k, v):
        assert k in ('username')
        self.__username = v
        self.__saved = False

    def delete(self):
        """Used during logout to delete the current session"""
        self.__username = None

    def save(self):
        self.__saved = True

#TODO: implement tests around MockedSession __saved

class MockedSessionCork(Cork):
    """Mocked Cork instance where the session is replaced with
    MockedSession
    """
    @property
    def _beaker_session(self):
        return self._mocked_beaker_session


### Fixtures and helpers

## Backends

def setup_sqlite_db(request):
    # in-memory SQLite DB using the SQLiteBackend backend module.
    b = SQLiteBackend(':memory:', initialize=True)
    b.connection.executescript("""
        INSERT INTO users (username, email_addr, desc, role, hash, creation_date) VALUES
        (
            'admin',
            'admin@localhost.local',
            'admin test user',
            'admin',
            'cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=',
            '2012-10-28 20:50:26.286723'
        );
        INSERT INTO roles (role, level) VALUES ('special', 200);
        INSERT INTO roles (role, level) VALUES ('admin', 100);
        INSERT INTO roles (role, level) VALUES ('editor', 60);
        INSERT INTO roles (role, level) VALUES ('user', 50);
    """)
    return b


def setup_json_db(request, tmpdir):
    # Setup test directory with valid JSON files and return JsonBackend instance
    tmpdir.join('users.json').write("""{"admin": {"email_addr": "admin@localhost.local", "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596", "last_login": "2012-10-28 20:50:26.286723"}}""")
    tmpdir.join('roles.json').write("""{"special": 200, "admin": 100, "user": 50, "editor": 60}""")
    tmpdir.join('register.json').write("""{}""")
    return JsonBackend(tmpdir)


def setup_sqlalchemy_with_sqlite_in_memory_db(request):
    # Setup an SqlAlchemyBackend backend using an in-memory SQLite DB

    mb = SqlAlchemyBackend('sqlite:///:memory:', initialize=True)

    ## Purge DB
    mb._drop_all_tables()
    assert len(mb.roles) == 0
    assert len(mb.users) == 0

    # Create roles
    mb.roles.insert({'role': 'special', 'level': 200})
    mb.roles.insert({'role': 'admin', 'level': 100})
    mb.roles.insert({'role': 'editor', 'level': 60})
    mb.roles.insert({'role': 'user', 'level': 50})

    # Create admin
    mb.users.insert({
        "username": "admin",
        "email_addr": "admin@localhost.local",
        "desc": "admin test user",
        "role": "admin",
        "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
        "creation_date": "2012-10-28 20:50:26.286723",
        "last_login": "2012-10-28 20:50:26.286723"
    })
    assert len(mb.roles) == 4
    assert len(mb.users) == 1

    def fin():
        mb._drop_all_tables()
        assert len(mb.roles) == 0
        assert len(mb.users) == 0

    request.addfinalizer(fin)
    return mb

    #def purge_test_db(self):
    #    # Purge DB
    #    mb = connect_to_test_db()
    #    mb._drop_all_tables()

def setup_mongo_db(request):
    # FIXME no last_login?
    t0 = time.time()
    def timer(s, max_time=None):
        delta = time.time() - t0
        print("%s %f" % (s, delta))
        if max_time is not None:
            assert delta < max_time

    mb = MongoDBBackend(db_name='cork-functional-test', initialize=True)
    timer('connect + init')

    # Purge DB
    mb.users._coll.drop()
    mb.roles._coll.drop()
    mb.pending_registrations._coll.drop()
    timer('purge')

    # Create admin
    mb.users._coll.insert({
        "login": "admin",
        "email_addr": "admin@localhost.local",
        "desc": "admin test user",
        "role": "admin",
        "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
        "creation_date": "2012-10-28 20:50:26.286723"
    })
    timer('create')

    # Create users
    mb.roles._coll.insert({'role': 'special', 'val': 200})
    mb.roles._coll.insert({'role': 'admin', 'val': 100})
    mb.roles._coll.insert({'role': 'editor', 'val': 60})
    mb.roles._coll.insert({'role': 'user', 'val': 50})
    timer('create users')

    def fin():
        mb.users._coll.drop()
        mb.roles._coll.drop()

    request.addfinalizer(fin)
    timer('mongo setup', 8)
    return mb


def setup_mysql_db(request):

    if os.environ.get('TRAVIS', False):
        # Using Travis-CI - https://travis-ci.org/
        password = ''
        db_name = 'myapp_test'
    else:
        password = ''
        db_name = 'cork_functional_test'

    uri = "mysql://root:%s@localhost/%s" % (password, db_name)
    mb = SqlAlchemyBackend(uri, initialize=True)

    ## Purge DB
    mb._drop_all_tables()

    assert len(mb.roles) == 0
    assert len(mb.users) == 0

    # Create roles
    mb.roles.insert({'role': 'special', 'level': 200})
    mb.roles.insert({'role': 'admin', 'level': 100})
    mb.roles.insert({'role': 'editor', 'level': 60})
    mb.roles.insert({'role': 'user', 'level': 50})

    # Create admin
    mb.users.insert({
        "username": "admin",
        "email_addr": "admin@localhost.local",
        "desc": "admin test user",
        "role": "admin",
        "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
        "creation_date": "2012-10-28 20:50:26.286723",
        "last_login": "2012-10-28 20:50:26.286723"
    })
    assert len(mb.roles) == 4
    assert len(mb.users) == 1

    def fin():
        return  # TODO: fix
        mb._drop_all_tables()
        assert len(mb.roles) == 0
        assert len(mb.users) == 0

    request.addfinalizer(fin)
    return mb


def setup_postgresql_db(request):

    if os.environ.get('TRAVIS', False):
        # Using Travis-CI - https://travis-ci.org/
        db_name = 'myapp_test'
    else:
        db_name = 'cork_functional_test'

    uri = "postgresql+psycopg2://postgres:@/%s" % db_name
    mb = SqlAlchemyBackend(uri, initialize=True)

    # Purge DB
    mb._drop_all_tables()
    assert len(mb.roles) == 0
    assert len(mb.users) == 0

    # Create roles
    mb.roles.insert({'role': 'special', 'level': 200})
    mb.roles.insert({'role': 'admin', 'level': 100})
    mb.roles.insert({'role': 'editor', 'level': 60})
    mb.roles.insert({'role': 'user', 'level': 50})

    # Create admin
    mb.users.insert({
        "username": "admin",
        "email_addr": "admin@localhost.local",
        "desc": "admin test user",
        "role": "admin",
        "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
        "creation_date": "2012-10-28 20:50:26.286723",
        "last_login": "2012-10-28 20:50:26.286723"
    })
    assert len(mb.roles) == 4
    assert len(mb.users) == 1

    def fin():
        mb._drop_all_tables()
        assert len(mb.roles) == 0
        assert len(mb.users) == 0

    request.addfinalizer(fin)
    return mb



## General fixtures

@pytest.fixture(params=[
    'json',
    'mongodb',
    'mysql',
    'postgresql',
    'sqlalchemy',
    'sqlite',
])
def backend(tmpdir, request):
    # Create backend instances
    backend_type = request.param
    if backend_type == 'json':
        return setup_json_db(request, tmpdir)

    if backend_type == 'sqlite':
        return setup_sqlite_db(request)

    if backend_type == 'sqlalchemy':
        return setup_sqlalchemy_with_sqlite_in_memory_db(request)

    if backend_type == 'mongodb':
        if not pymongo_available:
            pytest.skip()

        return setup_mongo_db(request)

    if backend_type == 'mysql':
        if not MySQLdb_available:
            pytest.skip()

        return setup_mysql_db(request)

    if backend_type == 'postgresql':
        return setup_postgresql_db(request)

    raise Exception()


@pytest.fixture
def aaa_unauth(templates_dir, backend):
    # Session without any authenticated user
    aaa = MockedSessionCork(
        templates_dir,
        backend=backend,
        smtp_server='localhost',
        email_sender='test@localhost',
    )
    aaa._mocked_beaker_session = MockedSession()
    return aaa


@pytest.fixture
def aaa_admin(templates_dir, backend):
    # Session with an admin user
    aaa = MockedSessionCork(
        templates_dir,
        backend=backend,
        email_sender='test@localhost',
        smtp_server='localhost',
    )
    aaa._mocked_beaker_session = MockedSession(username='admin')
    return aaa


### Tests

## Unauthenticated user

def test_unauth_basic(aaa_unauth):
    assert aaa_unauth._beaker_session.get('username', None) == None

def test_get_current_user_unauth(aaa_unauth):
    with raises(AAAException):
        aaa_unauth.current_user['username']

def test_unauth_is_anonymous(aaa_unauth):
    assert aaa_unauth.user_is_anonymous

def test_failing_login_unauth(aaa_unauth):
    login = aaa_unauth.login('phil', 'hunter123')
    assert login == False, "Login must fail"
    assert aaa_unauth._beaker_session.get('username', None) == None


## Logged in as admin

def test_mockedadmin(aaa_admin):
    assert len(aaa_admin._store.users) == 1,  len(aaa_admin._store.users)
    assert 'admin' in aaa_admin._store.users, repr(aaa_admin._store.users)


def test_password_hashing(aaa_admin):
    shash = aaa_admin._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith(b'='), "hash should end with '='"
    assert aaa_admin._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"


def test_incorrect_password_hashing(aaa_admin):
    shash = aaa_admin._hash('user_foo', 'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith(b'='), "hash should end with '='"
    assert aaa_admin._verify_password('user_foo', '####', shash) == False, \
        "Hashing verification should fail"
    assert aaa_admin._verify_password('###', 'bogus_pwd', shash) == False, \
        "Hashing verification should fail"


def test_password_hashing_collision(aaa_admin):
    salt = b'S' * 32
    hash1 = aaa_admin._hash(u'user_foo', u'bogus_pwd', salt=salt)
    hash2 = aaa_admin._hash(u'user_foobogus', u'_pwd', salt=salt)
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


@pytest.fixture
def disable_os_urandom(monkeypatch):
    monkeypatch.setattr('os.urandom', lambda n: b'9' * n)


def test_check_hashing(aaa_admin, disable_os_urandom):
    h1 = aaa_admin._hash(u'user', u'pwd')
    assert h1 == b'cDk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5ihNBRY2RYEuI8BWPKndJzD0BTxFOV+hv4Ih9WvRk9Dg='


def test_create_user_check_hashing(aaa_admin, disable_os_urandom):
    assert len(aaa_admin._store.users) == 1, repr(aaa_admin._store.users)
    aaa_admin.create_user(u'phil', 'user', u'pwd')
    assert len(aaa_admin._store.users) == 2, repr(aaa_admin._store.users)
    assert 'phil' in aaa_admin._store.users

    h = aaa_admin._store.users['phil']['hash'].encode('ascii')
    assert h == b'cDk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5REycUvi9EWiRY7kAUwU4vnGD84a0hstdqigKOaNmqBM='
    assert h == aaa_admin._hash(u'phil', u'pwd')


def test_unauth_delete_user(aaa_admin):
    aaa_admin._store.roles['admin'] = 10  # lower admin level
    assert_raises(AuthException, aaa_admin.delete_user, 'phil')


def test_delete_nonexistent_user(aaa_admin):
    assert_raises(AAAException, aaa_admin.delete_user, 'not_an_user')


def test_delete_user(aaa_admin):
    assert len(aaa_admin._store.users) == 1, repr(aaa_admin._store.users)
    aaa_admin.delete_user(u'admin')
    assert len(aaa_admin._store.users) == 0, repr(aaa_admin._store.users)
    assert 'admin' not in aaa_admin._store.users



def test_list_users(aaa_admin):
    users = list(aaa_admin.list_users())
    assert len(users) == 1, "Incorrect. Users are: %s" % repr(aaa_admin._store.users)


def test_iteritems_on_users(aaa_admin):
    expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date',
        'desc', 'last_login'))

    if isinstance(aaa_admin._store, MongoDBBackend):
        expected_dkeys.discard('last_login')

    if hasattr(aaa_admin._store.users, 'iteritems'):
        items = aaa_admin._store.users.iteritems()
    else:
        items = iter(aaa_admin._store.users.items())

    for k, v in items:
        dkeys = set(v.keys())

        extra = dkeys - expected_dkeys
        assert not extra, "Unexpected extra keys: %s" % repr(extra)

        missing = expected_dkeys - dkeys
        assert not missing, "Missing keys: %s" % repr(missing)


def test_failing_login(aaa_admin):
    login = aaa_admin.login('phil', 'hunter123')
    assert login == False, "Login must fail"
    assert aaa_admin._beaker_session.get('username', None) == 'admin'


def test_login_nonexistent_user_empty_password(aaa_admin):
    login = aaa_admin.login('IAmNotHome', '')
    assert login == False, "Login must fail"
    assert aaa_admin._beaker_session.get('username', None) == 'admin'


def test_login_existing_user_empty_password(aaa_admin):
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert 'phil' in aaa_admin._store.users
    assert aaa_admin._store.users['phil']['role'] == 'user'
    login = aaa_admin.login('phil', '')
    assert login == False, "Login must fail"
    assert aaa_admin._beaker_session.get('username', None) == 'admin'


def test_create_and_validate_user(aaa_admin):
    assert len(aaa_admin._store.users) == 1, "Only the admin user should be present"
    aaa_admin.create_user('phil', 'user', 'hunter123')
    assert len(aaa_admin._store.users) == 2, "Two users should be present"
    assert 'phil' in aaa_admin._store.users
    assert aaa_admin._store.users['phil']['role'] == 'user'
    login = aaa_admin.login('phil', 'hunter123')
    assert login == True, "Login must succeed"
    assert aaa_admin._beaker_session['username'] == 'phil'

def test_create_and_validate_user_unicode(aaa_admin, backend):
    # FIXME, see #4
    if hasattr(backend, '_engine'):
        url = backend._engine.url
        if str(url).startswith('mysql'):
            pytest.xfail()

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
    except bottle.HTTPResponse as e:
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

def test_write_user_hash_bytes(aaa_admin, backend):
    username = 'huh'
    h = b'1234'
    tstamp = "just a string"

    h = h.decode('ascii')
    assert isinstance(h, type(u''))
    aaa_admin._store.users[username] = {
        'role': "user",
        'hash': h,
        'email_addr': "bar",
        'desc': "foo",
        'creation_date': tstamp,
        'last_login': tstamp
    }

    if hasattr(backend, '_engine'):
        h_from_db = backend._engine.execute("SELECT * FROM users").fetchall()[1][2]
        assert h_from_db == '1234'

    fetched_h = aaa_admin._store.users[username]['hash']
    fetched_h = fetched_h.encode('ascii')
    assert isinstance(fetched_h, type(b''))
    assert fetched_h == b'1234'


def test_write_user_hash_unicode(aaa_admin):
    username = 'huh'
    h = u'1234'
    tstamp = "just a string"
    aaa_admin._store.users[username] = {
        'role': "user",
        'hash': h,
        'email_addr': "bar",
        'desc': "foo",
        'creation_date': tstamp,
        'last_login': tstamp
    }

    if hasattr(backend, '_engine'):
        h_from_db = backend._engine.execute("SELECT * FROM users").fetchall()[1][2]
        print("H %r" % h_from_db)
        assert h_from_db == '1234'


    fetched_h = aaa_admin._store.users[username]['hash']
    assert fetched_h == u'1234'


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
        aaa_admin._store.users.pop(u'admin')
        aaa_admin.current_user.update(role='user')


def test_update_role(aaa_admin):
    aaa_admin.current_user.update(role='user')
    assert aaa_admin._store.users['admin']['role'] == 'user'


def test_update_pwd(aaa_admin):
    aaa_admin.current_user.update(pwd='meow')


def test_update_email(aaa_admin):
    aaa_admin.current_user.update(email_addr='foo')
    assert aaa_admin._store.users['admin']['email_addr'] == 'foo', aaa_admin._store.users['admin']


def test_get_current_user_nonexistent(aaa_admin):
    # The current user 'admin' is not in the user table
    with raises(AuthException):
        aaa_admin._store.users.pop(u'admin')
        aaa_admin.current_user


def test_get_nonexistent_user(aaa_admin):
    assert aaa_admin.user('nonexistent_user') is None


def test_get_user_description_field(aaa_admin):
    admin = aaa_admin.user(u'admin')
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


def test_register_valid(aaa_admin, templates_dir):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.register('foo', 'pwd', 'email@email.org', role='user',
        email_template='views/registration_email.tpl'
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

def test_validate_registration(aaa_admin, templates_dir):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.register('foo', 'pwd', 'email@email.org', role='user',
        email_template='views/registration_email.tpl'
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

def test_send_password_reset_email_only_email(aaa_admin, templates_dir):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.send_password_reset_email(email_addr='admin@localhost.local',
        email_template='views/password_reset_email')

def test_send_password_reset_email_only_username(aaa_admin, tmpdir, templates_dir):
    aaa_admin.mailer.send_email = mock.Mock()
    aaa_admin.send_password_reset_email(username='admin',
        email_template='views/password_reset_email')



def test_perform_password_reset_invalid(aaa_admin):
    with raises(AuthException):
        aaa_admin.reset_password(u'bogus', u'newpassword')


def test_perform_password_reset_timed_out(aaa_admin):
    aaa_admin.password_reset_timeout = 0
    token = aaa_admin._reset_code(u'admin', u'admin@localhost.local')
    with raises(AuthException):
        aaa_admin.reset_password(token, 'newpassword')


def test_perform_password_reset_nonexistent_user(aaa_admin):
    token = aaa_admin._reset_code(u'admin_bogus', u'admin@localhost.local')
    with raises(AAAException):
        aaa_admin.reset_password(token, u'newpassword')


# The following test should fail
# an user can change the password reset timestamp by b64-decoding the token,
# editing the field and b64-encoding it
@pytest.mark.xfail  # FIXME
def test_perform_password_reset_mangled_timestamp(aaa_admin):
    token = aaa_admin._reset_code(u'admin', 'admin@localhost.local')
    reset_code = b64decode(token).decode('utf-8')
    username, email_addr, tstamp, h = reset_code.split(':', 3)
    tstamp = str(int(tstamp) + 100)
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token.encode('utf-8'))
    with raises(AuthException):
        aaa_admin.reset_password(mangled_token, u'newpassword')


def test_perform_password_reset_mangled_username(aaa_admin):
    token = aaa_admin._reset_code(u'admin', u'admin@localhost.local')
    reset_code = b64decode(token).decode('utf-8')
    username, email_addr, tstamp, h = reset_code.split(':', 3)
    username += "mangled_username"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token.encode('utf-8'))
    with raises(AuthException):
        aaa_admin.reset_password(mangled_token, u'newpassword')


def test_perform_password_reset_mangled_email(aaa_admin):
    token = aaa_admin._reset_code(u'admin', u'admin@localhost.local')
    reset_code = b64decode(token).decode('utf-8')
    username, email_addr, tstamp, h = reset_code.split(':', 3)
    email_addr += "mangled_email"
    mangled_token = ':'.join((username, email_addr, tstamp, h))
    mangled_token = b64encode(mangled_token.encode('utf-8'))
    with raises(AuthException):
        aaa_admin.reset_password(mangled_token, u'newpassword')


def test_set_password_directly(aaa_admin):
    #assert aaa_admin.login(u'admin', u'newpwd') == False
    user = aaa_admin.user(u'admin')
    assert user
    user.update(pwd='newpwd')
    assert aaa_admin.login(u'admin', u'newpwd')


def test_perform_password_reset(aaa_admin):
    token = aaa_admin._reset_code(u'admin', u'admin@localhost.local')
    aaa_admin.reset_password(token, u'newpassword')
    login = aaa_admin.login(u'admin', u'newpassword')
    assert login == True, "Login must succeed"

