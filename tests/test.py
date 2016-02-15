# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing
#

from base64 import b64encode
import mock
import pytest
import smtplib

import cork.cork
from cork import Cork, JsonBackend, AAAException, AuthException
from cork.base_backend import BackendIOException


class RoAttrDict(dict):
    """Read-only attribute-accessed dictionary.
    Used to mock beaker's session objects
    """
    def __getattr__(self, name):
        return self[name]


class MockedAdminCork(Cork):
    """Mocked module where the current user is always 'admin'"""
    @property
    def _beaker_session(self):
        return RoAttrDict(username=u'admin')

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


@pytest.fixture
def json_db_dir(tmpdir, templates_dir):
    """Setup test directory with valid JSON files"""
    tmpdir.join('users.json').write("""{"admin": {"email_addr": null, "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596"}}""")
    tmpdir.join('roles.json').write("""{"special": 200, "admin": 100, "user": 50}""")
    tmpdir.join('register.json').write("""{}""")
    return tmpdir


@pytest.fixture
def aaa(json_db_dir):
    """Setup a MockedAdminCork instance"""
    aaa = MockedAdminCork(json_db_dir.strpath, smtp_server='localhost', email_sender='test@localhost')
    aaa.mailer.use_threads = False
    return aaa


@pytest.fixture
def aaa_unauth(json_db_dir):
    """Setup test directory and a MockedAdminCork instance"""
    aaa = MockedUnauthenticatedCork(json_db_dir.strpath)
    aaa.mailer.use_threads = False
    return aaa


# Patch SMTP / SMTP_SSL to prevent network interaction
@pytest.fixture(autouse=True)
def mock_smtp(monkeypatch):
    m = mock.Mock()
    monkeypatch.setattr('cork.cork.SMTP', m)
    return m

@pytest.fixture(autouse=True)
def mock_smtp_ssl(monkeypatch):
    m = mock.Mock()
    m.return_value = mock.Mock()
    monkeypatch.setattr('cork.cork.SMTP_SSL', m)
    return m

@pytest.fixture
def mock_send(monkeypatch):
    m = mock.Mock()
    m.return_value = Mock()
    monkeypatch.setattr(Mailer, '_send', m)
    return m

def raises(f, *e):
    def wrapper(*a, **kw):
        return f(*a, **kw)
    return wrapper



# Tests

def test_init(json_db_dir):
    Cork(json_db_dir.strpath)


def test_initialize_storage(json_db_dir):
    jb = JsonBackend(json_db_dir.strpath, initialize=True)
    Cork(backend=jb)
    assert json_db_dir.join('users.json').read() == '{}'
    assert json_db_dir.join('roles.json').read() == '{}'
    assert json_db_dir.join('register.json').read() == '{}'
    return
    with open("%s/views/registration_email.tpl" % testdir) as f:
        assert f.readlines() == [
            'Username:{{username}} Email:{{email_addr}} Code:{{registration_code}}']
    with open("%s/views/password_reset_email.tpl" % testdir) as f:
        assert f.readlines() == [
            'Username:{{username}} Email:{{email_addr}} Code:{{reset_code}}']


def test_unable_to_save(json_db_dir):
    bogus_dir = '/___inexisting_directory___'
    with pytest.raises(BackendIOException):
        Cork(bogus_dir, initialize=True)


def test_loadjson_missing_file(aaa):
    with pytest.raises(BackendIOException):
        aaa._store._loadjson('nonexistent_file', {})

def test_loadjson_broken_file(aaa, json_db_dir):
    json_db_dir.join('broken_file.json').write('-----')
    with pytest.raises(BackendIOException):
        aaa._store._loadjson('broken_file', {})


def test_loadjson_unchanged(aaa):
    # By running _refresh with unchanged files the files should not be reloaded
    mtimes = aaa._store._mtimes
    aaa._store._refresh()
    # The test simply ensures that no mtimes have been updated
    assert mtimes == aaa._store._mtimes


# Test PBKDF2-based password hashing

def test_password_hashing_PBKDF2(aaa):
    shash = aaa._hash(u'user_foo', u'bogus_pwd')
    assert isinstance(shash, bytes)
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith(b'='), "hash should end with '='"
    assert aaa._verify_password('user_foo', 'bogus_pwd', shash) == True, \
        "Hashing verification should succeed"


def test_hashlib_pbk():
    # Hashlib works under py2 and py3 producing the same output.
    # With iterations = 10 and dklen = 32 the output is also consistent with
    # beaker under py2 as in the previous versions of Cork
    import hashlib
    cleartext = b'hello'
    salt = b'hi'
    h = hashlib.pbkdf2_hmac('sha1', cleartext, salt, 10, dklen=32)
    assert b64encode(h) == b'QTH8vcCFLLqLhxCTnkz6sq+Un3B4RQgWjMPpRC9hfEY='

def test_password_hashing_PBKDF2_known_hash(aaa):
    assert aaa.preferred_hashing_algorithm == 'PBKDF2'
    salt = b's' * 32
    shash = aaa._hash(u'user_foo', u'bogus_pwd', salt=salt)
    assert shash == b'cHNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzax44AxQgK6uD9q1YWxLos1ispCe1Z7T7pOFK1PwdWEs='

def test_password_hashing_PBKDF2_known_hash_2(aaa):
    assert aaa.preferred_hashing_algorithm == 'PBKDF2'
    salt = b'\0' * 32
    shash = aaa._hash(u'user_foo', u'bogus_pwd', salt=salt)
    assert shash == b'cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/8Uh4pyEOHoRz4j0lDzAmqb7Dvmo8GpeXwiKTDsuYFw='


def test_password_hashing_PBKDF2_known_hash_3(aaa):
    assert aaa.preferred_hashing_algorithm == 'PBKDF2'
    salt = b'x' * 32
    shash = aaa._hash(u'user_foo', u'bogus_pwd', salt=salt)
    assert shash == b'cHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4MEaIU5Op97lmvwX5NpVSTBP8jg8OlrN7c2K8K8tnNks='


def test_password_hashing_PBKDF2_incorrect_hash_len(aaa):
    salt = b'x' * 31 # Incorrect length
    with pytest.raises(AssertionError):
        shash = aaa._hash(u'user_foo', u'bogus_pwd', salt=salt)


def test_password_hashing_PBKDF2_incorrect_hash_value(aaa):
    shash = aaa._hash(u'user_foo', u'bogus_pwd')
    assert len(shash) == 88, "hash length should be 88 and is %d" % len(shash)
    assert shash.endswith(b'='), "hash should end with '='"
    assert aaa._verify_password(u'user_foo', u'####', shash) == False, \
        "Hashing verification should fail"
    assert aaa._verify_password(u'###', u'bogus_pwd', shash) == False, \
        "Hashing verification should fail"


def test_password_hashing_PBKDF2_collision(aaa):
    salt = b'S' * 32
    hash1 = aaa._hash(u'user_foo', u'bogus_pwd', salt=salt)
    hash2 = aaa._hash(u'user_foobogus', u'_pwd', salt=salt)
    assert hash1 != hash2, "Hash collision"


# Test password hashing for inexistent algorithms

def test_password_hashing_bogus_algo(aaa):
    with pytest.raises(RuntimeError):
        aaa._hash('user_foo', 'bogus_pwd', algo='bogus_algo')


def test_password_hashing_bogus_algo_during_verify(aaa):
    # Incorrect hash type (starts with "X")
    shash = b64encode(b'X' + b'bogusstring')
    with pytest.raises(RuntimeError):
        aaa._verify_password(u'user_foo', u'bogus_pwd', shash)


# End of password hashing tests

@pytest.mark.xfail
def test_create_empty_role(aaa):
    # TODO: implement empty role check
    with pytest.raises(AAAException):
        aaa.create_role('', 42)


def test_authenticated_is_not_anonymous(aaa):
    assert not aaa.user_is_anonymous


def test_register(aaa, json_db_dir):
    aaa.register(u'foo', u'pwd', u'a@a.a')
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)


def test_smtp_url_parsing_1(aaa):
    c = aaa.mailer._parse_smtp_url('')
    assert c['proto'] == 'smtp'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == ''
    assert c['port'] == 25


def test_smtp_url_parsing_2(aaa):
    c = aaa.mailer._parse_smtp_url('starttls://foo')
    assert c['proto'] == 'starttls'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == 'foo'
    assert c['port'] == 25


def test_smtp_url_parsing_3(aaa):
    c = aaa.mailer._parse_smtp_url('foo:443')
    assert c['proto'] == 'smtp'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


def test_smtp_url_parsing_4(aaa):
    c = aaa.mailer._parse_smtp_url('ssl://user:pass@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'user'
    assert c['pass'] == 'pass'
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


def test_smtp_url_parsing_5(aaa):
    c = aaa.mailer._parse_smtp_url('smtp://smtp.magnet.ie')
    assert c['proto'] == 'smtp'
    assert c['user'] == None
    assert c['pass'] == None
    assert c['fqdn'] == 'smtp.magnet.ie'
    assert c['port'] == 25


def test_smtp_url_parsing_email_as_username_no_password(aaa):
    # the username contains an at sign '@'
    c = aaa.mailer._parse_smtp_url('ssl://us.er@somewhere.net@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == u'us.er@somewhere.net', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == None
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


def test_smtp_url_parsing_email_as_username(aaa):
    # the username contains an at sign '@'
    c = aaa.mailer._parse_smtp_url('ssl://us.er@somewhere.net:pass@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == u'us.er@somewhere.net', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == 'pass'
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


def test_smtp_url_parsing_at_sign_in_password(aaa):
    # the password contains at signs '@'
    c = aaa.mailer._parse_smtp_url('ssl://username:pass@w@rd@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == 'username', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == 'pass@w@rd', \
        "Password is incorrectly parsed as '%s'" % c['pass']
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


def test_smtp_url_parsing_email_as_username_2(aaa):
    # both the username and the password contains an at sign '@'
    c = aaa.mailer._parse_smtp_url('ssl://us.er@somewhere.net:pass@word@foo:443/')
    assert c['proto'] == 'ssl'
    assert c['user'] == u'us.er@somewhere.net', \
        "Username is incorrectly parsed as '%s'" % c['user']
    assert c['pass'] == u'pass@word', \
        "Password is incorrectly parsed as '%s'" % c['pass']
    assert c['fqdn'] == 'foo'
    assert c['port'] == 443


def test_smtp_url_parsing_incorrect_URL_port(aaa):
    with pytest.raises(RuntimeError):
        c = aaa.mailer._parse_smtp_url(':99999')


def test_smtp_url_parsing_incorrect_URL_port_len(aaa):
    with pytest.raises(RuntimeError):
        c = aaa.mailer._parse_smtp_url(':123456')


def test_smtp_url_parsing_incorrect_URL_len(aaa):
    with pytest.raises(RuntimeError):
        c = aaa.mailer._parse_smtp_url('a' * 256)


def test_smtp_url_parsing_incorrect_URL_syntax(aaa):
    with pytest.raises(RuntimeError):
        c = aaa.mailer._parse_smtp_url('::')


def test_smtp_url_parsing_IPv4(aaa):
    c = aaa.mailer._parse_smtp_url('127.0.0.1')
    assert c['fqdn'] == '127.0.0.1'


def test_smtp_url_parsing_IPv6(aaa):
    c = aaa.mailer._parse_smtp_url('[2001:0:0123:4567:89ab:cdef]')
    assert c['fqdn'] == '[2001:0:0123:4567:89ab:cdef]'


def test_send_email_SMTP(aaa, mock_smtp):
    aaa.mailer.send_email(u'address', u' sbj', u'text')
    aaa.mailer.join()

    mock_smtp.assert_called_once_with('localhost', 25)
    session = mock_smtp.return_value
    assert session.sendmail.call_count == 1
    assert session.quit.call_count == 1


def test_send_email_SMTP_SSL(aaa, mock_smtp_ssl):
    aaa.mailer._conf['proto'] = 'ssl'
    aaa.mailer.send_email('address', ' sbj', 'text')
    aaa.mailer.join()

    mock_smtp_ssl.assert_called_once_with('localhost', 25)
    session = mock_smtp_ssl.return_value
    assert session.sendmail.call_count == 1
    assert session.quit.call_count == 1
    assert len(session.method_calls) == 2


def test_send_email_SMTP_SSL_with_login(aaa, mock_smtp_ssl):
    aaa.mailer._conf['proto'] = 'ssl'
    aaa.mailer._conf['user'] = u'username'
    aaa.mailer.send_email('address', ' sbj', 'text')
    aaa.mailer.join()

    mock_smtp_ssl.assert_called_once_with('localhost', 25)
    session = mock_smtp_ssl.return_value
    assert session.login.call_count == 1
    assert session.sendmail.call_count == 1
    assert session.quit.call_count == 1
    assert len(session.method_calls) == 3


def test_send_email_SMTP_STARTTLS(aaa, mock_smtp):
    aaa.mailer._conf['proto'] = 'starttls'
    aaa.mailer.send_email(u'address', u' sbj', u'text')
    aaa.mailer.join()

    mock_smtp.assert_called_once_with('localhost', 25)
    session = mock_smtp.return_value
    assert session.ehlo.call_count == 2
    assert session.starttls.call_count == 1
    assert session.sendmail.call_count == 1
    assert session.quit.call_count == 1
    assert len(session.method_calls) == 5


def test_do_not_send_email(aaa):
    aaa.mailer._conf['fqdn'] = None  # disable email delivery
    with pytest.raises(AAAException):
        aaa.mailer.send_email(u'address', u'sbj', u'text')

    aaa.mailer.join()



def test_purge_expired_registration(aaa, json_db_dir):
    aaa.register(u'foo', u'pwd', u'a@a.a')
    assert len(aaa._store.pending_registrations) == 1, "The registration should" \
        " be present"
    aaa._purge_expired_registrations()
    assert len(aaa._store.pending_registrations) == 1, "The registration should " \
        "be still there"
    aaa._purge_expired_registrations(exp_time=0)
    assert len(aaa._store.pending_registrations) == 0, "The registration should " \
        "have been removed"


def test_prevent_double_registration(aaa, json_db_dir):
    # Create two registration requests, then validate them.
    # The first should succeed, the second one fail as the account has been created.

    # create first registration
    aaa.register(u'user_foo', u'first_pwd', u'a@a.a')
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)
    for first_registration_code in aaa._store.pending_registrations:
        break

    # create second registration
    aaa.register(u'user_foo', u'second_pwd', u'b@b.b')
    assert len(aaa._store.pending_registrations) == 2, repr(aaa._store.pending_registrations)
    registration_codes = list(aaa._store.pending_registrations)
    if first_registration_code == registration_codes[0]:
        second_registration_code = registration_codes[1]
    else:
        second_registration_code = registration_codes[0]

    # Only the 'admin' account exists
    assert len(aaa._store.users) == 1

    # Run validate_registration with the first registration
    aaa.validate_registration(first_registration_code)
    assert 'user_foo' in aaa._store.users, "Account should have been added"
    assert len(aaa._store.users) == 2

    # After the first registration only one pending registration should be left
    # The registration having 'a@a.a' email address should be gone
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)
    for pr_code, pr_data in aaa._store.pending_registrations.items():
        break
    assert pr_data['email_addr'] == u'b@b.b', "Incorrect registration in the datastore"

    # Logging in using the first login should succeed
    login = aaa.login('user_foo', 'first_pwd')
    assert login == True, "Login must succed"
    assert len(aaa._store.pending_registrations) == 1, repr(aaa._store.pending_registrations)

    # Run validate_registration with the second registration code
    # The second registration should fail as the user account exists
    with pytest.raises(AAAException):
        aaa.validate_registration(second_registration_code)

    # test login
    login = aaa.login('user_foo', 'second_pwd')
    assert login == False, "Login must fail"


def test_send_password_reset_email_no_params(aaa):
    with pytest.raises(AAAException):
        aaa.send_password_reset_email()


def test_send_password_reset_email_incorrect_addr(aaa):
    with pytest.raises(AAAException):
        aaa.send_password_reset_email(email_addr=u'incorrect_addr')


def test_send_password_reset_email_incorrect_user(aaa):
    with pytest.raises(AAAException):
        aaa.send_password_reset_email(username=u'bogus_name')


def test_send_password_reset_email_missing_email_addr(aaa):
    with pytest.raises(AAAException):
        aaa.send_password_reset_email(username=u'admin')


def test_send_password_reset_email_incorrect_pair(aaa):
    with pytest.raises(AuthException):
        aaa.send_password_reset_email(username=u'admin', email_addr=u'incorrect_addr')


def test_send_password_reset_email_by_email_addr(aaa, json_db_dir):
    aaa._store.users['admin']['email_addr'] = u'admin@localhost.local'
    aaa.send_password_reset_email(email_addr=u'admin@localhost.local')


def test_send_password_reset_email_by_username(aaa, json_db_dir, mock_smtp):
    aaa._store.users['admin']['email_addr'] = u'admin@localhost.local'
    assert aaa._store.users['admin']['email_addr'] == u'admin@localhost.local'
    assert not mock_smtp.called
    aaa.send_password_reset_email(username='admin')
    aaa.mailer.join()
    assert mock_smtp.called
    session = mock_smtp.return_value
    assert session.sendmail.called
    assert session.sendmail.call_args[0][1] == u'admin@localhost.local'
    assert session.quit.called
