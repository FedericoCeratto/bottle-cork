#!/usr/bin/env python
#
# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2012 Federico Ceratto
#
# This package is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3 of the License, or (at your option) any later version.
#
# This package is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#
# Cork is designed for web application with a small userbase. User credentials
# are stored in a JSON file.
#
# Features:
#  - basic role support
#  - user registration
#
# Roadmap:
#  - add hooks to provide logging or user-defined functions in case of
#     login/require failure
#  - decouple authentication logic from data storage to allow multiple backends
#    (e.g. a key/value database)

from base64 import b64encode, b64decode
from beaker import crypto
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from logging import getLogger
from smtplib import SMTP
from threading import Thread
from time import time
import bottle
import os
import re
import uuid

try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json

__version__ = '0.2'

log = getLogger(__name__)


class AAAException(Exception):
    """Generic Authentication/Authorization Exception"""
    pass


class AuthException(AAAException):
    """Authentication Exception: incorrect username/password pair"""
    pass


class JsonBackend(object):

    def __init__(self, directory, users_fname='users',
            roles_fname='roles', pending_reg_fname='register', initialize=False):
        """Data storage class. Handles JSON files

        :param users_fname: users file name (without .json)
        :type users_fname: str.
        :param roles_fname: roless file name (without .json)
        :type roles_fname: str.
        :param pending_reg_fnames: pending registrations file name (without .json)
        :type pending_reg_fname: str.
        :param initialize: create empty JSON files (defaults to False)
        :type initialize: bool.
        """
        assert directory, "Directory name must be valid"
        self._directory = directory
        self.users = {}
        self._users_fname = users_fname
        self.roles = {}
        self._roles_fname = roles_fname
        self._mtimes = {}
        self._pending_reg_fname = pending_reg_fname
        self.pending_registrations = {}
        if initialize:
            self._initialize_storage()
        self._refresh()  # load users and roles

    def _initialize_storage(self):
        """Create empty JSON files"""
        self._savejson(self._users_fname, {})
        self._savejson(self._roles_fname, {})
        self._savejson(self._pending_reg_fname, {})

    def _refresh(self):
        """Load users and roles from JSON files, if needed"""
        self._loadjson(self._users_fname, self.users)
        self._loadjson(self._roles_fname, self.roles)
        self._loadjson(self._pending_reg_fname, self.pending_registrations)

    def _loadjson(self, fname, dest):
        """Load JSON file located under self._directory, if needed

        :param fname: short file name (without path and .json)
        :type fname: str.
        :param dest: destination
        :type dest: dict
        """
        try:
            fname = "%s/%s.json" % (self._directory, fname)
            mtime = os.stat(fname).st_mtime

            if self._mtimes.get(fname, 0) == mtime:
                # no need to reload the file: the mtime has not been changed
                return

            with open(fname) as f:
                json_data = f.read()
        except Exception as e:
            raise AAAException("Unable read json file %s: %s" % (fname, e))

        try:
            json_obj = json.loads(json_data)
            dest.clear()
            dest.update(json_obj)
            self._mtimes[fname] = os.stat(fname).st_mtime
        except Exception as e:
            raise AAAException("""Unable to parse JSON data from %s: %s
                """ % (fname, e))

    def _savejson(self, fname, obj):
        """Save obj in JSON format in a file in self._directory"""
        fname = "%s/%s.json" % (self._directory, fname)
        try:
            s = json.dumps(obj)
            with open("%s.tmp" % fname, 'wb') as f:
                f.write(s)
                f.flush()
            os.rename("%s.tmp" % fname, fname)
        except Exception as e:
            raise AAAException("""Unable to save JSON file %s: %s
                """ % (fname, e))

    def _save_users(self):
        """Save users in a JSON file"""
        self._savejson('users', self.users)


class Cork(object):

    def __init__(self, directory, email_sender=None,
        users_fname='users', roles_fname='roles', pending_reg_fname='register',
        initialize=False, session_domain=None, smtp_url='localhost',
        smtp_server=None):
        """Auth/Authorization/Accounting class

        :param directory: configuration directory
        :type directory: str.
        :param users_fname: users filename (without .json), defaults to 'users'
        :type users_fname: str.
        :param roles_fname: roles filename (without .json), defaults to 'roles'
        :type roles_fname: str.
        """
        if smtp_server:
            smtp_url = smtp_server
        self.mailer = Mailer(email_sender, smtp_url)
        self._store = JsonBackend(directory, users_fname='users',
            roles_fname='roles', pending_reg_fname='register',
            initialize=initialize)
        self.password_reset_timeout = 3600 * 24
        self.session_domain = session_domain

    def login(self, username, password, success_redirect=None,
        fail_redirect=None):
        """Check login credentials for an existing user.
        Optionally redirect the user to another page (tipically /login)

        :param username: username
        :type username: str.
        :param password: cleartext password
        :type password: str.
        :param success_redirect: redirect authorized users (optional)
        :type success_redirect: str.
        :param fail_redirect: redirect unauthorized users (optional)
        :type fail_redirect: str.
        :returns: True for successful logins, else False
        """
        assert isinstance(username, str), "the username must be a string"
        assert isinstance(password, str), "the password must be a string"

        if username in self._store.users:
            if self._verify_password(username, password,
                    self._store.users[username]['hash']):
                # Setup session data
                self._setup_cookie(username)
                if success_redirect:
                    bottle.redirect(success_redirect)
                return True

        if fail_redirect:
            bottle.redirect(fail_redirect)

        return False

    def logout(self, success_redirect='/login', fail_redirect='/login'):
        """Log the user out, remove cookie

        :param success_redirect: redirect the user after logging out
        :type success_redirect: str.
        :param fail_redirect: redirect the user if it is not logged in
        :type fail_redirect: str.
        """
        try:
            session = bottle.request.environ.get('beaker.session')
            session.delete()
            bottle.redirect(success_redirect)
        except:
            bottle.redirect(fail_redirect)

    def require(self, username=None, role=None, fixed_role=False,
        fail_redirect=None):
        """Ensure the user is logged in has the required role (or higher).
        Optionally redirect the user to another page (tipically /login)
        If both `username` and `role` are specified, both conditions need to be
        satisfied.
        If none is specified, any authenticated user will be authorized.
        By default, any role with higher level than `role` will be authorized;
        set fixed_role=True to prevent this.

        :param username: username (optional)
        :type username: str.
        :param role: role
        :type role: str.
        :param fixed_role: require user role to match `role` strictly
        :type fixed_role: bool.
        :param redirect: redirect unauthorized users (optional)
        :type redirect: str.
        """
        # Parameter validation
        if username is not None:
            if username not in self._store.users:
                raise AAAException("Nonexistent user")

        if fixed_role and role is None:
            raise AAAException(
                """A role must be specified if fixed_role has been set""")

        if role is not None and role not in self._store.roles:
            raise AAAException("Role not found")

        # Authentication
        try:
            cu = self.current_user
        except AAAException:
            if fail_redirect is None:
                raise AuthException("Unauthenticated user")
            else:
                bottle.redirect(fail_redirect)

        if cu.role not in self._store.roles:
            raise AAAException("Role not found for the current user")

        if username is not None:
            if username != self.current_user.username:
                if fail_redirect is None:
                    raise AuthException("""Unauthorized access: incorrect
                        username""")
                else:
                    bottle.redirect(fail_redirect)

        if fixed_role:
            if role == self.current_user.role:
                return

            if fail_redirect is None:
                raise AuthException("Unauthorized access: incorrect role")
            else:
                bottle.redirect(fail_redirect)

        else:
            if role is not None:
                # Any role with higher level is allowed
                current_lvl = self._store.roles[self.current_user.role]
                threshold_lvl = self._store.roles[role]
                if current_lvl >= threshold_lvl:
                    return

                if fail_redirect is None:
                    raise AuthException("Unauthorized access: ")
                else:
                    bottle.redirect(fail_redirect)

        return

    def create_role(self, role, level):
        """Create a new role.

        :param role: role name
        :type role: str.
        :param level: role level (0=lowest, 100=admin)
        :type level: int.
        :raises: AuthException on errors
        """
        if self.current_user.level < 100:
            raise AuthException("The current user is not authorized to ")
        if role in self._store.roles:
            raise AAAException("The role is already existing")
        try:
            int(level)
        except ValueError:
            raise AAAException("The level must be numeric.")
        self._store.roles[role] = level
        self._store._savejson('roles', self._store.roles)

    def delete_role(self, role):
        """Deleta a role.

        :param role: role name
        :type role: str.
        :raises: AuthException on errors
        """
        if self.current_user.level < 100:
            raise AuthException("The current user is not authorized to ")
        if role not in self._store.roles:
            raise AAAException("Nonexistent role.")
        self._store.roles.pop(role)
        self._store._savejson(self._store._roles_fname, self._store.roles)

    def list_roles(self):
        """List roles.

        :returns: (role, role_level) generator (sorted by role)
        """
        for role in sorted(self._store.roles):
            yield (role, self._store.roles[role])

    def create_user(self, username, role, password, email_addr=None,
        description=None):
        """Create a new user account.
        This method is available to users with level>=100

        :param username: username
        :type username: str.
        :param role: role
        :type role: str.
        :param password: cleartext password
        :type password: str.
        :param email_addr: email address (optional)
        :type email_addr: str.
        :param description: description (free form)
        :type description: str.
        :raises: AuthException on errors
        """
        assert username, "Username must be provided."
        if self.current_user.level < 100:
            raise AuthException("The current user is not authorized to ")
        if username in self._store.users:
            raise AAAException("User is already existing.")
        if role not in self._store.roles:
            raise AAAException("Nonexistent user role.")
        tstamp = str(datetime.utcnow())
        self._store.users[username] = {
            'role': role,
            'hash': self._hash(username, password),
            'email_addr': email_addr,
            'desc': description,
            'creation_date': tstamp
        }
        self._store._save_users()

    def delete_user(self, username):
        """Delete a user account.
        This method is available to users with level>=100

        :param username: username
        :type username: str.
        :raises: Exceptions on errors
        """
        if self.current_user.level < 100:
            raise AuthException("The current user is not authorized to ")
        if username not in self._store.users:
            raise AAAException("Nonexistent user.")
        self.user(username).delete()

    def list_users(self):
        """List users.

        :return: (username, role, email_addr, description) generator (sorted by
        username)
        """
        for un in sorted(self._store.users):
            d = self._store.users[un]
            yield (un, d['role'], d['email_addr'], d['desc'])

    @property
    def current_user(self):
        """Current autenticated user

        :returns: User() instance, if authenticated
        :raises: AuthException otherwise
        """
        session = self._beaker_session
        username = session.get('username', None)
        if username is None:
            raise AuthException("Unauthenticated user")
        if username is not None and username in self._store.users:
            return User(username, self, session=session)
        raise AuthException("Unknown user: %s" % username)

    def user(self, username):
        """Existing user

        :returns: User() instance if the user exist, None otherwise
        """
        if username is not None and username in self._store.users:
            return User(username, self)
        return None

    def register(self, username, password, email_addr, role='user',
        max_level=50, subject="Signup confirmation",
        email_template='views/registration_email.tpl',
        description=None):
        """Register a new user account. An email with a registration validation
        is sent to the user.
        WARNING: this method is available to unauthenticated users

        :param username: username
        :type username: str.
        :param password: cleartext password
        :type password: str.
        :param role: role (optional), defaults to 'user'
        :type role: str.
        :param max_level: maximum role level (optional), defaults to 50
        :type max_level: int.
        :param email_addr: email address
        :type email_addr: str.
        :param subject: email subject
        :type subject: str.
        :param email_template: email template filename
        :type email_template: str.
        :param description: description (free form)
        :type description: str.
        :raises: AssertError or AAAException on errors
        """
        assert username, "Username must be provided."
        assert password, "A password must be provided."
        assert email_addr, "An email address must be provided."
        if username in self._store.users:
            raise AAAException("User is already existing.")
        if role not in self._store.roles:
            raise AAAException("Nonexistent role")
        if self._store.roles[role] > max_level:
            raise AAAException("Unauthorized role")

        registration_code = uuid.uuid4().hex
        creation_date = str(datetime.utcnow())

        # send registration email
        email_text = bottle.template(email_template,
            username=username,
            email_addr=email_addr,
            role=role,
            creation_date=creation_date,
            registration_code=registration_code
        )
        self.mailer.send_email(email_addr, subject, email_text)

        # store pending registration
        self._store.pending_registrations[registration_code] = {
            'username': username,
            'role': role,
            'hash': self._hash(username, password),
            'email_addr': email_addr,
            'desc': description,
            'creation_date': creation_date,
        }
        self._store._savejson(self._store._pending_reg_fname,
            self._store.pending_registrations)


    def validate_registration(self, registration_code):
        """Validate pending account registration, create a new account if
        successful.

        :param registration_code: registration code
        :type registration_code: str.
        """
        try:
            data = self._store.pending_registrations.pop(registration_code)
        except KeyError:
            raise AuthException("Invalid registration code.")

        # the user data is moved from pending_registrations to _users
        username = data['username']
        self._store.users[username] = {
            'role': data['role'],
            'hash': data['hash'],
            'email_addr': data['email_addr'],
            'desc': data['desc'],
            'creation_date': data['creation_date']
        }
        self._store._save_users()

    def send_password_reset_email(self, username=None, email_addr=None,
        subject="Password reset confirmation",
        email_template='views/password_reset_email'):
        """Email the user with a link to reset his/her password
        If only one parameter is passed, fetch the other from the users
        database. If both are passed they will be matched against the users
        database as a security check

        :param username: username
        :type username: str.
        :param email_addr: email address
        :type email_addr: str.
        :param subject: email subject
        :type subject: str.
        :param email_template: email template filename
        :type email_template: str.
        :raises: AAAException on missing username or email_addr,
            AuthException on incorrect username/email_addr pair
        """
        if username is None:
            if email_addr is None:
                raise AAAException("At least `username` or `email_addr` must" \
                    " be specified.")

            # only email_addr is specified: fetch the username
            for k, v in self._store.users.iteritems():
                if v['email_addr'] == email_addr:
                    username = k
                    break
                raise AAAException("Email address not found.")

        else: # username is provided
            if username not in self._store.users:
                raise AAAException("Nonexistent user.")
            if email_addr is None:
                email_addr = self._store.users[username].get('email_addr', None)
                if not email_addr:
                    raise AAAException("Email address not available.")
            else:
                # both username and email_addr are provided: check them
                stored_email_addr = self._store.users[username]['email_addr']
                if email_addr != stored_email_addr:
                    raise AuthException("Username/email address pair not found.")

        # generate a reset_code token
        reset_code = self._reset_code(username, email_addr)

        # send reset email
        email_text = bottle.template(email_template,
            username=username,
            email_addr=email_addr,
            reset_code=reset_code
        )
        self.mailer.send_email(email_addr, subject, email_text)

    def reset_password(self, reset_code, password):
        """Validate reset_code and update the account password
        The username is extracted from the reset_code token

        :param reset_code: reset token
        :type reset_code: str.
        :param password: new password
        :type password: str.
        :raises: AuthException for invalid reset tokens, AAAException
        """
        try:
            reset_code = b64decode(reset_code)
            username, email_addr, tstamp, h = reset_code.split(':', 3)
            tstamp = int(tstamp)
        except (TypeError, ValueError):
            raise AuthException("Invalid reset code.")
        if time() - tstamp > self.password_reset_timeout:
            raise AuthException("Expired reset code.")
        if not self._verify_password(username, email_addr, h):
            raise AuthException("Invalid reset code.")
        user = self.user(username)
        if user is None:
            raise AAAException("Nonexistent user.")
        user.update(pwd=password)

    ## Private methods

    @property
    def _beaker_session(self):
        """Get Beaker session"""
        return bottle.request.environ.get('beaker.session')

    def _setup_cookie(self, username):
        """Setup cookie for a user that just logged in"""
        session = bottle.request.environ.get('beaker.session')
        session['username'] = username
        if self.session_domain is not None:
            session.domain = self.session_domain
        session.save()

    @staticmethod
    def _hash(username, pwd, salt=None):
        """Hash username and password, generating salt value if required
        Use PBKDF2 from Beaker

        :returns: base-64 encoded str.
        """
        if salt is None:
            salt = os.urandom(32)
        assert len(salt) == 32, "Incorrect salt length"

        cleartext = "%s\0%s" % (username, pwd)
        h = crypto.generateCryptoKeys(cleartext, salt, 10)
        # 'p' for PBKDF2
        return b64encode('p' + salt + h)

    @classmethod
    def _verify_password(cls, username, pwd, salted_hash):
        """Verity username/password pair against a salted hash

        :returns: bool
        """
        decoded = b64decode(salted_hash)
        hash_type = decoded[0]
        if hash_type != 'p': # 'p' for PBKDF2
            return False # Only PBKDF2 is supported

        salt = decoded[1:33]
        return cls._hash(username, pwd, salt) == salted_hash

    def _purge_expired_registrations(self, exp_time=96):
        """Purge expired registration requests.

        :param exp_time: expiration time (hours)
        :type exp_time: float.
        """
        for uuid, data in self._store.pending_registrations.items():
            creation = datetime.strptime(data['creation_date'],
                "%Y-%m-%d %H:%M:%S.%f")
            now = datetime.utcnow()
            maxdelta = timedelta(hours=exp_time)
            if now - creation > maxdelta:
                self._store.pending_registrations.pop(uuid)

    def _reset_code(self, username, email_addr):
        """generate a reset_code token

        :param username: username
        :type username: str.
        :param email_addr: email address
        :type email_addr: str.
        :returns: Base-64 encoded token
        """
        h = self._hash(username, email_addr)
        t = "%d" % time()
        reset_code = ':'.join((username, email_addr, t, h))
        return b64encode(reset_code)

class User(object):

    def __init__(self, username, cork_obj, session=None):
        """Represent an authenticated user, exposing useful attributes:
        username, role, level, session_creation_time, session_accessed_time,
        session_id. The session-related attributes are available for the
        current user only.

        :param username: username
        :type username: str.
        :param cork_obj: instance of :class:`Cork`
        """
        self._cork = cork_obj
        assert username in self._cork._store.users, "Unknown user"
        self.username = username
        self.role = self._cork._store.users[username]['role']
        self.level = self._cork._store.roles[self.role]

        if session is not None:
            try:
                self.session_creation_time = session['_creation_time']
                self.session_accessed_time = session['_accessed_time']
                self.session_id = session['_id']
            except:
                pass

    def update(self, role=None, pwd=None, email_addr=None):
        """Update an user account data

        :param role: change user role, if specified
        :type role: str.
        :param pwd: change user password, if specified
        :type pwd: str.
        :param email_addr: change user email address, if specified
        :type email_addr: str.
        :raises: AAAException on nonexistent user or role.
        """
        username = self.username
        if username not in self._cork._store.users:
            raise AAAException("User does not exist.")
        if role is not None:
            if role not in self._cork._store.roles:
                raise AAAException("Nonexistent role.")
            self._cork._store.users[username]['role'] = role
        if pwd is not None:
            self._cork._store.users[username]['hash'] = self._cork._hash(
                username, pwd)
        if email_addr is not None:
            self._cork._store.users[username]['email'] = email_addr
        self._cork._store._save_users()

    def delete(self):
        """Delete user account

        :raises: AAAException on nonexistent user.
        """
        try:
            self._cork._store.users.pop(self.username)
        except KeyError:
            raise AAAException("Nonexistent user.")
        self._cork._store._save_users()



class Mailer(object):

    def __init__(self, sender, smtp_url, join_timeout=5):
        """Send emails asyncronously

        :param sender: Sender email address
        :type sender: str.
        :param smtp_server: SMTP server
        :type smtp_server: str.
        """
        self.sender = sender
        self.join_timeout = join_timeout
        self._threads = []
        self._conf = self._parse_smtp_url(smtp_url)

    def _parse_smtp_url(self, url):
        """Parse SMTP URL"""
        match = re.match(r"""
            (                                   # Optional protocol
                (?P<proto>smtp|starttls|ssl)    # Protocol name
                ://
            )?
            (                                   # Optional user:pass@
                (?P<user>.*?)
                (: (?P<pass>.*?) )? @           # Optional :pass
            )?
            (?P<fqdn>.*?)                       # Required FQDN
            (                                   # Optional :port
                :
                (?P<port>[0-9]{,5})             # Up to 5-digits port
            )?
            [/]?
            $
        """, url, re.VERBOSE)

        if not match:
            raise RuntimeError("SMTP URL seems incorrect")

        d = match.groupdict()
        if d['proto'] is None:
            d['proto'] = 'smtp'

        if d['port'] is None:
            d['port'] = 25
        else:
            d['port'] = int(d['port'])

        return d



    def send_email(self, email_addr, subject, email_text):
        """Send an email

        :param email_addr: email address
        :type email_addr: str.
        :param subject: subject
        :type subject: str.
        :param email_text: email text
        :type email_text: str.
        :raises: AAAException if smtp_server and/or sender are not set
        """
        if not (self._conf['fqdn'] and self.sender):
            raise AAAException("SMTP server or sender not set")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.sender
        msg['To'] = email_addr
        part = MIMEText(email_text, 'html')
        msg.attach(part)

        log.debug("Sending email using %s" % self._conf['fqdn'])
        thread = Thread(target=self._send, args=(email_addr, msg.as_string()))
        thread.start()
        self._threads.append(thread)

    def _send(self, email_addr, msg): # pragma: no cover
        """Deliver an email using SMTP

        :param email_addr: recipient
        :type email_addr: str.
        :param msg: email text
        :type msg: str.
        """
        try:
            session = SMTP(self._conf['fqdn'])

            if self._conf['proto'] == 'ssl':
                raise NotImplementedError
            elif self._conf['proto'] == 'starttls':
                log.debug('Sending EHLO and STARTTLS')
                session.ehlo()
                session.starttls()
                session.ehlo()

            if self._conf['user'] is not None:
                log.debug('Performing login')
                session.login(self._conf['user'], self._conf['pass'])

            log.debug('sending')
            session.sendmail(self.sender, email_addr, msg)
            session.quit()
            log.info('Email sent')
        except Exception, e:
            log.error("Error sending email: %s" % e, exc_info=True)

    def join(self):
        """Flush email queue by waiting the completion of the existing threads

        :returns: None
        """
        return [t.join(self.join_timeout) for t in self._threads]

    def __del__(self):
        """Class destructor: wait for threads to terminate within a timeout"""
        self.join()

