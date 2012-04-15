#!/usr/bin/env python
#
# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2012 Federico Ceratto
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#  - password reset function
#  - add hooks to provide logging or user-defined functions in case of
#     login/require failure
#  - decouple authentication logic from data storage to allow multiple backends
#    (e.g. a key/value database)

from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from hashlib import sha512
from logging import getLogger
from random import randint
from smtplib import SMTP
from threading import Thread
import bottle
import os
import uuid

try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json

__version__ = '0.1~alpha'

log = getLogger(__name__)


class AAAException(Exception):
    """Generic Authentication/Authorization Exception"""
    pass


class AuthException(AAAException):
    """Authentication Exception: incorrect username/password pair"""
    pass


class Cork(object):

    def __init__(self, directory, email_sender=None, smtp_server=None,
        users_fname='users', roles_fname='roles', pending_reg_fname='register'):
        """Auth/Authorization/Accounting class

        :param directory: configuration directory
        :type directory: str.
        :param users_fname: users filename (without .json), defaults to 'users'
        :type users_fname: str.
        :param roles_fname: roles filename (without .json), defaults to 'roles'
        :type roles_fname: str.
        """
        assert directory, "Directory name must be valid"
        self._directory = directory
        self._users = {}
        self._users_fname = users_fname
        self._roles = {}
        self._roles_fname = roles_fname
        self._mtimes = {}
        self._pending_reg_fname = pending_reg_fname
        self._pending_registrations = {}
        self.mailer = Mailer(email_sender, smtp_server)
        self._refresh()  # load users and roles

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

        if username in self._users:
            if self._verify_password(username, password,
                    self._users[username]['hash']):
                # Setup session data
                self._setup_cookie(username)
                if success_redirect:
                    bottle.redirect(success_redirect)
                return True

            if fail_redirect:
                bottle.redirect(fail_redirect)

        return False

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
            if username not in self._users:
                raise AAAException("Nonexistent user")
        if fixed_role and role is None:
            raise AAAException("""A role must be specified if fixed_role
                has been set""")

        if role is not None and role not in self._roles:
            raise AAAException("Role not found")

        if self.current_user.role not in self._roles:
            raise AAAException("Role not found for the current user")

        # Authentication
        if self.current_user == None:
            raise AuthException("Unauthenticated user")

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
                bottle.redirect(redirect)

        else:
            if role is not None:
                # Any role with higher level is allowed
                current_lvl = self._roles[self.current_user.role]
                threshold_lvl = self._roles[role]
                if current_lvl >= threshold_lvl:
                    return

                if fail_redirect is None:
                    raise AuthException("Unauthorized access: ")
                else:
                    bottle.redirect(redirect)

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
        if role in self._roles:
            raise AAAException("The role is already existing")
        try:
            int(level)
        except ValueError:
            raise AAAException("The level must be numeric.")
        self._roles[role] = level
        self._savejson('roles', self._roles)

    def delete_role(self, role):
        """Deleta a role.

        :param role: role name
        :type role: str.
        :raises: AuthException on errors
        """
        if self.current_user.level < 100:
            raise AuthException("The current user is not authorized to ")
        if role not in self._roles:
            raise AAAException("Nonexistent role.")
        self._roles.pop(role)
        self._savejson(self._roles_fname, self._roles)

    def list_roles(self):
        """List roles."""
        raise NotImplementedError

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
        if username in self._users:
            raise AAAException("User is already existing.")
        tstamp = str(datetime.utcnow())
        self._users[username] = {
            'role': role,
            'hash': self._hash(username, password),
            'email_addr': email_addr,
            'desc': description,
            'creation_date': tstamp
        }
        self._save_users()

    def delete_user(self, username):
        """Delete a user account.
        This method is available to users with level>=100

        :param username: username
        :type username: str.
        :raises: Exceptions on errors
        """
        if self.current_user.level < 100:
            raise AuthException("The current user is not authorized to ")
        if username not in self._users:
            raise AAAException("Nonexistent user.")
        self.user(username).delete()

    def list_users(self):
        """List users."""
        raise NotImplementedError

    @property
    def current_user(self):
        """Current autenticated user

        :returns: User() instance, if authenticated
        :raises: AuthException otherwise
        """
        username = self._beaker_session_username
        if username is None:
            raise AuthException("Unauthenticated user")
        if username is not None and username in self._users:
            return User(username, self)
        raise AuthException("Unknown user: %s" % username)

    def user(self, username):
        """Existing user

        :returns: User() instance if the user exist, None otherwise
        """
        if username is not None and username in self._users:
            return User(username, self)
        return None

    def register(self, username, password, email_addr, role='user',
        max_level=50, email_template='view/registration_email', description=None):
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
        :param description: description (free form)
        :type description: str.
        :raises: AssertError or AAAException on errors
        """
        assert username, "Username must be provided."
        assert password, "A password must be provided."
        assert email_addr, "An email address must be provided."
        if username in self._users:
            raise AAAException("User is already existing.")
        if role not in self._roles:
            raise AAAException("Nonexistent role")
        if self._roles[role] > max_level:
            raise AAAException("Unauthorized role")

        registration_code = uuid.uuid4().hex

        # store pending registration
        creation_date = str(datetime.utcnow())
        self._pending_registrations[registration_code] = {
            'username': username,
            'role': role,
            'hash': self._hash(username, password),
            'email_addr': email_addr,
            'desc': description,
            'creation_date': creation_date,
        }
        self._savejson(self._pending_reg_fname, self._pending_registrations)

        # send registration email
        email_text = bottle.template(email_template,
            username=username,
            email_addr=email_addr,
            role=role,
            creation_date=creation_date,
            registration_code=registration_code
        )
        self.mailer.send_email(email_addr, email_text)

    def validate_registration(self, registration_code):
        """Validate pending account registration, create a new account if
        successful.

        :param registration_code: registration code
        :type registration_code: str.
        """
        try:
            data = self._pending_registrations.pop(registration_code)
        except KeyError:
            raise AuthException("Invalid registration code.")

        # the user data is moved from _pending_registrations to _users
        username = data['username']
        self._users[username] = {
            'role': data['role'],
            'hash': data['hash'],
            'email_addr': data['email_addr'],
            'desc': data['desc'],
            'creation_date': data['creation_date']
        }
        self._save_users()

    ## Private methods

    @property
    def _beaker_session_username(self):
        """Get username from Beaker session"""
        session = bottle.request.environ.get('beaker.session')
        username = session.get('username', None)
        return username

    def _refresh(self):
        """Load users and roles from JSON files, if needed"""
        self._loadjson(self._users_fname, self._users)
        self._loadjson(self._roles_fname, self._roles)
        self._loadjson(self._pending_reg_fname, self._pending_registrations)

    def _loadjson(self, fname, dest):
        """Load JSON file located under self._directory, if needed

        :param fname: short file name (without path and .json)
        :type fname: str.
        :param dest: destination
        :type dest: dict
        """
        fname = "%s/%s.json" % (self._directory, fname)
        mtime = os.stat(fname).st_mtime

        if self._mtimes.get(fname, 0) == mtime:
            # no need to reload the file: the mtime has not been changed
            return

        try:
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
        self._savejson('users', self._users)

    def _setup_cookie(self, username):
        """Setup cookie for a user that just logged in"""
        session = bottle.request.environ.get('beaker.session')
        session['username'] = username
        session.save()

    @staticmethod
    def _hash(username, pwd, salt=None):
        """Hash username and password"""
        if salt is None:
            salt = ''.join(chr(randint(0,255)) for i in range(32)).encode('hex')
        return sha512("%s:::%s" % (username, pwd) + salt).hexdigest() + salt

    @classmethod
    def _verify_password(cls, username, pwd, salted_hash):
        hash_, salt = salted_hash[:128], salted_hash[128:]
        return cls._hash(username, pwd, salt) == salted_hash

    def __len__(self):
        """Count users"""
        return len(self._users) #TODO: remove this?

    def _purge_expired_registrations(self, exp_time=96):
        """Purge expired registration requests.

        :param exp_time: expiration time (hours)
        :type exp_time: float.
        """
        raise NotImplementedError


class User(object):

    def __init__(self, username, cork_obj):
        """Represent an authenticated user

        :param username: username
        :type username: str.
        :param cork_obj: instance of :class:`Cork`
        """
        self._cork = cork_obj
        assert username in self._cork._users, "Unknown user"
        self.username = username
        self.role = self._cork._users[username]['role']
        self.level = self._cork._roles[self.role]

    def logout(self, fail_redirect='/login'):
        """Log the user out, remove cookie

        :param fail_redirect: redirect the user if it is not logged in
        :type fail_redirect: str.
        """
        s = bottle.request.environ.get('beaker.session')
        u = s.get('username', None)
        if u:
            log.info('User %s logged out.' % u)
        s.delete()
        bottle.redirect(fail_redirect)

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
        if username not in self._cork._users:
            raise AAAException("User does not exist.")
        if role is not None:
            if role not in self._cork._roles:
                raise AAAException("Nonexistent role.")
            self._cork._users[username]['role'] = role
        if pwd is not None:
            self._cork._users[username]['hash'] = self._hash(username, pwd)
        if email_addr is not None:
            self._cork._users[username]['email'] = email_addr
        self._cork._save_users()

    def delete(self):
        """Delete user account

        :raises: AAAException on nonexistent user.
        """
        try:
            self._cork._users.pop(self.username)
        except KeyError:
            raise AAAException("Nonexistent user.")
        self._cork._save_users()

#TODO: add creation and last access date?


class Mailer(object):

    def __init__(self, sender, smtp_server, join_timeout=5):
        """Send emails asyncronously

        :param sender: Sender email address
        :type sender: str.
        :param smtp_server: SMTP server
        :type smtp_server: str.
        """
        self.sender = sender
        self.smtp_server = smtp_server
        self.join_timeout = join_timeout
        self._threads = []

    def send_email(self, email_addr, email_text):
        """Send an email

        :param email_addr: email address
        :type email_addr: str.
        :param email_text: email text
        :type email_text: str.
        """
        if self.smtp_server is None:
            return
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Register" #FIXME
        msg['From'] = self.sender
        msg['To'] = email_addr
        part = MIMEText(email_text, 'html')
        msg.attach(part)

        #log.debug("Sending email using %s" % self._smtp_server)
        thread = Thread(target=self._send, args=(email_addr, msg))
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
            session = SMTP(self.smtp_server)
            session.sendmail(self.sender, email_addr, msg) #TODO
            session.close()
            log.debug('Email sent')
        except Exception, e:
            log.error("Error sending email: %s" % e)

    def join(self):
        """Flush email queue by waiting the completion of the existing threads

        :returns: None
        """
        return [t.join(self.join_timeout) for t in self._threads]

    def __del__(self):
        """Class destructor: wait for threads to terminate within a timeout"""
        self.join()

