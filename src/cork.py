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
from hashlib import sha512
import bottle
import os

try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json


class AAAException(Exception):
    """Generic Authentication/Authorization Exception"""
    pass


class AuthException(AAAException):
    """Authentication Exception: incorrect username/password pair"""
    pass


class Cork(object):

    def __init__(self, directory, users_fname='users', roles_fname='roles'):
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
        self._salt = None  # add salt string to enable credentials salting
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

        print repr(self._users)
        if username in self._users:
            if self._hash(username, password) == self._users[username]['hash']:
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
        self._savejson('roles', self._roles)

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

    def _hash(self, username, pwd):
        """Hash username and password"""
        if self._salt is not None:
            username = sha512(username).hexdigest() + self._salt
            pwd = sha512(pwd).hexdigest() + self._salt
        return sha512("%s:::%s" % (username, pwd)).hexdigest()

    def __len__(self):
        """Count users"""
        return len(self._users)


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
