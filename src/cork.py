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

from bottle import request
from datetime import datetime
from hashlib import sha512
import os

try:
    import json
except ImportError: # pragma: no cover
    import simplejson as json

class AAAException(Exception):
    """Generic Authentication/Authorization Exception"""
    pass

class AuthException(AAAException):
    """Authentication Exception: incorrect username/password pair"""
    pass

class Cork(object):
    """Auth/Authorization/Accounting class"""

    def __init__(self, directory, users_fname='users', roles_fname='roles'):
        """"""
        assert directory, "Directory name must be valid"
        self._directory = directory
        self._users = {}
        self._users_fname = users_fname
        self._roles = {}
        self._roles_fname = roles_fname
        self._mtimes = {}
        self._refresh() # load users and roles

    def require(self, username=None, role=None, fixed_role=False, redirect=None):
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
        :type fixed_role: Bool (True/False)
        :param redirect: redirect unauthorized users (optional)
        :type redirect: str.
        """
        raise NotImplementedError

        if username is not None:
            if username != self.current_user.username:
                if redirect is None:
                    raise AuthException, "TODO"
                else:
                    bottle.redirect(redirect)

        if role is not None:
            if role != self.current_user.role:
                pass
                #TODO

        return #TODO
        myrole = s.get('role', None)
        if not myrole:
            raise Alert, "User needs to be authenticated."
        if m[myrole] >= m[role]:
            return
        log.info("An account with '%s' level or higher is required." % repr(role))
        raise Exception

    def create_role(self, role, level):
        """Create a new role.
        :param role: role name
        :type role: str.
        :param level: role level (0=lowest, 100=admin)
        :type level: int.
        :raises: AuthException on errors
        """
        if self.current_user.level < 100:
            raise AuthException, "The current user is not authorized to "
        if role in self._roles:
            raise AAAException, "The role is already existing"
        self._roles[role] = level
        self._savejson('roles', self._roles)

    def delete_role(self, role):
        """Deleta a role.
        :param role: role name
        :type role: str.
        :raises: AuthException on errors
        """
        if self.current_user.level < 100:
            raise AuthException, "The current user is not authorized to "
        if role not in self._roles:
            raise AAAException, "The role is not existing"
        self._roles.pop(role)
        self._savejson('roles', self._roles)

    def create_user(self, username, role, password, email_addr=None,
        description=None):
        """Create a new user account.
        This method is available to users with level>=100
        :param username: username
        :type username: str.
        :param role: role
        :type role: str
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
            raise AuthException, "The current user is not authorized to "
        if username in self._users:
            raise AAAException, "User is already existing."
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
            raise AuthException, "The current user is not authorized to "
        if username not in self._users:
            raise AAAException, "User does not exists"
        self.user(username).delete()

    @property
    def current_user(self):
        """Current autenticated user
        :returns: User() instance, if authenticated, None otherwise
        """
        username = self._beaker_session_username
        if username is not None and username in self._users:
            return User(username, self)
        raise AuthException, "Unknown user: %s" % username

    def user(self, username):
        """Existing user
        :returns: User() instance if the user exists, None otherwise
        """
        if username is not None and username in self._users:
            return User(username, self)
        return None

    def validate(self, username, pwd):
        """Validate an username and password"""
        assert username, "Missing username."
        assert username in self._users, "Incorrect user or password."
        assert self._hash(username, pwd) == self._users[username][1], \
            "Incorrect user or password."


    ## Private methods

    @property
    def _beaker_session_username(self):
        """Get username from Beaker session"""
        session = request.environ.get('beaker.session')
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
        except Exception, e:
            raise AAAException, "Unable read json file %s.json: %s" % (fname, e)

        try:
            dest = json.loads(json_data)
            self._mtimes[fname] = os.stat(fname).st_mtime
        except Exception, e:
            raise AAAException, "Unable to parse JSON data from %s.json: %s" % \
                (fname, e)

    def _savejson(self, fname, obj):
        """Save obj in JSON format in a file in self._directory"""
        fname = "%s/%s.json" % (self._directory, fname)
        try:
            s = json.dumps(obj)
            with open("%s.tmp" % fname, 'wb') as f:
                f.write(s)
                f.flush()
            os.rename("%s.tmp" % fname, fname)
        except Exception, e:
            raise AAAException, "Unable to save JSON file %s.json: %s" % \
                (fname, e)

    def _save_users(self):
        """Save users in a JSON file"""
        self._savejson('users', self._users)

    def _hash(self, username, pwd):
        """Hash username and password"""
        #TODO: should I add salting?
        return sha512("%s:::%s" % (username, pwd)).hexdigest()


    def __len__(self):
        """Count users"""
        return len(self._users)


class User(object):
    """Represent an authenticated user"""

    def __init__(self, username, cork_obj):
        """Create User instance"""
        self._cork = cork_obj
        assert username in self._cork._users, "Unknown user"
        self.username = username
        self.role = self._cork._users[username]['role']
        self.level = self._cork._roles[self.role]

    def logout(self):
        """Log the user out, remove cookie"""
        s = request.environ.get('beaker.session')
        u = s.get('username', None)
        if u:
            log.info('User %s logged out.' % u)
        s.delete()
        bottle.redirect('/')

    def update(self, role=None, pwd=None, email_addr=None):
        """Update an user account data
        """
        username = self.username
        if username not in self._users:
            raise AAAException, "User does not exists."
        if role is not None:
            self._users[username][0] = role
        if pwd is not None:
            self._users[username][1] = self._hash(username, pwd)
        if email is not None:
            self._users[username][2] = email_addr
        self._save_users()

    def delete(self):
        """Delete user account"""
        try:
            self._cork._users.pop(self.username)
        except KeyError:
            raise AAAException, "Non existing user."
        self._cork._save_users()

#TODO: add creation and last access date?


