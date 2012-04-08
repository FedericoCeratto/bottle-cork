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
        self._directory = directory
        self._users = _loadjson(users_fname)
        self._roles = _loadjson(roles_fname)

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

        s = bottle.request.environ.get('beaker.session')
        if not s:
            log.warn("User needs to be authenticated.")
            #TODO: not really explanatory in a multiuser session.
            raise Alert, "User needs to be authenticated."
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
        raise NotImplementedError

    def delete_role(self, role):
        """Deleta a role.
        :param role: role name
        :type role: str.
        :raises: AuthException on errors
        """
        raise NotImplementedError

    def create_user(self, username, role, password, email_addr=None,
        description=None):
        """Create a new user account.
        This method is available to users with level>100
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
        if username in self._users:
            raise AAAException, "User is already existing."
        self._users[username] = [role, self._hash(username, pwd), email]
        self._save_users()

        raise NotImplementedError

    def delete_user(self, username):
        """Delete a user account.
        This method is available to users with level>100
        :param username: username
        :type username: str.
        :raises: AuthException on errors
        """
        try:
            self._users.pop(username)
        except KeyError:
            raise AAAException, "Non existing user."
        self._save_users()

    @property
    def user(self):
        """Current autenticated user
        :returns: User() instance, if authenticated, None otherwise
        """
        raise NotImplementedError

    #def list(self):
    #    return list(self._users)

    def update(self, username, role=None, pwd=None, email=None):
        """Update an user

        Args:
            username (string): the username
        Kwargs:
            role (string): user role
            pwd (string): user password
            email (string): user email
        """
        if username not in self._users:
            raise AAAException, "User does not exists."
        if role is not None:
            self._users[username][0] = role
        if pwd is not None:
            self._users[username][1] = self._hash(username, pwd)
        if email is not None:
            self._users[username][2] = email
        self._save_users)

    def validate(self, username, pwd):
        """Validate an username and password"""
        assert username, "Missing username."
        assert username in self._users, "Incorrect user or password."
        assert self._hash(username, pwd) == self._users[username][1], \
            "Incorrect user or password."


    ## Private methods

    def _loadjson(self, fname):
        """Load JSON file located under self._directory"""
        fname = "%s/%s.json" % (self._directory, fname)
        try:
            with open(fname) as f:
                json_data = f.read()
        except Exception, e:
            raise AAAException, "Unable read json file %s.json: %s" % (fname, e)

        try:
            return json.loads(s)
        except Exception, e:
            raise AAAException, "Unable to parse JSON data from %s.json: %s" % \
                (fname, e)

    def _savejson(self, fname, obj):
        """Save obj in JSON format in a file in self._directory"""
        fname = "%s/%s.json" % (self._directory, fname)
        try:
            s = json.dumps(obj)
            with open("%s.tmp" % fname, 'wb'):
                f.write(s)
                f.flush()
            rename("%s.tmp" % fname, fname)
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


#TODO: add creation and last access date?


