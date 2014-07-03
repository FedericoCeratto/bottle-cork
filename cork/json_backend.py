# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt

"""
.. module:: json_backend
   :synopsis: JSON file-based storage backend.
"""

import shutil
import os
from logging import getLogger
try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json

from base_backend import BackendIOException

log = getLogger(__name__)

class JsonBackend(object):
    """JSON file-based storage backend."""

    def __init__(self, directory, users_fname='users',
            roles_fname='roles', pending_reg_fname='register', initialize=False):
        """Data storage class. Handles JSON files

        :param users_fname: users file name (without .json)
        :type users_fname: str.
        :param roles_fname: roles file name (without .json)
        :type roles_fname: str.
        :param pending_reg_fname: pending registrations file name (without .json)
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
            raise BackendIOException("Unable to read json file %s: %s" % (fname, e))

        try:
            json_obj = json.loads(json_data)
            dest.clear()
            dest.update(json_obj)
            self._mtimes[fname] = os.stat(fname).st_mtime
        except Exception as e:
            raise BackendIOException("Unable to parse JSON data from %s: %s" \
                % (fname, e))

    def _savejson(self, fname, obj):
        """Save obj in JSON format in a file in self._directory"""
        fname = "%s/%s.json" % (self._directory, fname)
        try:
            s = json.dumps(obj)
            with open("%s.tmp" % fname, 'wb') as f:
                f.write(s)
                f.flush()
            shutil.move("%s.tmp" % fname, fname)
        except Exception as e:
            raise BackendIOException("Unable to save JSON file %s: %s" \
                % (fname, e))

    def save_users(self):
        """Save users in a JSON file"""
        self._savejson(self._users_fname, self.users)

    def save_roles(self):
        """Save roles in a JSON file"""
        self._savejson(self._roles_fname, self.roles)

    def save_pending_registrations(self):
        """Save pending registrations in a JSON file"""
        self._savejson(self._pending_reg_fname, self.pending_registrations)
