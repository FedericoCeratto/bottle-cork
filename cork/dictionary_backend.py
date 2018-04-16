"""
.. module:: dict_backend
   :synopsis: Dictionary based storage backend.
"""

from logging import getLogger
import sys
from datetime import datetime as dt

from .base_backend import BackendIOException

is_py3 = (sys.version_info.major == 3)

log = getLogger(__name__)

try:
    dict.iteritems
    py23dict = dict
except AttributeError:
    class py23dict(dict):
        iteritems = dict.items


class DictionaryBackend(object):
    """Dictionary based storage backend."""

    def __init__(self, users=None, roles=None,
            pending_registrations=None):
        """Dictionary storage class.

        :param users: A dictionary of dictionary containing users and roles, e.g.
            {
                'mel': {
                    'hash': cork._hash('mel', 'sugartits'),
                    'email_addr': 'bravehurt@yahoo.com',
                    'role': 'admin',
                    'creation_data': '2012-10-28 20:50:26.286723',
                    'desc': 'Cheers!'}
                },
                # ...
            }
        :type users: dict
        :param roles: A table of roles, e.g. {'admin': 100, 'user': 50}
        :type roles: dict
        :param pending_registrations: A table of pending registrations.
        :type pending_registrations: dict
        """
        self.users = py23dict(users) if users is not None else py23dict()
        self.roles = py23dict(roles) if roles is not None else py23dict()
        self.pending_registrations = py23dict(pending_registrations) \
            if pending_registrations is not None else py23dict()

    def add_user(self, username, role, hash,
            email=None, description=None, creation_date=None, last_login=None):
        """Adds a new user."""
        if username in self.users:
            raise BackendIOException('The user {} already exists!'.format(username))
        if role not in self.roles:
            raise BackendIOException('The role {} does not exist!'.format(role))

        if creation_date is None:
            creation_date = dt.strftime(dt.now(), '%Y-%m-%d %H:%M:%S.%f')
        self.users[username] = {
            'hash': hash,
            'email_addr': email,
            'role': role,
            'creation_date': creation_date,
            'last_login': last_login,
            'desc': description
        }

    def add_role(self, name, priority):
        """Add a new role."""
        if name in self.roles:
            raise BackendIOException('The role {} already exists!'.format(name))
        self.roles[name] = priority

    def save_users(self):
        """Does nothing."""
        pass

    def save_roles(self):
        """Does nothing."""
        pass

    def save_pending_registrations(self):
        """Does nothing."""
        pass
