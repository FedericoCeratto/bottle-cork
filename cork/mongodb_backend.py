# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt

"""
.. module:: mongodb_backend
   :synopsis: MongoDB storage backend.
"""
from logging import getLogger
log = getLogger(__name__)

from .base_backend import Backend, Table

try:
    try:
        from pymongo import MongoClient
    except ImportError:  # pragma: no cover
        # Backward compatibility with PyMongo 2.2
        from pymongo import Connection as MongoClient

    pymongo_available = True
except ImportError:  # pragma: no cover
    pymongo_available = False



class MongoTable(Table):
    """Abstract MongoDB Table.
    Allow dictionary-like access.
    """
    def __init__(self, name, key_name, collection):
        self._name = name
        self._key_name = key_name
        self._coll = collection

    def create_index(self):
        """Create collection index."""
        self._coll.create_index(
            self._key_name,
            drop_dups=True,
            unique=True,
        )

    def __len__(self):
        return self._coll.count()

    def __contains__(self, value):
        r = self._coll.find_one({self._key_name: value})
        return r is not None

    def __iter__(self):
        """Iter on dictionary keys"""
        r = self._coll.find(fields=[self._key_name,])
        return (i[self._key_name] for i in r)

    def iteritems(self):
        """Iter on dictionary items.

        :returns: generator of (key, value) tuples
        """
        r = self._coll.find()
        for i in r:
            d = i.copy()
            d.pop(self._key_name)
            d.pop('_id')
            yield (i[self._key_name], d)

    def pop(self, key_val):
        """Remove a dictionary item"""
        r = self[key_val]
        self._coll.remove({self._key_name: key_val}, safe=True)
        return r


class MongoSingleValueTable(MongoTable):
    """MongoDB table accessible as a simple key -> value dictionary.
    Used to store roles.
    """
    # Values are stored in a MongoDB "column" named "val"
    def __init__(self, *args, **kw):
        super(MongoSingleValueTable, self).__init__(*args, **kw)

    def __setitem__(self, key_val, data):
        assert not isinstance(data, dict)
        spec = {self._key_name: key_val}
        data = {self._key_name: key_val, 'val': data}
        self._coll.update(spec, data, upsert=True, safe=True)

    def __getitem__(self, key_val):
        r = self._coll.find_one({self._key_name: key_val})
        if r is None:
            raise KeyError(key_val)

        return r['val']

class MongoMutableDict(dict):
    """Represent an item from a Table. Acts as a dictionary.
    """
    def __init__(self, parent, root_key, d):
        """Create a MongoMutableDict instance.
        :param parent: Table instance
        :type parent: :class:`MongoTable`
        """
        super(MongoMutableDict, self).__init__(d)
        self._parent = parent
        self._root_key = root_key

    def __setitem__(self, k, v):
        super(MongoMutableDict, self).__setitem__(k, v)
        self._parent[self._root_key] = self


class MongoMultiValueTable(MongoTable):
    """MongoDB table accessible as a dictionary.
    """
    def __init__(self, *args, **kw):
        super(MongoMultiValueTable, self).__init__(*args, **kw)

    def __setitem__(self, key_val, data):
        assert isinstance(data, dict)
        key_name = self._key_name
        if key_name in data:
            assert data[key_name] == key_val
        else:
            data[key_name] = key_val

        spec = {key_name: key_val}
        self._coll.update(spec, data, upsert=True)

    def __getitem__(self, key_val):
        r = self._coll.find_one({self._key_name: key_val})
        if r is None:
            raise KeyError(key_val)

        return MongoMutableDict(self, key_val, r)


class MongoDBBackend(Backend):
    def __init__(self, db_name='cork', hostname='localhost', port=27017, initialize=False, username=None, password=None):
        """Initialize MongoDB Backend"""
        connection = MongoClient(host=hostname, port=port)
        db = connection[db_name]
        if username and password:
            db.authenticate(username, password)
        self.users = MongoMultiValueTable('users', 'login', db.users)
        self.pending_registrations = MongoMultiValueTable(
            'pending_registrations',
            'pending_registration',
            db.pending_registrations
        )
        self.roles = MongoSingleValueTable('roles', 'role', db.roles)

        if initialize:
            self._initialize_storage()

    def _initialize_storage(self):
        """Create MongoDB indexes."""
        for c in (self.users, self.roles, self.pending_registrations):
            c.create_index()

    def save_users(self):
        pass

    def save_roles(self):
        pass

    def save_pending_registrations(self):
        pass
