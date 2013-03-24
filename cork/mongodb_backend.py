# Cork - Authentication module for tyyhe Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under GPLv3+ license, see LICENSE.txt
#
# MongoDB storage backend.
#
from logging import getLogger
log = getLogger(__name__)

from .base_backend import Backend, Table

try:
    import pymongo
    pymongo_available = True
except ImportError:
    pymongo_available = False

try:
    from pymongo import MongoClient
except ImportError:
    # Backward compatibility with PyMongo 2.2
    from pymongo import Connection as MongoClient


class MongoTable(Table):
    def __init__(self, name, key_name, collection):
        self._name = name
        self._key_name = key_name
        self._coll = collection
        #self._coll.create_index([(key_name, pymongo.DESCENDING)])
        self._coll.create_index(key_name,
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

    def _dump(self):
        from json import dumps
        print
        #print dumps(list(self._coll.find()), indent=2)
        for x in self._coll.find():
            for k in sorted(x):
                if k != '_id':
                    print k, x[k], ',',

            print

    def pop(self, key_val):
        r = self[key_val]
        self._coll.remove({self._key_name: key_val}, safe=True)
        return r


class MongoSingleValueTable(MongoTable):
    # simple key -> value
    def __init__(self, *args, **kw):
        super(MongoSingleValueTable, self).__init__(*args, **kw)

    def __setitem__(self, key_val, data):
        assert not isinstance(data, dict)
        spec = {self._key_name: key_val}
        data = {self._key_name: key_val, 'val': data}
        self._coll.update(spec, data, upsert=True, safe=True)

    def __getitem__(self, key_val):
        r = self._coll.find_one({self._key_name: key_val})
        #print 'whatIgot', repr(r)
        #print 'listall', repr(list(self._coll.find()))
        if r is None:
            raise KeyError(key_val)

        return r['val']

class MongoMutableDict(dict):
    """ """
    def __init__(self, parent, root_key, d):
        super(MongoMutableDict, self).__init__(d)
        self._parent = parent
        self._root_key = root_key

    def __setitem__(self, k, v):
        super(MongoMutableDict, self).__setitem__(k, v)
        log.debug("MMD setitem")
        self._parent[self._root_key] = self


class MongoMultiValueTable(MongoTable):
    def __init__(self, *args, **kw):
        super(MongoMultiValueTable, self).__init__(*args, **kw)

    def __setitem__(self, key_val, data):
        log.debug("parent setitem %s" % repr(data))
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
    def __init__(self, db_name='cork', hostname='localhost', port=27017, initialize=False):
        """Initialize MongoDB Backend"""
        connection = MongoClient(host=hostname, port=port)
        db = connection[db_name]
        self.users = MongoMultiValueTable('users', 'login', db.users)
        self.pending_registrations = MongoMultiValueTable('pending_registrations',
            'pending_registration', db.pending_registrations)
        self.roles = MongoSingleValueTable('roles', 'role', db.roles)

    def save_users(self):
        pass

    def save_roles(self):
        pass
