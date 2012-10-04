import pymongo
import bson.json_util as json_util

class MongoException(Exception):
    """Generic Exception from MongoDbBackend"""
    pass

class MongoDbBackend(object):

    def __init__(self, server, port, database, users_store='users',
                 roles_store='roles', pending_regs_store='register', initialize=False, safe=True):
        """Data storage class. Handles MongoDb database

        :param server: ip or host name of the mongodb server, e.g. "localhost"
        :type server: str.
        :param port: port used by mongod process
        :type port: int.
        :param database: Name of the database, e.g. "mydb"
        :type database: str.
        :param roles_store: Name of the roles collection
        :type roles_store: str.
        :param roles_store: Name of the roles collection
        :type users_store: str.
        :param users_store: Name of the users collection
        :type users_store: str.
        :param pending_regs_store: Name of the registrations collection
        :type pending_regs_store: str.
        :param initialize: flag, when True drops all the collections.
        :type initialize: bool.
        :param safe: flag, when False changes to mongodb are not immediately written to disk.
        :type safe: bool.
        """
        assert database, "Database must be valid"
        self._database = database

        self._connection = pymongo.Connection("localhost",27017)
        self._database = self._connection[database]

        self._users_collection = self._database[users_store]
        self.users = self.Users(self._users_collection)

        self._roles_collection = self._database[roles_store]
        self.roles = self.Roles(self._roles_collection)

        self._pending_reg_collection = self._database[pending_regs_store]
        self.pending_registrations = self.PendingRegistrations(self._pending_reg_collection)

        if initialize:
            self._initialize_storage()

        # dummy so we have same interface as JsonBackend
        self._roles_fname = None
        self._users_fname = None
        self._pending_reg_fname = None

    def _initialize_storage(self):
        """Create empty database"""
        # TODO: you can also clear the collections, maintain indices
        self._users_collection.drop()
        self._roles_collection.drop()
        self._pending_reg_collection.drop()

    # dummy. This lets us be compatible with JsonBackend. In other words,
    # Cork calls this, but we don't need to do anything. Our changes
    # are saved instantly on __setitem__ and the like.
    def _savejson(self, *arg, **kw):
        pass

    # dummy
    def _loadjson(self, *arg, **kw):
        pass

    # dummy
    def _save_users(self):
        pass

    class Users(dict):

        def __init__(self, users_collection=None, *args, **kwargs):
            #assert users_collection
            if users_collection:
                self._users = users_collection
            else:
                raise MongoException("Users collection not defined")

        def __getitem__(self, item):
            user = self._users.find_one({"username":item})
            return user

        def __setitem__(self, key, value):
            self._users.update({"username":key}, value, safe=True, upsert=True)

        def __contains__(self, item):
            r = self._users.find_one({"username":item})
            return r is not None

        def __delitem__(self, key):
            self._users.remove({"username": key}, safe=True)

        def __iter__(self):
            all_users = self._users.find()
            for u in all_users:
                yield u

        def __len__(self):
            return self._users.find().count()

        def pop(self, item, default=None):
            u = self._users.find_one({"username":item})
            if not u:
                raise KeyError()
            self._users.remove(u)
            return u

        def clear(self):
            self._users.remove(safe=True)

        # TODO: write test case
        def items(self):
            """
            Right now this is implemented as a generator. This breaks
            when we're accessing via index. But what if there are
            100M users? A dictionary is not a suitable wrapper in that case anyway.
            So we stick with the generator while Cork doesn't break this.
            """
            all_users = self._users.find()
            yield [(key, self._users[key]) for key in all_users]

        def keys(self):
            all_users = self._users.find()
            for u in all_users:
                yield (u["username"])

        def values(self):
            all_users = self._users.find()
            for u in all_users:
                yield u

        def iteritems(self):
            all_users = self._users.find()
            for doc in all_users:
                yield doc["username"], doc

        def update(self, indict):
            self._users.update({indict.keys()[0]:indict.values()[0]},
                {"$set":{indict.keys()[1]:indict.values()[1]}})

        def get(self, item, default=None):
            return self._users.find_one({"username":item})

    class Roles(dict):
        """Role document: {"special": 200, "admin": 100, "user": 50}
           This means we want to make sure to store int, not str
        """
        def __init__(self,roles_collection=None, *args, **kwargs):
            if roles_collection:
                self._roles = roles_collection
            else:
                raise MongoException("Roles collection not defined")

        def __getitem__(self, item):
            role = self._roles.find_one({"role":item})
            if role:
                return role["level"]
            return None

        def __setitem__(self, key, value):
            # allow the following syntax:
            # roles['admin'] = 10
            # means: {"role":"admin", "level":10}
            doc = value
            if not isinstance(doc, dict):
                doc = {"$set": {"level":int(value)}}
            self._roles.update({"role":key}, doc, safe=True, upsert=True)

        def __contains__(self, item):
            r =  self._roles.find_one({"role":item})
            return r is not None

        def __delitem__(self, key):
            self._roles.remove({"role": key}, safe=True)

        def __iter__(self):
            all_roles = self._roles.find()
            for u in all_roles:
                yield u

        def __len__(self):
            return self._roles.find().count()

        def pop(self, item, default=None):
            r = self._roles.find_one({"role":item})
            if not r:
                raise KeyError()
            self._roles.remove(r)
            return r

    class PendingRegistrations(dict):

        def __init__(self,pending_registrations_collection=None, *args, **kwargs):
            if pending_registrations_collection:
                self._regs_coll = pending_registrations_collection
            else:
                raise MongoException("Registrations collection not defined")

        def __getitem__(self, item):
            pending_registration = self._regs_coll.find_one({"registration_code":item})
            return pending_registration

        def __setitem__(self, key, value):
            self._regs_coll.update({"registration_code":key}, value, safe=True, upsert=True)

        def __contains__(self, item):
            return self._regs_coll.find_one({"registration_code":item}) is not None

        def __delitem__(self, key):
            self._regs_coll.remove({"registration_code": key}, safe=True)

        def __iter__(self):
            all_regs = self._regs_coll.find()
            for u in all_regs:
                yield u

        def __len__(self):
            return self._regs_coll.find().count()

        def pop(self, item, default=None):
            c = self._regs_coll.find_one({"registration_code":item})
            if not c:
                raise KeyError()
            self._regs_coll.remove(c)
            return c

        def items(self):
            all_users = self._regs_coll.find()
            for doc in all_users:
                yield doc["registration_code"], doc

        def keys(self):
            all_users = self._regs_coll.find()
            for u in all_users:
                yield [u["registration_code"]]

        def get_key_helper(self, index):
            """
            For test_validate_registration we need a key, any key (there is only one).
            """
            reg = self._regs_coll.find_one()
            return reg["registration_code"]