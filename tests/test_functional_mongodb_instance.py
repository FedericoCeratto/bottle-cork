# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing - test the Cork module against a real MongoDB instance
# running on localhost.

from base64 import b64encode, b64decode
from nose import SkipTest
from nose.tools import assert_raises, raises, with_setup
from time import time
import bottle
import mock
import os
import shutil

from cork import Cork, AAAException, AuthException
from cork.backends import MongoDBBackend
import testutils

testdir = None  # Test directory

class Conf(object):

    def setup_test_db(self):
        mb = MongoDBBackend(db_name='cork-functional-test', initialize=True)

        # Purge DB
        mb.users._coll.drop()
        mb.roles._coll.drop()
        mb.pending_registrations._coll.drop()

        # Create admin
        mb.users._coll.insert({
            "login": "admin",
            "email_addr": "admin@localhost.local",
            "desc": "admin test user",
            "role": "admin",
            "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
            "creation_date": "2012-10-28 20:50:26.286723"
        })

        # Create users
        mb.roles._coll.insert({'role': 'special', 'val': 200})
        mb.roles._coll.insert({'role': 'admin', 'val': 100})
        mb.roles._coll.insert({'role': 'editor', 'val': 60})
        mb.roles._coll.insert({'role': 'user', 'val': 50})

        return mb

    def purge_test_db(self):
        # Purge DB
        mb = MongoDBBackend(db_name='cork-functional-test', initialize=True)
        mb.users._coll.drop()
        mb.roles._coll.drop()


    def test_iteritems_on_users(self):
        for k, v in self.aaa._store.users.iteritems():
            #assert isinstance(k, str)
            #assert isinstance(v, dict)
            expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date',
                'desc'))
            dkeys = set(v.keys())

            extra = dkeys - expected_dkeys
            assert not extra, "Unexpected extra keys: %s" % repr(extra)

            missing = expected_dkeys - dkeys
            assert not missing, "Missing keys: %s" % repr(missing)


class TestMongoDBUnauth(Conf, testutils.DatabaseInteractionAsUnauthenticated):
    pass

class TestMongoDBAdmin(Conf, testutils.DatabaseInteractionAsAdmin):
    pass
