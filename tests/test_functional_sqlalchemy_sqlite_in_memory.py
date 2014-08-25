# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing - test the Cork module against an in-memory SQLite DB using the
# SqlAlchemyBackend backend module

from nose import SkipTest
from nose.tools import assert_raises, raises, with_setup

from cork import Cork, AAAException, AuthException
from cork.backends import SqlAlchemyBackend
import os
import testutils

def connect_to_test_db():

    if os.environ.get('TRAVIS', False):
        # Using Travis-CI - https://travis-ci.org/
        password = ''
        db_name = 'myapp_test'
    else:
        password = ''
        db_name = 'cork_functional_test'

    return SqlAlchemyBackend('sqlite:///:memory:', initialize=True)


class Conf(object):

    def setup_test_db(self):

        mb = connect_to_test_db()

        ## Purge DB
        mb._drop_all_tables()
        #mb.users.empty_table()
        #mb.roles.empty_table()
        #mb.pending_registrations.empty_table()

        assert len(mb.roles) == 0
        assert len(mb.users) == 0

        # Create roles
        mb.roles.insert({'role': 'special', 'level': 200})
        mb.roles.insert({'role': 'admin', 'level': 100})
        mb.roles.insert({'role': 'editor', 'level': 60})
        mb.roles.insert({'role': 'user', 'level': 50})

        # Create admin
        mb.users.insert({
            "username": "admin",
            "email_addr": "admin@localhost.local",
            "desc": "admin test user",
            "role": "admin",
            "hash": "cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=",
            "creation_date": "2012-10-28 20:50:26.286723",
            "last_login": "2012-10-28 20:50:26.286723"
        })
        assert len(mb.roles) == 4
        assert len(mb.users) == 1

        return mb

    def purge_test_db(self):
        # Purge DB
        mb = connect_to_test_db()
        mb._drop_all_tables()


class TestSQLAlchemyUnauth(Conf, testutils.DatabaseInteractionAsUnauthenticated):
    pass

class TestSQLAlchemyAdmin(Conf, testutils.DatabaseInteractionAsAdmin):
    pass
