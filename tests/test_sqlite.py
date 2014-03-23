# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing - test the Cork module against an in-memory SQLite DB using
# the SQLiteBackend backend module.

from nose import SkipTest
from nose.tools import assert_raises, raises, with_setup

from cork import Cork, AAAException, AuthException
from cork.backends import SQLiteBackend
import testutils

class Conf(object):

    def setup_test_db(self):
        b = SQLiteBackend(':memory:', initialize=True)
        b.connection.executescript("""
            INSERT INTO users (username, email_addr, desc, role, hash, creation_date) VALUES
            (
                'admin',
                'admin@localhost.local',
                'admin test user',
                'admin',
                'cLzRnzbEwehP6ZzTREh3A4MXJyNo+TV8Hs4//EEbPbiDoo+dmNg22f2RJC282aSwgyWv/O6s3h42qrA6iHx8yfw=',
                '2012-10-28 20:50:26.286723'
            );
            INSERT INTO roles (role, level) VALUES ('special', 200);
            INSERT INTO roles (role, level) VALUES ('admin', 100);
            INSERT INTO roles (role, level) VALUES ('editor', 60);
            INSERT INTO roles (role, level) VALUES ('user', 50);
        """)
        return b

class TestSQLiteUnauth(Conf, testutils.DatabaseInteractionAsUnauthenticated):
    pass

class TestSQLiteAdmin(Conf, testutils.DatabaseInteractionAsAdmin):
    pass





