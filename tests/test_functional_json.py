# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Unit testing - test the Cork module against a Json-based db using the
# JsonBackend backend module

from nose import SkipTest
from nose.tools import assert_raises, raises, with_setup
from time import time
import os
import shutil

from cork import Cork, AAAException, AuthException
from cork.backends import JsonBackend
import testutils

class Conf(object):

    def setup_test_db(self):
        """Setup test directory with valid JSON files"""
        testdir = testutils.pick_temp_directory()
        os.mkdir(testdir + '/views')
        with open("%s/users.json" % testdir, 'w') as f:
            f.write("""{"admin": {"email_addr": "admin@localhost.local", "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596"}}""")
        with open("%s/roles.json" % testdir, 'w') as f:
            f.write("""{"special": 200, "admin": 100, "user": 50, "editor": 60}""")
        with open("%s/register.json" % testdir, 'w') as f:
            f.write("""{}""")
        with open("%s/views/registration_email.tpl" % testdir, 'w') as f:
            f.write("""Username:{{username}} Email:{{email_addr}} Code:{{registration_code}}""")
        with open("%s/views/password_reset_email.tpl" % testdir, 'w') as f:
            f.write("""Username:{{username}} Email:{{email_addr}} Code:{{reset_code}}""")
        print("setup done in %s" % testdir)

        #jb = JsonBackend(testdir, initialize=True)
        jb = JsonBackend(testdir)

        self.__testdir = testdir
        return jb

    def purge_test_db(self):
        global cookie_name
        cookie_name = None
        if self.__testdir:
            shutil.rmtree(self.__testdir)
            self.__testdir = None

    def test_iteritems_on_users(self):
        for k, v in self.aaa._store.users.iteritems():
            expected_dkeys = set(('hash', 'email_addr', 'role', 'creation_date',
                'desc'))
            dkeys = set(v.keys())

            extra = dkeys - expected_dkeys
            assert not extra, "Unexpected extra keys: %s" % repr(extra)

            missing = expected_dkeys - dkeys
            assert not missing, "Missing keys: %s" % repr(missing)

class TestUnauth(Conf, testutils.DatabaseInteractionAsUnauthenticated):
    pass

class TestAdmin(Conf, testutils.DatabaseInteractionAsAdmin):
    pass
