#!/usr/bin/env python
#
#
# Regenerate mongodb database for sample_webapp

from datetime import datetime
from cork import Cork, MongoDbBackend
import pymongo

def initialize_mongodb():
    """
    Create a mongo database named 'sample_webapp'
    Initialize with user 'admin', password 'admin' and roles
    admin and user.
    """

    # We need to get a Cork instance in order to use _hash.
    backend = MongoDbBackend(
        server = "localhost",
        port = 27017,
        database = "sample_webapp",
        initialize=True,
        users_store="users",
        roles_store="roles",
        pending_regs_store="register",
    )
    cork = Cork(backend)

    # Let's use pymongo directly, even though we could have used cork's interface.
    # TODO: Create indices
    connection = pymongo.Connection("localhost",27017)
    db = connection["sample_webapp"]
    db["users"].drop()
    db["roles"].drop()
    db["register"].drop()

    username = password = "admin"
    db["users"].save(
        {
            'username':username,
            'role': "admin",
            'hash': cork._hash(username, password),
            #'hash': "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623",
            'email_addr': None,
            'desc': None,
            'creation_date': "2012-04-09 14:22:27.075596"
        }, safe=True
    )
    username = password = "user"
    tstamp = str(datetime.utcnow())
    db["users"].save(
        {
            "username": username, # when using mongodb backend, user and pwd cannot be blank.
            'role': 'user',
            'hash': cork._hash(username, password),
            'email_addr': username + '@localhost.local',
            'desc': username + ' test user',
            'creation_date': tstamp
        }, safe=True
    )

    db["roles"].save(
        {"role":"admin", "level":100}
    )
    db["roles"].save(
        {"role":"editor", "level":60}
    )
    db["roles"].save(
        {"role":"user", "level":50}
    )

    print "MongoDb initialized."

if __name__ == '__main__':
    initialize_mongodb()



