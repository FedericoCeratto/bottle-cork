#!/usr/bin/env python
#
#
# Regenerate files in example_conf

from datetime import datetime
from cork import Cork, JsonBackend

def populate_conf_directory():

    backend = JsonBackend(
        'example_conf',
        users_fname='users',
        roles_fname='roles',
        pending_reg_fname='register',
        initialize=True
    )

    cork = Cork(backend)

    cork._store.roles['admin'] = 100
    cork._store.roles['editor'] = 60
    cork._store.roles['user'] = 50
    cork._store._savejson('roles', cork._store.roles)

    tstamp = str(datetime.utcnow())
    username = password = 'admin'
    cork._store.users[username] = {
        'role': 'admin',
        'hash': cork._hash(username, password),
        'email_addr': username + '@localhost.local',
        'desc': username + ' test user',
        'creation_date': tstamp
    }

    username = password = ''
    cork._store.users[username] = {
        'role': 'user',
        'hash': cork._hash(username, password),
        'email_addr': username + '@localhost.local',
        'desc': username + ' test user',
        'creation_date': tstamp
    }
    cork._store._save_users()

    print "Json files created. "

if __name__ == '__main__':
    populate_conf_directory()


