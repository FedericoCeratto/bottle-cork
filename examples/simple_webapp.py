
import bottle
# #  Bottle methods  # #

def pg(name, default=''):
    return request.POST.get(name, default).strip()



@bottle.route('/login', method='POST')
def login():
    """ """
    s = bottle.request.environ.get('beaker.session')
    if 'username' in s:  # user is authenticated <--> username is set
        say("Already logged in as \"%s\"." % s['username'])
        return {'logged_in': True}
    user = pg('user', '')
    pwd = pg('pwd', '')
    try:
        users.validate(user, pwd)
        role = users._users[user][0]
        say("User %s with role %s logged in." % (user, role), level="success")
        s['username'] = user
        s['role'] = role
        s = bottle.request.environ.get('beaker.session')
        s.save()
        return {'logged_in': True}
    except (Alert, AssertionError), e:
        say("Login denied for \"%s\": %s" % (user, e), level="warning")
        return {'logged_in': False}



@bottle.route('/logout')
def logout():
    s = bottle.request.environ.get('beaker.session')
    if 'username' in s:
        s.delete()
        say('User logged out.')
    else:
        say('User already logged out.', level='warning')

