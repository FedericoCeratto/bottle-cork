#!/usr/bin/env python
#
#
# Cork example web application
#
# The following users are already available:
#  admin/admin, demo/demo

import bottle
from beaker.middleware import SessionMiddleware
from cork import Cork

# Use users.json and roles.json in the local example_conf directory
aaa = Cork('example_conf')


# #  Bottle methods  # #

def get_post_param(name, default=''):
    return request.POST.get(name, default).strip()

@bottle.view('login_form')
@bottle.route('/login')
def login_form():
    """Serve login form"""
    return 

@bottle.route('/login', method='POST')
def login():
    """Authenticate users"""
    username = get_post_param('user', '')
    password = get_post_param('pwd', '')

    aaa.login(redirect='/login')

    #login successful
    return "Welcome!"

@bottle.route('/logout')
def logout():
    s = bottle.request.environ.get('beaker.session')
    if 'username' in s:
        s.delete()
        say('User logged out.')
    else:
        say('User already logged out.', level='warning')

@bottle.route('/')
def index():
    """Only authenticated users can see this"""
    aaa.login(redirect='/login')
    return 'Welcome!'

# #  Web application main  # #

def main():

    session_opts = {
        'session.type': 'cookie',
        'session.validate_key': True,
    }

    # Setup Beaker middleware to handle sessions and cookies
    app = bottle.default_app()
    app = SessionMiddleware(app, session_opts)

    # Start the Bottle webapp
    bottle.bottle_debug = True
    bottle.debug = True
    bottle.run(app=app, reloader=True)

if __name__ == "__main__":
    main()
