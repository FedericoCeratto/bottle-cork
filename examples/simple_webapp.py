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

def post_get(name, default=''):
    return bottle.request.POST.get(name, default).strip()

@bottle.route('/login', method='POST')
def login():
    """Authenticate users"""
    username = post_get('user')
    password = post_get('pwd')
    aaa.login(username, password, success_redirect='/', fail_redirect='/login')

@bottle.route('/logout')
def logout():
    aaa.current_user.logout()

@bottle.route('/')
def index():
    """Only authenticated users can see this"""
    session = bottle.request.environ.get('beaker.session')
    aaa.require(fail_redirect='/sorry_page')
    return 'Welcome! <a href="/admin">Admin page</a>'

# Admin-only pages

@bottle.route('/admin')
@bottle.view('admin_page')
def admin():
    """Only admin users can see this"""
    aaa.require(role='admin', fail_redirect='/sorry_page')
    return {}

@bottle.route('/create_user', method='POST')
def create_user():
    try:
        aaa.create_user(
            post_get('username'),
            post_get('role'),
            post_get('password')
        )
        return dict(ok=True, msg='')
    except Exception, e:
        return dict(ok=False, msg=e.message)

@bottle.route('/delete_user', method='POST')
def delete_user():
    try:
        aaa.delete_user(post_get('username'))
        return dict(ok=True, msg='')
    except Exception, e:
        return dict(ok=False, msg=e.message)

@bottle.route('/create_role', method='POST')
def create_role():
    try:
        aaa.create_role(post_get('role'), post_get('level'))
        return dict(ok=True, msg='')
    except Exception, e:
        return dict(ok=False, msg=e.message)

@bottle.route('/delete_role', method='POST')
def delete_role():
    try:
        aaa.delete_role(post_get('role'))
        return dict(ok=True, msg='')
    except Exception, e:
        return dict(ok=False, msg=e.message)

# Static pages

@bottle.route('/login')
@bottle.view('login_form')
def login_form():
    """Serve login form"""
    return {}

@bottle.route('/sorry_page')
def sorry_page():
    """Serve sorry page"""
    return '<p>Sorry, you are not authorized to perform this action</p>'

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
    bottle.debug(True)
    bottle.run(app=app, quiet=False, reloader=True)

if __name__ == "__main__":
    main()
