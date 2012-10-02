#!/usr/bin/env python
#
#
# Cork example web application
#
# The following users are already available:
#  admin/admin, demo/demo

import bottle
from beaker.middleware import SessionMiddleware
from cork import Cork, JsonBackend, MongoDbBackend
import logging
import sys

logging.basicConfig(format='localhost - - [%(asctime)s] %(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)


# Use users.json and roles.json in the local example_conf directory
aaa = None
app = None
def configure_app(backend, session_opts):
    assert backend

    global aaa
    aaa = Cork(backend, email_sender='federico.ceratto@gmail.com', smtp_server='mail2.eircom.net')

    global app
    app = bottle.app()
    app = SessionMiddleware(app, session_opts)


# #  Bottle methods  # #

def postd():
    return bottle.request.forms

def post_get(name, default=''):
    return bottle.request.POST.get(name, default).strip()

@bottle.post('/login')
def login():
    """Authenticate users"""
    username = post_get('username')
    password = post_get('password')
    aaa.login(username, password, success_redirect='/', fail_redirect='/login')

@bottle.route('/logout')
def logout():
    aaa.logout()

@bottle.post('/register')
def register():
    """Send out registration email"""
    aaa.register(post_get('username'), post_get('password'), post_get('email_address'))
    return 'Please check your mailbox.'

@bottle.route('/validate_registration/:registration_code')
def validate_registration(registration_code):
    """Validate registration, create user account"""
    aaa.validate_registration(registration_code)
    return 'Thanks. <a href="/login">Go to login</a>'

@bottle.post('/reset_password')
def send_password_reset_email():
    """Send out password reset email"""
    aaa.send_password_reset_email(
        username=post_get('username'),
        email_addr=post_get('email_address')
    )
    return 'Please check your mailbox.'

@bottle.route('/change_password/:reset_code')
@bottle.view('password_change_form')
def change_password(reset_code):
    """Show password change form"""
    return dict(reset_code=reset_code)

@bottle.post('/change_password')
def change_password():
    """Change password"""
    aaa.reset_password(post_get('reset_code'), post_get('password'))
    return 'Thanks. <a href="/login">Go to login</a>'


@bottle.route('/')
def index():
    """Only authenticated users can see this"""
    session = bottle.request.environ.get('beaker.session')
    aaa.require(fail_redirect='/login')
    return 'Welcome! <a href="/admin">Admin page</a> <a href="/logout">Logout</a>'

@bottle.route('/restricted_download')
def restricted_download():
    """Only authenticated users can download this file"""
    aaa.require(fail_redirect='/login')
    return bottle.static_file('static_file', root='.')



# Admin-only pages

@bottle.route('/admin')
@bottle.view('admin_page')
def admin():
    """Only admin users can see this"""
    aaa.require(role='admin', fail_redirect='/sorry_page')
    return dict(
        current_user = aaa.current_user,
        users = aaa.list_users(),
        roles = aaa.list_roles()
    )

@bottle.post('/create_user')
def create_user():
    try:
        aaa.create_user(postd().username, postd().role, postd().password)
        return dict(ok=True, msg='')
    except Exception, e:
        return dict(ok=False, msg=e.message)

@bottle.post('/delete_user')
def delete_user():
    try:
        aaa.delete_user(post_get('username'))
        return dict(ok=True, msg='')
    except Exception, e:
        print repr(e)
        return dict(ok=False, msg=e.message)

@bottle.post('/create_role')
def create_role():
    try:
        aaa.create_role(post_get('role'), post_get('level'))
        return dict(ok=True, msg='')
    except Exception, e:
        return dict(ok=False, msg=e.message)

@bottle.post('/delete_role')
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

def configure(backend_type='jsonbackend'):

    backend = None

    # Use users.json and roles.json in the local example_conf directory
    # Run init_backend.py to initialize the database
    if backend_type == 'jsonbackend':
        backend = JsonBackend(
            'example_conf',
            users_fname='users',
            roles_fname='roles',
            pending_reg_fname='register',
            initialize=False
        )

    # Use 'sampole_webapp' MongoDb database with 'users', 'roles' and 'register' collections.
    # Run init_backend.py to initialize the database
    if backend_type == 'mongobackend':
        backend = MongoDbBackend(
            server = "localhost",
            port = 27017,
            database = "sample_webapp",
            initialize=False,
            users_store="users",
            roles_store="roles",
            pending_regs_store="register",
        )

    session_opts = {
        'session.type': 'cookie',
        'session.validate_key': True,
        'session.cookie_expires': True,
        'session.timeout': 3600 * 24, # 1 day
        'session.encrypt_key': 'please use a random key and keep it secret!',
        }

    configure_app(backend, session_opts)



def main():
    # Start the Bottle webapp
    bottle.debug(True)
    bottle.run(app=app, quiet=False, reloader=True)

if __name__ == "__main__":

    backend_type = None
    if len( sys.argv ) == 2:
        if sys.argv[1] == 'jsonbackend':
            backend_type = 'jsonbackend'
        elif sys.argv[1] == 'mongobackend':
            backend_type = 'mongobackend'
        else:
            print 'usage:'
            print 'python simpple_webapp.py [backend_type]'
            print 'valid backend_types:'
            print 'jsonbackend: json files on the file system'
            print 'mongobackend: MongoDb database'
            print 'default: mongobackend'
    else:
        # default to jsonbackend
        configure('jsonbackend')

    main()
