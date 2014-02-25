#!/usr/bin/env python
#
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt
#
# Cork example web application
#
# The following users are already available:
#  admin/admin, demo/demo

import flask
from beaker.middleware import SessionMiddleware
from cork import FlaskCork
import logging
import os

logging.basicConfig(format='localhost - - [%(asctime)s] %(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

# Use users.json and roles.json in the local example_conf directory
aaa = FlaskCork('example_conf', email_sender='federico.ceratto@gmail.com', smtp_url='smtp://smtp.magnet.ie')

app = flask.Flask(__name__)
app.debug = True
app.options = {} #FIXME

from flask import jsonify

#session_opts = {
#    'session.cookie_expires': True,
#    'session.encrypt_key': 'please use a random key and keep it secret!',
#    'session.httponly': True,
#    'session.timeout': 3600 * 24,  # 1 day
#    'session.type': 'cookie',
#    'session.validate_key': True,
#}
#app = SessionMiddleware(app, session_opts)


# #  Bottle methods  # #

def post_get(name, default=''):
    v = flask.request.form.get(name, default).strip()
    return str(v)

from cork import Redirect
@app.errorhandler(Redirect)
def redirect_exception_handler(e):
    return flask.redirect(e.message)


@app.route('/login', methods=['POST'])
def login():
    """Authenticate users"""
    username = post_get('username')
    password = post_get('password')
    aaa.login(username, password, success_redirect='/', fail_redirect='/login')

@app.route('/user_is_anonymous')
def user_is_anonymous():
    if aaa.user_is_anonymous:
        return 'True'

    return 'False'

@app.route('/logout')
def logout():
    aaa.logout(success_redirect='/login')


@app.route('/register', methods=['POST'])
def register():
    """Send out registration email"""
    aaa.register(post_get('username'), post_get('password'), post_get('email_address'))
    return 'Please check your mailbox.'


@app.route('/validate_registration/:registration_code')
def validate_registration(registration_code):
    """Validate registration, create user account"""
    aaa.validate_registration(registration_code)
    return 'Thanks. <a href="/login">Go to login</a>'


@app.route('/reset_password', methods=['POST'])
def send_password_reset_email():
    """Send out password reset email"""
    aaa.send_password_reset_email(
        username=post_get('username'),
        email_addr=post_get('email_address')
    )
    return 'Please check your mailbox.'


@app.route('/change_password/:reset_code')
def change_password(reset_code):
    """Show password change form"""
    return flask.render_template('password_change_form',
        reset_code=reset_code)


@app.route('/change_password', methods=['POST'])
def do_change_password():
    """Change password"""
    aaa.reset_password(post_get('reset_code'), post_get('password'))
    return 'Thanks. <a href="/login">Go to login</a>'


@app.route('/')
def index():
    """Only authenticated users can see this"""
    aaa.require(fail_redirect='/login')
    return 'Welcome! <a href="/admin">Admin page</a> <a href="/logout">Logout</a>'


@app.route('/restricted_download')
def restricted_download():
    """Only authenticated users can download this file"""
    aaa.require(fail_redirect='/login')
    return flask.static_file('static_file', root='.')


@app.route('/my_role')
def show_current_user_role():
    """Show current user role"""
    session = flask.request.environ.get('beaker.session')
    print "Session from simple_webapp", repr(session)
    aaa.require(fail_redirect='/login')
    return aaa.current_user.role


# Admin-only pages

@app.route('/admin')
def admin():
    """Only admin users can see this"""
    aaa.require(role='admin', fail_redirect='/sorry_page')
    return flask.render_template('admin_page.html',
        current_user=aaa.current_user,
        users=aaa.list_users(),
        roles=aaa.list_roles()
    )


@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        aaa.create_user(post_get('username'), post_get('role'),
            post_get('password'))
        return jsonify(ok=True, msg='')
    except Exception, e:
        return jsonify(ok=False, msg=e.message)


@app.route('/delete_user', methods=['POST'])
def delete_user():
    try:
        aaa.delete_user(post_get('username'))
        return jsonify(ok=True, msg='')
    except Exception, e:
        print repr(e)
        return jsonify(ok=False, msg=e.message)


@app.route('/create_role', methods=['POST'])
def create_role():
    try:
        aaa.create_role(post_get('role'), post_get('level'))
        return jsonify(ok=True, msg='')
    except Exception, e:
        return jsonify(ok=False, msg=e.message)


@app.route('/delete_role', methods=['POST'])
def delete_role():
    try:
        aaa.delete_role(post_get('role'))
        return jsonify(ok=True, msg='')
    except Exception, e:
        return jsonify(ok=False, msg=e.message)


# Static pages

@app.route('/login')
def login_form():
    """Serve login form"""
    return flask.render_template('login_form.html')


@app.route('/sorry_page')
def sorry_page():
    """Serve sorry page"""
    return '<p>Sorry, you are not authorized to perform this action</p>'


# #  Web application main  # #

app.secret_key = os.urandom(24) #FIXME: why
def main():

    # Start the Bottle webapp
    #bottle.debug(True)
    app.secret_key = os.urandom(24)
    app.run(debug=True, use_reloader=True)

if __name__ == "__main__":
    main()
