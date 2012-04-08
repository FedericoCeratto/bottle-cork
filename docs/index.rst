.. Cork documentation master file, created by
   sphinx-quickstart on Sun Apr  8 13:40:17 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Cork - Authentication for the Bottle web framework
================================

Cork provides a simple set of methods to implement Authentication and Authorization in web applications based on Bottle.

It is designed to stay out of the way and let you focus on what your application should do.

Features
--------

* Cork is designed for web application with a relatively small userbase. User credentials are stored in JSON files.

* Simple role-based authentication. User are authorized by role e.g. 'admin', 'user', 'editor'. Admin users can create and delete other user account and roles.

* Thread safe and easy to tweak


Roadmap
-------

* Password reset function

* Additional hooks to provide logging or user-defined functions in case of login()/require() failure

* Decoupling of authentication logic from data storage to allow multiple backends e.g. a key/value database


Basic usage
-----------


Example of a web application::

    from cork import Cork

    # Use users.json and roles.json in the local example_conf directory
    aaa = Cork('example_conf')

    @bottle.route('/login', method='POST')
    def login():
        username = request.POST.get('user', '')
        password = request.POST.get('pwd', '')
        aaa.login(username, password, redirect='/login')

    @bottle.route('/logout')
    def logout():
        aaa.current_user.logout(redirect='/login')

    @bottle.route('/')
    def index():
        """Only authenticated users can see this"""
        aaa.require(fail_redirect='/sorry_page')
        return 'Welcome!'

    @bottle.route('/admin')
    def admin():
        """Only admin users can see this"""
        aaa.require(role='admin', fail_redirect='/sorry_page')
        return 'Welcome administrators'

    @bottle.view('login_form')
    @bottle.route('/login')
    def login_form():
        return

    # Web application main

    def main():

        session_opts = {
            'session.type': 'cookie',
            'session.validate_key': True,
        }

        # Setup Beaker middleware to handle sessions and cookies
        app = bottle.default_app()
        app = SessionMiddleware(app, session_opts)

        # Start the Bottle webapp
        bottle.run(app=app, reloader=True)

    if __name__ == "__main__":
        main()

Code documentation
------------------

.. toctree::
   :maxdepth: 2


.. automodule:: cork
    :members:
    :inherited-members:
    :undoc-members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

