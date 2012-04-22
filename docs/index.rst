.. Cork documentation master file, created by
   sphinx-quickstart on Sun Apr  8 13:40:17 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Cork - Authentication for the Bottle web framework
================================

Cork provides a simple set of methods to implement Authentication and Authorization in web applications based on Bottle.

It is designed to stay out of the way and let you focus on what your application should do.

 `Source code <https://github.com/FedericoCeratto/bottle-cork>`_
 - `Downloads <https://github.com/FedericoCeratto/bottle-cork/downloads>`_
 - `Bug tracker <http://github.com/FedericoCeratto/bottle-cork/issues>`_
 - IRC: #bottle on Freenode

**Version 0.1-beta is out!**

Cork is currently **under development** - contributions are very welcome!

Features
--------

* Minimal API

* Designed for web application with moderate userbases. User credentials are stored in JSON files.

* Simple role-based authentication. User are authorized by role e.g. 'admin', 'user', 'editor'.

  * Admin users can create and delete user accounts and roles.

* User registration with email delivery and confirmation

* Thread safe and easy to tweak

* Unit-tested and `code covered <./cover/cork.html>`_

* Multiple backends support (e.g. storing users/roles in a key/value database)

* Password reset function

Roadmap
-------

* Additional hooks to provide logging or user-defined functions in case of login()/require() failure

* Hooks to share session data between multiple hosts


Basic usage
-----------

A fully working example is provided with the Cork `sources <https://github.com/FedericoCeratto/bottle-cork/tree/master/examples>`_

**Example of a web application**::

    from cork import Cork

    # Use users.json and roles.json in the local example_conf directory
    aaa = Cork('example_conf')

    @bottle.route('/login', method='POST')
    def login():
        username = request.POST.get('user', '')
        password = request.POST.get('pwd', '')
        aaa.login(username, password, success_redirect='/', fail_redirect='/login')

    @bottle.route('/logout')
    def logout():
        aaa.current_user.logout(redirect='/login')

    @bottle.route('/')
    def index():
        """Only authenticated users can see this"""
        aaa.require(fail_redirect='/sorry_page')
        return "Welcome %s" % aaa.current_user.username

    @bottle.route('/admin')
    def admin():
        """Only administrators can see this"""
        aaa.require(role='admin', fail_redirect='/sorry_page')
        return 'Welcome administrators'

    @bottle.route('/register', method='POST')
    def register():
        """Users can create new accounts, but only with 'user' role"""
        username = request.POST.get('user', '')
        password = request.POST.get('pwd', '')
        email_addr = request.POST.get('email_addr', '')
        aaa.register(username, password, email_addr)
        return 'Please check your inbox.'


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

