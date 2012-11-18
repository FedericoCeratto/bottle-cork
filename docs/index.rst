
Cork - Authentication for the Bottle web framework
================================

.. image:: cork.png
   :name: logo

.. sidebar:: Links

 - `Mailing list <https://groups.google.com/forum/?fromgroups#!forum/cork-discuss>`_
 - `Bug tracker <http://github.com/FedericoCeratto/bottle-cork/issues>`_
 - IRC: (`#bottle <http://webchat.freenode.net?channels=bottle&uio=OT10cnVlde>`_) on Freenode
 - `Downloads <http://pypi.python.org/pypi/bottle-cork/>`_
 - `Source code <https://github.com/FedericoCeratto/bottle-cork>`_

Cork provides a simple set of methods to implement Authentication and Authorization in web applications based on `Bottle <http://bottlepy.org>`_.

It is designed to stay out of the way and let you focus on what your application should do.


News:

* 2012-11-18: **Version 0.3 is out!**

  * PBKDF2 hash length check added
  * Multi-platform unit testing

* 2012-10-04: Version 0.2

  * SMTP URL added: support for STARTTLS, SSL and configurable port numbers
  * Bugfix: login() redirects to fail_redirect if an username is not provided
  * Better password hashing, multiple hash formats supported

* 2012-07-09: Version 0.1 - Improved installation
* 2012-06-10: Version 0.1~beta3 - Improved registration and password reset

Cork is under development - contributions are welcome.

Features
--------

* Minimal design, easy to tweak.

* Designed for web application with moderate userbases. User credentials are stored in JSON files.

* Simple role-based authentication. User are authorized by role e.g. 'admin', 'user', 'editor'.

  * Admin users can create and delete user accounts and roles.

* User registration and password reset using email delivery and confirmation.

* Unit-tested and almost fully `code covered <./cover/cork_cork.html>`_

* Multiple backends support (e.g. storing users/roles in a key/value database).

* Thread safe.

Roadmap
-------

* Additional hooks to provide logging or user-defined functions in case of login()/require() failure

* Hooks to share session data between multiple hosts

* Flask support

Basic usage
-----------

Installation::

    $ pip install bottle-cork
    or
    $ easy_install bottle-cork

Use virtualenv on package-based Linux distributions! `Learn why <http://workaround.org/easy-install-debian>`_

A fully working example is provided with the Cork `sources <https://github.com/FedericoCeratto/bottle-cork/downloads>`_

**Example web application**::

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


.. automodule:: cork.cork
    :members:
    :inherited-members:
    :undoc-members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

