
Cork - Authentication for the Bottle web framework
==================================================

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


Cork is under development - contributions are welcome.

Features
--------

* Minimal design, easy to tweak.

* Multiple storage backends are supported:

  * `MySQL <http://mysql.com>`_, `MariaDB <http://mariadb.com>`_, `PostgreSQL <http://postgresql.org>`_ using `SQLAlchemy <http://sqlalchemy.org/>`_

  * `MongoDb <http://mongodb.com>`_

  * `SQLite <http://sqlite.com>`_

  * Local JSON files for low-traffic web applications

* Simple role-based authentication. User are authorized by role e.g. 'admin', 'user', 'editor'.

  * Admin users can create and delete user accounts and roles.

* User registration and password reset using email delivery and confirmation.

* Unit-tested and `code covered <./cover/cork_cork.html>`_


News
----

* 2013-09-22: Version 0.10

  * Decorator support added. #6
  * 'last_login' user attribute added. #47 #48
  * In-memory SQLite Database support added.
  * CONTRIBUTORS.txt added
  * Bugfix: configurable role table name #46
  * Bugfix: email address #42

* 2013-07-07: Version 0.9

  * SQLite support added.
  * SMTP URL bugfix #38

* 2013-05-27: Version 0.8

  * scrypt implemented, bugfixes #34 #35 #32

* 2013-04-08: Version 0.7

  * Configurable backend support added.
  * SQLAlchemy and MongoDB support added.
  * Closes: #8 #27 #28

* 2013-01-27: Version 0.6

  * More flexible file naming in JsonBackend.
  * Fixed function to update user's email address.
  * More informative log message for missing Pycrypto.


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

Fully working examples are provided with the `sources <https://github.com/FedericoCeratto/bottle-cork/downloads>`_

* :doc:`example_webapp_decorated`

* :doc:`example_webapp`


Code documentation
------------------


:doc:`cork_module`

:doc:`sqlalchemy_backend`

:doc:`mongodb_backend`

:doc:`sqlite_backend`


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
