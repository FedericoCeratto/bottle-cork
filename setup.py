#!/usr/bin/env python

from setuptools import setup

__version__ = '0.12.0a2'

CLASSIFIERS = map(str.strip,
"""Development Status :: 4 - Beta
Environment :: Web Environment
Framework :: Bottle
Framework :: Flask
Intended Audience :: Developers
License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)
Natural Language :: English
Operating System :: POSIX :: Linux
Operating System :: POSIX :: Linux
Programming Language :: Python
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3.4
Topic :: Internet :: WWW/HTTP :: WSGI
Topic :: Internet :: WWW/HTTP :: WSGI
Topic :: Security
Topic :: Software Development :: Libraries :: Python Modules
Topic :: Software Development :: Libraries :: Python Modules
""".splitlines())

setup(
    name="bottle-cork",
    version=__version__,
    author="Federico Ceratto",
    author_email="federico.ceratto@gmail.com",
    description="Authentication/Authorization library for Bottle",
    license="LGPLv3+",
    url="http://cork.firelet.net/",
    long_description="Cork is a simple Authentication/Authorization library"
        "for the Bottle and Flask web frameworks.",
    classifiers=CLASSIFIERS,
    install_requires=[
        'Bottle',
        'pycrypto',
    ],
    extras_require={
        'scrypt': ["scrypt>=0.6.1"],
    },
    packages=['cork'],
    platforms=['Linux'],
)
