# Cork - Authentication module for tyyhe Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under GPLv3+ license, see LICENSE.txt
#
# Base Backend.
#

from abc import ABCMeta, abstractmethod

class BackendIOException(Exception):
    """Generic Backend I/O Exception"""
    pass

def ni(*args, **kwargs):
    raise NotImplementedError

class Backend(object):
    """Base Backend class - to be subclassed by real backends."""
    __metaclass__ = ABCMeta

    save_users = ni
    save_roles = ni
    save_pending_registrations = ni

    @abstractmethod
    def initialize(self):
        pass

class Table(object):
    """Base Table class - to be subclassed by real backends."""
    __len__ = ni
    __contains__ = ni
    __setitem__ = ni
    __getitem__ = ni
    __iter__ = ni
    iteritems = ni

