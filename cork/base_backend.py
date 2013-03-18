
class Backend(object):
    pass

def ni(*args, **kwargs):
    raise NotImplementedError

class Table(object):
    __len__ = ni
    __contains__ = ni
    __setitem__ = ni
    __getitem__ = ni
    __iter__ = ni
    iteritems = ni

