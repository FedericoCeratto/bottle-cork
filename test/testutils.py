import sys
import tempfile

def pick_conf_directory():
    """Select a temporary directory for the test files.
    Set the tmproot global variable.
    """
    if sys.platform == 'linux2':
        # In-memory filesystem allows faster testing.
        return "/dev/shm"

    return  tempfile.mkdtemp()

