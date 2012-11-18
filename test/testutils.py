import sys
import tempfile
import shutil

def pick_temp_directory():
    """Select a temporary directory for the test files.
    Set the tmproot global variable.
    """
    if sys.platform == 'linux2':
        # In-memory filesystem allows faster testing.
        return "/dev/shm"

    return  tempfile.mkdtemp()

def purge_temp_directory(test_dir):
    """Remove the test directory"""
    assert test_dir
    shutil.rmtree(test_dir)
