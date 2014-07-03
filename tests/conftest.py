
import pytest

from cork import Cork

@pytest.fixture
def mytmpdir(tmpdir):
    """Setup tmp directory with test files
    """
    tmpdir.mkdir('views')
    tmpdir.join('users.json').write("""{"admin": {"email_addr": null, "desc": null, "role": "admin", "hash": "69f75f38ac3bfd6ac813794f3d8c47acc867adb10b806e8979316ddbf6113999b6052efe4ba95c0fa9f6a568bddf60e8e5572d9254dbf3d533085e9153265623", "creation_date": "2012-04-09 14:22:27.075596"}}""")
    tmpdir.join('roles.json').write("""{"special": 200, "admin": 100, "user": 50}""")
    tmpdir.join('register.json').write("""{}""")
    tmpdir.join('registration_email.tpl').write("""Username:{{username}} Email:{{email_addr}} Code:{{registration_code}}""")
    tmpdir.join('password_reset_email.tpl').write("""Username:{{username}} Email:{{email_addr}} Code:{{reset_code}}""")
    return tmpdir

@pytest.fixture
def aaa(mytmpdir):
    aaa = Cork(mytmpdir, smtp_server='localhost', email_sender='test@localhost')
    return aaa

