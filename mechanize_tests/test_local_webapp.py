#
# Functional testing using Mechanize.
# A local instance of the example webapp needs to be run on port 8080.
#

import mechanize
import cookielib


class TestUsingMechanize(object):
    def setup(self):
        self.local_url = "http://127.0.0.1:8080%s"
        br = mechanize.Browser()
        # Cookie Jar
        self.cj = cookielib.LWPCookieJar()
        br.set_cookiejar(self.cj)
        # Browser options
        br.set_handle_equiv(True)
        br.set_handle_gzip(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)
        # Want debugging messages?
        # br.set_debug_http(True)
        br.set_debug_redirects(True)
        br.set_debug_responses(True)

        self.br = br

    def teardown(self):
        del (self.local_url)
        del (self.br)
        del (self.cj)

    def openurl(self, path, data=None):
        """Perform GET or POST request"""
        if path in ("", None):
            path = "/"

        if data is not None:
            # Prepare for POST
            for k, v in data.iteritems():
                # FIXME: test POST
                self.br[k] = v

        res = self.br.open(self.local_url % path)
        assert self.br.viewing_html()
        return res

    def submit_form(self, formname, data):
        """Select and submit a form"""
        self.br.select_form(name=formname)

        # Prepare for POST
        for k, v in data.iteritems():
            self.br[k] = v

        res = self.br.submit()
        assert not hasattr(self.br, k)
        return res

    @property
    def cookies(self):
        """Return a list of cookies"""
        return list(self.cj)

    def test_login_and_logout(self):

        assert not self.cookies

        res = self.openurl("/")
        assert not self.cookies

        res = self.submit_form("login", {"username": "admin", "password": "admin"})
        assert "Welcome!" in res.get_data()

        assert len(self.cookies) == 1
        assert self.cookies[0].name == "beaker.session.id"

        res = self.openurl("/logout")
        assert not self.cookies
