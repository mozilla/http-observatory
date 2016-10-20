from unittest import TestCase
from unittest.mock import patch

from httpobs.scanner.utils import valid_hostname


class TestValidHostname(TestCase):
    def test_valid_hostname(self):
        # TODO: Try to find a site with www.site.foo but not site.foo
        self.assertTrue(valid_hostname('mozilla.org'))
        self.assertTrue(valid_hostname('www.mozilla.org'))

    def test_invalid_hostname(self):
        self.assertFalse(valid_hostname('.com'))
        self.assertFalse(valid_hostname('foo'))
        self.assertFalse(valid_hostname('localhost'))
        self.assertFalse(valid_hostname('intranet'))
        self.assertFalse(valid_hostname('_spf.google.com'))  # no A records
        self.assertFalse(valid_hostname('127.0.0.1'))
        self.assertFalse(valid_hostname('2607:f8b0:4009:80b::200e'))

    @patch('httpobs.scanner.utils.SCANNER_ALLOW_LOCALHOST', 'yes')
    def test_valid_localhost(self):
        self.assertTrue(valid_hostname('localhost'))
