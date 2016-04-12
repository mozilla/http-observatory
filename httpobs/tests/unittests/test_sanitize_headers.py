from unittest import TestCase

from httpobs.scanner.utils import sanitize_headers


class TestValidHostname(TestCase):
    def test_valid_size_headers(self):
        # TODO: Try to find a site with www.site.foo but not site.foo
        headers = {
            'Content-Type': 'text/html',
            'Location': '/whatever'
        }

        self.assertEquals(headers, sanitize_headers(headers))

    def test_huge_headers(self):
        headers = {
            'Content-Type': 'text/html',
            'Location': '/whatever' * 10000
        }

        self.assertIsNone(sanitize_headers(headers))
