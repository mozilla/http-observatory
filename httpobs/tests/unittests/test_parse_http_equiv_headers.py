from unittest import TestCase

from httpobs.tests.utils import empty_requests


class TestHTTPEquivHeaders(TestCase):
    def setUp(self):
        self.reqs = None

    def tearDown(self):
        self.reqs = None

    def test_header_match(self):
        reqs = empty_requests('test_parse_http_equiv_headers_csp1.html')

        self.assertEquals(reqs['responses']['auto'].http_equiv, {'Content-Security-Policy': 'default-src \'none\';'})

    def test_header_case_insensitivity(self):
        reqs = empty_requests('test_parse_http_equiv_headers_csp1.html')

        self.assertEquals(reqs['responses']['auto'].http_equiv['content-security-policy'], 'default-src \'none\';')
        self.assertEquals(reqs['responses']['auto'].http_equiv['content-SECURITY-policy'], 'default-src \'none\';')
