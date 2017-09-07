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

    def test_multiple_http_equivs(self):
        reqs = empty_requests('test_parse_http_equiv_headers_csp_multiple_http_equiv1.html')

        self.assertEquals(reqs['responses']['auto'].http_equiv['Content-Security-Policy'],
                          "default-src 'none'; object-src 'none'; media-src 'none';; connect-src 'self'; " +
                          "font-src 'self'; child-src 'self'; img-src 'self'; style-src 'self' " +
                          "'nonce-gAeQO8jI4VJCsrsXkcUVRCzQjiihKteQ; script-src 'self' 'unsafe-inline' " +
                          "'nonce-gAeQO8jI4VJCsrsXkcUVRCzQjiihKteQ'")
