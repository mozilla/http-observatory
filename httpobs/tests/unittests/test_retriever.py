import random
import string
from unittest import TestCase

import requests

from httpobs.scanner.retriever import get_duplicate_header_values, retrieve_all
from httpobs.tests.utils import empty_requests


class TestRetriever(TestCase):
    def test_retrieve_non_existent_domain(self):
        domain = ''.join(random.choice(string.ascii_lowercase) for _ in range(223)) + '.net'
        reqs = retrieve_all(domain)

        self.assertIsNone(reqs['responses']['auto'])
        self.assertIsNone(reqs['responses']['cors'])
        self.assertIsNone(reqs['responses']['http'])
        self.assertIsNone(reqs['responses']['https'])
        self.assertIsNone(reqs['session'])

        self.assertEquals(domain, reqs['hostname'])
        self.assertEquals({}, reqs['resources'])

    def test_retrieve_mdn(self):
        reqs = retrieve_all('developer.mozilla.org')

        # Various things we know about developer.mozilla.org
        self.assertIsNotNone(reqs['resources']['__path__'])
        self.assertIsNotNone(reqs['resources']['/robots.txt'])
        self.assertIsNone(reqs['resources']['/clientaccesspolicy.xml'])
        self.assertIsNone(reqs['resources']['/crossdomain.xml'])

        self.assertIsInstance(reqs['responses']['auto'], requests.Response)
        self.assertIsInstance(reqs['responses']['cors'], requests.Response)
        self.assertIsInstance(reqs['responses']['http'], requests.Response)
        self.assertIsInstance(reqs['responses']['https'], requests.Response)
        self.assertIsInstance(reqs['session'], requests.Session)

        self.assertEquals(reqs['hostname'], 'developer.mozilla.org')

        self.assertEquals('text/html', reqs['responses']['auto'].headers['Content-Type'][0:9])
        self.assertEquals(1, len(reqs['responses']['auto'].history))
        self.assertEquals(200, reqs['responses']['auto'].status_code)
        self.assertEquals('https://developer.mozilla.org/en-US/', reqs['responses']['auto'].url)

    def test_retrieve_invalid_cert(self):
        reqs = retrieve_all('expired.badssl.com')

        self.assertFalse(reqs['responses']['auto'].verified)

    def test_multiple_csp_headers_in_http(self):
        reqs = empty_requests()

        reqs['responses']['auto'].raw.headers.add('Content-Security-Policy', "script-src 'unsafe-inline'")
        reqs['responses']['auto'].raw.headers.add('Content-Security-Policy', 'img-src https://google.com')

        self.assertEquals(
            get_duplicate_header_values(reqs['responses']['auto'], 'Content-Security-Policy'),
            ["script-src 'unsafe-inline'", 'img-src https://google.com'],
        )
