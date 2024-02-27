from unittest import TestCase

from httpobs.scanner.analyzer.content import subresource_integrity
from httpobs.tests.utils import empty_requests


class TestSubResourceIntegrity(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_no_scripts(self):
        self.reqs = empty_requests('test_content_sri_no_scripts.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-but-no-scripts-loaded', result['result'])
        self.assertTrue(result['pass'])

    def test_not_html(self):
        # invalid html
        self.reqs['resources']['__path__'] = '<![..]>'

        result = subresource_integrity(self.reqs)

        self.assertEquals('html-not-parsable', result['result'])
        self.assertFalse(result['pass'])

        # json, like what an API might return
        self.reqs['responses']['auto'].headers['Content-Type'] = 'application/json'
        self.reqs['resources'][
            '__path__'
        ] = """
        {
            'foo': 'bar'
        }
        """

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-response-not-html', result['result'])
        self.assertTrue(result['pass'])

    def test_same_origin(self):
        self.reqs = empty_requests('test_content_sri_sameorigin1.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals(result['result'], 'sri-not-implemented-but-all-scripts-loaded-from-secure-origin')
        self.assertTrue(result['pass'])

        # On the same second-level domain, but without a protocol
        self.reqs = empty_requests('test_content_sri_sameorigin3.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-and-external-scripts-not-loaded-securely', result['result'])
        self.assertFalse(result['pass'])

        # On the same second-level domain, with https:// specified
        self.reqs = empty_requests('test_content_sri_sameorigin2.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-but-all-scripts-loaded-from-secure-origin', result['result'])
        self.assertTrue(result['pass'])

        # And the same, but with a 404 status code
        self.reqs['responses']['auto'].status_code = 404

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-but-all-scripts-loaded-from-secure-origin', result['result'])
        self.assertTrue(result['pass'])

    def test_implemented_external_scripts_https(self):
        # load from a remote site
        self.reqs = empty_requests('test_content_sri_impl_external_https1.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-implemented-and-external-scripts-loaded-securely', result['result'])
        self.assertTrue(result['pass'])

        # load from an intranet / localhost
        self.reqs = empty_requests('test_content_sri_impl_external_https2.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-implemented-and-external-scripts-loaded-securely', result['result'])
        self.assertTrue(result['pass'])

    def test_implemented_same_origin(self):
        self.reqs = empty_requests('test_content_sri_impl_sameorigin.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-implemented-and-all-scripts-loaded-securely', result['result'])
        self.assertTrue(result['pass'])

    def test_not_implemented_external_scripts_https(self):
        self.reqs = empty_requests('test_content_sri_notimpl_external_https.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-but-external-scripts-loaded-securely', result['result'])
        self.assertFalse(result['pass'])

    def test_implemented_external_scripts_http(self):
        self.reqs = empty_requests('test_content_sri_impl_external_http.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-implemented-but-external-scripts-not-loaded-securely', result['result'])
        self.assertFalse(result['pass'])

    def test_implemented_external_scripts_noproto(self):
        self.reqs = empty_requests('test_content_sri_impl_external_noproto.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-implemented-but-external-scripts-not-loaded-securely', result['result'])
        self.assertFalse(result['pass'])

    def test_not_implemented_external_scripts_http(self):
        self.reqs = empty_requests('test_content_sri_notimpl_external_http.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-and-external-scripts-not-loaded-securely', result['result'])
        self.assertFalse(result['pass'])

    def test_not_implemented_external_scripts_noproto(self):
        self.reqs = empty_requests('test_content_sri_notimpl_external_noproto.html')

        result = subresource_integrity(self.reqs)

        self.assertEquals('sri-not-implemented-and-external-scripts-not-loaded-securely', result['result'])
        self.assertFalse(result['pass'])
