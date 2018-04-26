from unittest import TestCase

from httpobs.scanner.analyzer.content import contribute, subresource_integrity
from httpobs.tests.utils import empty_requests


class TestContribute(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_no_contribute_mozilla(self):
        result = contribute(self.reqs)

        self.assertEquals('contribute-json-not-implemented', result['result'])
        self.assertFalse(result['pass'])

    def test_no_contribute_not_mozilla(self):
        self.reqs['responses']['auto'].url = 'https://github.com'

        result = contribute(self.reqs)

        self.assertEquals('contribute-json-only-required-on-mozilla-properties', result['result'])
        self.assertTrue(result['pass'])

    def test_invalid_json(self):
        self.reqs['resources']['/contribute.json'] = 'foobar'

        result = contribute(self.reqs)

        self.assertEquals('contribute-json-invalid-json', result['result'])
        self.assertFalse(result['pass'])

    def test_contribute_too_large(self):
        self.reqs['resources']['/contribute.json'] = '{"name": "' + 'foo' * 100000 + '"}'

        result = contribute(self.reqs)

        self.assertEquals(result['data'], {})

    def test_with_required_keys(self):
        self.reqs['resources']['/contribute.json'] = """
        {
            "name": "Bedrock",
            "description": "The app powering www.mozilla.org.",
            "repository": {
                "url": "https://github.com/mozilla/bedrock",
                "license": "MPL2",
                "tests": "https://travis-ci.org/mozilla/bedrock/"
            },
            "participate": {
                "home": "https://wiki.mozilla.org/Webdev/GetInvolved/mozilla.org",
                "docs": "http://bedrock.readthedocs.org/",
                "mailing-list": "https://www.mozilla.org/about/forums/#dev-mozilla-org",
                "irc": "irc://irc.mozilla.org/#www"
            },
            "bugs": {
                "list": "https://bugzilla.mozilla.org/describecomponents.cgi?product=www.mozilla.org",
                "report": "https://bugzilla.mozilla.org/enter_bug.cgi?product=www.mozilla.org",
                "mentored": "https://bugzilla.mozilla.org/buglist.cgi?f1=bug_mentor&o1=..."
            },
            "urls": {
                "prod": "https://www.mozilla.org",
                "stage": "https://www.allizom.org",
                "dev": "https://www-dev.allizom.org",
                "demo1": "https://www-demo1.allizom.org",
                "demo2": "https://www-demo2.allizom.org",
                "demo3": "https://www-demo3.allizom.org",
                "demo4": "https://www-demo4.allizom.org",
                "demo5": "https://www-demo5.allizom.org"
            },
            "keywords": [
                "python",
                "less-css",
                "django",
                "html5",
                "jquery"
            ]
        }"""

        result = contribute(self.reqs)

        self.assertEquals('contribute-json-with-required-keys', result['result'])
        self.assertTrue(result['pass'])

    def test_missing_required_keys(self):
        self.reqs['resources']['/contribute.json'] = """
        {
            "name": "Bedrock",
            "description": "The app powering www.mozilla.org.",
            "repository": {
                "url": "https://github.com/mozilla/bedrock",
                "license": "MPL2",
                "tests": "https://travis-ci.org/mozilla/bedrock/"
            },
            "participate": {
                "home": "https://wiki.mozilla.org/Webdev/GetInvolved/mozilla.org",
                "docs": "http://bedrock.readthedocs.org/",
                "mailing-list": "https://www.mozilla.org/about/forums/#dev-mozilla-org",
                "irc": "irc://irc.mozilla.org/#www"
            },
            "urls": {
                "prod": "https://www.mozilla.org",
                "stage": "https://www.allizom.org",
                "dev": "https://www-dev.allizom.org",
                "demo1": "https://www-demo1.allizom.org",
                "demo2": "https://www-demo2.allizom.org",
                "demo3": "https://www-demo3.allizom.org",
                "demo4": "https://www-demo4.allizom.org",
                "demo5": "https://www-demo5.allizom.org"
            },
            "keywords": [
                "python",
                "less-css",
                "django",
                "html5",
                "jquery"
            ]
        }"""

        result = contribute(self.reqs)

        self.assertEquals('contribute-json-missing-required-keys', result['result'])
        self.assertFalse(result['pass'])


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
        self.reqs['resources']['__path__'] = """
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
