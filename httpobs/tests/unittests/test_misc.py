from collections import UserDict
from unittest import TestCase

from httpobs.scanner.analyzer.misc import *
from httpobs.tests.utils import empty_requests


class TestCORS(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_acao_public(self):
        self.reqs['responses']['cors'].headers['Access-Control-Allow-Origin'] = '*'

        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-public-access', result['result'])
        self.assertEquals('*', result['data']['acao'])
        self.assertTrue(result['pass'])

    def test_acao_restricted_with_acao(self):
        self.reqs['responses']['cors'].request.headers['Origin'] = 'https://http-observatory.services.mozilla.com'
        self.reqs['responses']['cors'].headers['Access-Control-Allow-Origin'] = 'https://mozilla.com'

        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-restricted-access', result['result'])
        self.assertTrue(result['pass'])

    def test_acao_universal_with_acao(self):
        self.reqs['responses']['cors'].request.headers['Origin'] = 'https://http-observatory.services.mozilla.com'
        self.reqs['responses']['cors'].headers['Access-Control-Allow-Origin'] = \
            'https://http-observatory.services.mozilla.com'
        self.reqs['responses']['cors'].headers['Access-Control-Allow-Credentials'] = 'true'

        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-universal-access', result['result'])
        self.assertFalse(result['pass'])

    def test_acao_restricted_with_crossdomain(self):
        self.reqs['resources']['/crossdomain.xml'] = """
        <cross-domain-policy>
          <allow-access-from domain="http-observatory.services.mozilla.com" secure="true"/>
          <allow-access-from domain="github.com" secure="true"/>
        </cross-domain-policy>"""

        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-restricted-access', result['result'])
        self.assertEquals(['http-observatory.services.mozilla.com', 'github.com'], result['data']['crossdomain'])
        self.assertTrue(result['pass'])

    def test_acao_universal_with_crossdomain(self):
        self.reqs['resources']['/crossdomain.xml'] = """
        <cross-domain-policy>
          <allow-access-from domain="*" secure="true"/>
        </cross-domain-policy>"""

        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-universal-access', result['result'])
        self.assertFalse(result['pass'])

    def test_acao_restricted_with_clientaccess(self):
        self.reqs['resources']['/clientaccesspolicy.xml'] = """
        <access-policy>
          <cross-domain-access>
            <policy>
              <allow-from http-methods="*">
                <domain uri="http-observatory.services.mozilla.com"/>
                <domain uri="github.com"/>
              </allow-from>
            </policy>
          </cross-domain-access>
        </access-policy>"""

        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-restricted-access', result['result'])
        self.assertEquals(['http-observatory.services.mozilla.com', 'github.com'], result['data']['clientaccesspolicy'])
        self.assertTrue(result['pass'])

    def test_acao_universal_with_clientaccess(self):
        self.reqs['resources']['/clientaccesspolicy.xml'] = """
        <access-policy>
          <cross-domain-access>
            <policy>
              <allow-from http-methods="*">
                <domain uri="*"/>
              </allow-from>
            </policy>
          </cross-domain-access>
        </access-policy>"""
        result = cross_origin_resource_sharing(self.reqs)

        self.assertEquals('cross-origin-resource-sharing-implemented-with-universal-access', result['result'])
        self.assertFalse(result['pass'])


class TestRedirection(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_no_http_but_does_have_https(self):
        self.reqs['responses']['http'] = None

        result = redirection(self.reqs)

        self.assertEquals('redirection-not-needed-no-http', result['result'])
        self.assertTrue(result['pass'])

    def test_redirection_missing(self):
        self.reqs['responses']['http'].url = 'http://http-observatory.services.mozilla.com'

        result = redirection(self.reqs)

        self.assertEquals('redirection-missing', result['result'])
        self.assertFalse(result['pass'])

    def test_redirection_not_to_https(self):
        self.reqs['responses']['http'].url = 'http://http-observatory.services.mozilla.com/foo'

        history1 = UserDict()
        history1.request = UserDict()
        history1.request.url = 'http://http-observatory.services.mozilla.com/'

        self.reqs['responses']['http'].history.append(history1)

        result = redirection(self.reqs)

        self.assertEquals('redirection-not-to-https', result['result'])
        self.assertFalse(result['pass'])

    def test_redirects_to_https(self):
        history1 = UserDict()
        history1.request = UserDict()
        history1.request.url = 'http://http-observatory.services.mozilla.com/'

        self.reqs['responses']['http'].history.append(history1)

        result = redirection(self.reqs)

        self.assertEquals('redirection-to-https', result['result'])
        self.assertEquals(['http://http-observatory.services.mozilla.com/',
                           'https://http-observatory.services.mozilla.com/'], result['route'])
        self.assertTrue(result['pass'])

    def test_first_redirection_still_http(self):
        self.reqs['responses']['http'].url = 'https://http-observatory.services.mozilla.com/foo'

        history1 = UserDict()
        history1.request = UserDict()
        history1.request.url = 'http://http-observatory.services.mozilla.com/'

        history2 = UserDict()
        history2.request = UserDict()
        history2.request.url = 'http://http-observatory.services.mozilla.com/foo'

        self.reqs['responses']['http'].history.append(history1)
        self.reqs['responses']['http'].history.append(history2)

        result = redirection(self.reqs)

        self.assertEquals('redirection-not-to-https-on-initial-redirection', result['result'])
        self.assertFalse(result['pass'])

    def test_first_redirection_off_host(self):
        self.reqs['responses']['http'].url = 'https://http-foo.services.mozilla.com/'

        history1 = UserDict()
        history1.status_code = 301
        history1.request = UserDict()
        history1.request.url = 'http://http-observatory.services.mozilla.com/'

        self.reqs['responses']['http'].history.append(history1)

        result = redirection(self.reqs)

        self.assertEquals('redirection-off-host-from-http', result['result'])
        self.assertFalse(result['pass'])
