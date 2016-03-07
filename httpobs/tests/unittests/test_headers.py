from http.cookiejar import Cookie
from unittest import TestCase

from httpobs.scanner.analyzer.headers import *
from httpobs.tests.utils import empty_requests


class TestContentSecurityPolicy(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = content_security_policy(self.reqs)

        self.assertEquals('csp-not-implemented', result['result'])
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = ''  # TODO: Try to think of anything!

        # result = content_security_policy(self.reqs)

        # self.assertEquals(result['result'], 'csp-header-invalid')
        # self.assertFalse(result['pass'])

    def test_insecure_scheme(self):
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = 'default-src http://mozilla.org'

        result = content_security_policy(self.reqs)

        self.assertEquals('csp-implemented-with-insecure-scheme', result['result'])
        self.assertFalse(result['pass'])

    def test_unsafe_inline(self):
        values = ("script-src 'unsafe-inline'",
                  "script-src data:",
                  "default-src 'unsafe-inline'",
                  "upgrade-insecure-requests")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-unsafe-inline', result['result'])
            self.assertFalse(result['pass'])

    def test_unsafe_eval(self):
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = "script-src 'unsafe-eval'"

        result = content_security_policy(self.reqs)

        self.assertEquals('csp-implemented-with-unsafe-eval', result['result'])
        self.assertEquals(result['data']['script-src'], ["'unsafe-eval'"])
        self.assertFalse(result['pass'])

    def test_unsafe_inline_in_style_src_only(self):
        values = ("script-src 'none'; style-src 'unsafe-inline'",
                  "default-src 'none'; script-src https://mozilla.org; style-src 'unsafe-inline'",
                  "default-src 'unsafe-inline'; script-src https://mozilla.org;",
                  "default-src 'none'; style-src data:")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-unsafe-inline-in-style-src-only', result['result'])
            self.assertFalse(result['pass'])

    def test_no_unsafe(self):
        values = ("default-src 'none'",
                  "script-src https://mozilla.org; style-src https://mozilla.org; upgrade-insecure-requests;")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-no-unsafe', result['result'])
            self.assertTrue(result['pass'])


class TestCookies(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = cookies(self.reqs)

        self.assertEquals('cookies-not-found', result['result'])
        self.assertTrue(result['pass'])

    def test_secure_with_httponly_sessions(self):
        # Python cookies are the literal worst, seriously, the worst
        cookie = Cookie(name='SESSIONID',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={'HttpOnly': None},
                        secure=True,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(name='foo',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={},
                        secure=True,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-secure-with-httponly-sessions', result['result'])
        self.assertTrue(result['pass'])

    def test_regular_cookie_no_secure_but_hsts(self):
        cookie = Cookie(name='foo',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={'HttpOnly': None},
                        secure=False,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=15768000'

        result = cookies(self.reqs)

        self.assertEquals('cookies-without-secure-flag-but-protected-by-hsts', result['result'])
        self.assertFalse(result['pass'])

    def test_session_cookie_no_secure_but_hsts(self):
        cookie = Cookie(name='SESSIONID',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={'HttpOnly': None},
                        secure=False,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=15768000'

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag-but-protected-by-hsts', result['result'])
        self.assertFalse(result['pass'])

    def test_no_secure(self):
        cookie = Cookie(name='foo',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={'HttpOnly': None},
                        secure=False,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])

    def test_session_no_httponly(self):
        cookie = Cookie(name='SESSIONID',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={},
                        secure=True,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-httponly-flag', result['result'])
        self.assertFalse(result['pass'])

    def test_session_no_secure(self):
        cookie = Cookie(name='SESSIONID',
                        comment=None,
                        comment_url=None,
                        discard=False,
                        domain='mozilla.com',
                        domain_initial_dot=False,
                        domain_specified='mozilla.com',
                        expires=None,
                        path='/',
                        path_specified='/',
                        port=443,
                        port_specified=443,
                        rfc2109=False,
                        rest={'HttpOnly': None},
                        secure=False,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])


class TestStrictTransportSecurity(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-not-implemented', result['result'])
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'includeSubDomains; preload'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_no_https(self):
        self.reqs['responses']['auto'].headers['Strict-Transport-Security'] = 'max-age=15768000'
        self.reqs['responses']['http'].headers['Strict-Transport-Security'] = 'max-age=15768000'
        self.reqs['responses']['https'] = None

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-not-implemented-no-https', result['result'])
        self.assertFalse(result['pass'])

    def test_max_age_too_low(self):
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=86400'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-implemented-max-age-less-than-six-months', result['result'])
        self.assertFalse(result['pass'])

    def test_implemented(self):
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=15768000; includeSubDomains; preload'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-implemented-max-age-at-least-six-months', result['result'])
        self.assertEquals(result['max-age'], 15768000)
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['preload'])
        self.assertTrue(result['pass'])

    def test_preloaded(self):
        self.reqs['responses']['https'].url = 'https://www.google.com/'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-preloaded', result['result'])
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])

        self.reqs['responses']['https'].url = 'https://cloudflare.com/'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-preloaded', result['result'])
        self.assertFalse(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])


class TestXContentTypeOptions(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = x_content_type_options(self.reqs)

        self.assertEquals('x-content-type-options-not-implemented', result['result'])
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['auto'].headers['X-Content-Type-Options'] = 'whimsy'

        result = x_content_type_options(self.reqs)

        self.assertEquals('x-content-type-options-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_nosniff(self):
        self.reqs['responses']['auto'].headers['X-Content-Type-Options'] = 'nosniff'

        result = x_content_type_options(self.reqs)

        self.assertEquals('x-content-type-options-nosniff', result['result'])
        self.assertTrue(result['pass'])


class TestXFrameOptions(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = x_frame_options(self.reqs)

        self.assertEquals('x-frame-options-not-implemented', result['result'])
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['auto'].headers['X-Frame-Options'] = 'whimsy'

        result = x_frame_options(self.reqs)

        self.assertEquals('x-frame-options-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_deny(self):
        self.reqs['responses']['auto'].headers['X-Frame-Options'] = 'DENY'

        result = x_frame_options(self.reqs)

        self.assertEquals('x-frame-options-sameorigin-or-deny', result['result'])
        self.assertTrue(result['pass'])

    def test_enabled_via_csp(self):
        self.reqs['responses']['auto'].headers['X-Frame-Options'] = 'DENY'
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = 'frame-ancestors https://mozilla.org'

        result = x_frame_options(self.reqs)

        self.assertEquals('x-frame-options-implemented-via-csp', result['result'])
        self.assertTrue(result['pass'])


class TestXXSSProtection(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-not-implemented', result['result'])
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['auto'].headers['X-XSS-Protection'] = 'whimsy'

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_disabled(self):
        self.reqs['responses']['auto'].headers['X-XSS-Protection'] = '0'

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-disabled', result['result'])
        self.assertFalse(result['pass'])

    def test_enabled_noblock(self):
        self.reqs['responses']['auto'].headers['X-XSS-Protection'] = '1'

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-enabled', result['result'])
        self.assertTrue(result['pass'])

    def test_enabled_block(self):
        self.reqs['responses']['auto'].headers['X-XSS-Protection'] = '1; mode=block'

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-enabled-mode-block', result['result'])
        self.assertTrue(result['pass'])

    def test_enabled_via_csp(self):
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = 'script-src \'none\''

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-not-needed-due-to-csp', result['result'])
        self.assertTrue(result['pass'])
