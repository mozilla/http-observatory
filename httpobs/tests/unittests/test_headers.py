from http.cookiejar import Cookie
from unittest import TestCase

from httpobs.scanner.analyzer.headers import (
    content_security_policy,
    cookies,
    referrer_policy,
    strict_transport_security,
    x_content_type_options,
    x_frame_options,
    x_xss_protection,
)
from httpobs.tests.utils import empty_requests, set_header


class TestContentSecurityPolicy(TestCase):
    def test_missing(self):
        reqs = empty_requests()
        result = content_security_policy(reqs)

        self.assertEquals('csp-not-implemented', result['result'])
        self.assertEquals(result['numPolicies'], 0)
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        values = (
            "  ",
            "\r\n",
            "",
            "default-src 'none'; default-src 'none'",  # Repeated directives not allowed
            "default-src 'none'; img-src 'self'; default-src 'none'",
            "default-src 'none'; script-src 'strict-dynamic'",  # strict dynamic without hash/nonce
            "defa",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals(result['result'], 'csp-header-invalid')
            self.assertEquals(result['numPolicies'], 1)
            self.assertFalse(result['pass'])

    def test_insecure_scheme(self):
        values = (
            "default-src http://mozilla.org",
            "default-src 'none'; script-src http://mozilla.org",
            "default-src 'none'; script-src http://mozilla.org",
            "default-src 'none'; script-src ftp://mozilla.org",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-insecure-scheme', result['result'])
            self.assertFalse(result['pass'])
            self.assertTrue(result['policy']['insecureSchemeActive'])

    def test_insecure_scheme_in_passive_content_only(self):
        values = (
            "default-src 'none'; img-src http://mozilla.org",
            "default-src 'self'; img-src ftp:",
            "default-src 'self'; img-src http:",
            "default-src 'none'; img-src https:; media-src http://mozilla.org",
            "default-src 'none'; img-src http: https:; script-src 'self'; style-src 'self'",
            "default-src 'none'; img-src 'none'; media-src http:; script-src 'self'; style-src 'self'",
            "default-src 'none'; img-src 'none'; media-src http:; script-src 'self'; style-src 'unsafe-inline'",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-insecure-scheme-in-passive-content-only', result['result'])
            self.assertTrue(result['pass'])
            self.assertTrue(result['policy']['insecureSchemePassive'])

    def test_unsafe_inline(self):
        values = (
            "script-src 'unsafe-inline'",
            "script-src data:",  # overly broad
            "script-src http:",
            "script-src ftp:",
            "default-src 'unsafe-inline'",
            "default-src 'UNSAFE-INLINE'",
            "upgrade-insecure-requests",
            "script-src 'none'",
            "script-src https:",
            "script-src https://mozilla.org https:",
            "default-src https://mozilla.org https:",
            "default-src 'none'; script-src *",
            "default-src *; script-src *; object-src 'none'",
            "default-src 'none'; script-src 'none', object-src *",
            "default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'",
            "default-src 'none'; script-src 'unsafe-inline' http:",
            "object-src https:; script-src 'none'",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-unsafe-inline', result['result'])
            self.assertFalse(result['pass'])
            self.assertTrue(result['policy']['unsafeInline'])

    def test_unsafe_eval(self):
        reqs = empty_requests()

        set_header(reqs['responses']['auto'], 'Content-Security-Policy', "default-src 'none'; script-src 'unsafe-eval'")

        result = content_security_policy(reqs)

        self.assertEquals('csp-implemented-with-unsafe-eval', result['result'])
        self.assertEquals(result['data']['script-src'], ["'unsafe-eval'"])
        self.assertFalse(result['pass'])
        self.assertTrue(result['policy']['unsafeEval'])

    def test_unsafe_inline_in_style_src_only(self):
        values = (
            "object-src 'none'; script-src 'none'; style-src 'unsafe-inline'",
            "default-src 'none'; script-src https://mozilla.org; style-src 'unsafe-inline'",
            "default-src 'unsafe-inline'; script-src https://mozilla.org",
            "default-src 'none';;; ;;;style-src 'self' 'unsafe-inline'",
            "default-src 'none'; style-src data:",
            "default-src 'none'; style-src *",
            "default-src 'none'; style-src https:",
            "default-src 'none'; style-src 'unsafe-inline'; "
            + "script-src 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB=' "
            + "'unsafe-inline'",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-unsafe-inline-in-style-src-only', result['result'])
            self.assertTrue(result['pass'])
            self.assertTrue(result['policy']['unsafeInlineStyle'])

    def test_no_unsafe(self):
        # See https://github.com/mozilla/http-observatory/issues/88 and
        # https://github.com/mozilla/http-observatory/issues/277 for 'unsafe-inline' + hash/nonce
        values = (
            "default-src https://mozilla.org",
            "default-src https://mozilla.org;;; ;;;script-src 'none'",
            "object-src 'none'; script-src https://mozilla.org; "
            + "style-src https://mozilla.org; upgrade-insecure-requests;",
            "object-src 'none'; script-src 'strict-dynamic' 'nonce-abc' 'unsafe-inline'; style-src 'none'",
            "object-src 'none'; style-src 'self';" + "script-src 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBA='",
            "object-src 'none'; style-src 'self'; script-src 'unsafe-inline' "
            + "'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBA='"
            + "'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB='",
            "object-src 'none'; script-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'; style-src 'none'",
            "default-src https://mozilla.org; style-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'",
            "default-src https://mozilla.org; style-src 'unsafe-inline' "
            + "'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB=' 'unsafe-inline'",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-no-unsafe', result['result'])
            self.assertTrue(result['pass'])

    def test_no_unsafe_default_src_none(self):
        # An HTTP header (default-src http:) and HTTP equiv (default-src https:), with differing values
        # that should end up as default-src 'none'
        reqs = empty_requests('test_parse_http_equiv_headers_csp2.html')
        set_header(reqs['responses']['auto'], 'Content-Security-Policy', "default-src http:")
        result = content_security_policy(reqs)
        self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
        self.assertEquals(result['numPolicies'], 2)
        self.assertTrue(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])
        values = (
            "default-src",  # no value == 'none'  TODO: Fix this
            "default-src 'none'; script-src 'strict-dynamic' 'nonce-abc123' 'unsafe-inline'",
            "default-src 'none'; script-src https://mozilla.org;"
            + "style-src https://mozilla.org; upgrade-insecure-requests;",
            "default-src 'none'; object-src https://mozilla.org",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)

            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
            self.assertEquals(result['numPolicies'], 1)
            self.assertTrue(result['http'])
            self.assertFalse(result['meta'])
            self.assertTrue(result['pass'])
            self.assertTrue(result['policy']['defaultNone'])

        # Do the same with an HTTP equiv
        reqs = empty_requests('test_parse_http_equiv_headers_csp1.html')
        result = content_security_policy(reqs)
        self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
        self.assertEquals(result['numPolicies'], 1)
        self.assertFalse(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

        # Do the same with an HTTP equiv that has multiple policies
        reqs = empty_requests('test_parse_http_equiv_headers_csp_multiple_http_equiv1.html')
        result = content_security_policy(reqs)
        self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
        self.assertEquals(result['numPolicies'], 4)
        self.assertFalse(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

        # With both a header and an HTTP equiv set to default-src 'none'
        reqs = empty_requests('test_parse_http_equiv_headers_csp1.html')
        set_header(reqs['responses']['auto'], 'Content-Security-Policy', "default-src 'none'")
        result = content_security_policy(reqs)
        self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
        self.assertEquals(result['numPolicies'], 2)
        self.assertTrue(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

        # With both a header (default-src 'none') and a conflicting HTTP equiv (default-src https:)
        reqs = empty_requests('test_parse_http_equiv_headers_csp2.html')
        set_header(reqs['responses']['auto'], 'Content-Security-Policy', "default-src 'none'")
        result = content_security_policy(reqs)
        self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
        self.assertEquals(result['numPolicies'], 2)
        self.assertTrue(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

        # An HTTP header (img-src 'none') and HTTP equiv (default-src 'none'), with differing values
        reqs = empty_requests('test_parse_http_equiv_headers_csp1.html')
        set_header(reqs['responses']['auto'], 'Content-Security-Policy', "img-src 'none'")
        result = content_security_policy(reqs)
        self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
        self.assertEquals(result['numPolicies'], 2)
        self.assertTrue(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

    def test_strict_dynamic(self):
        values = (
            "default-src 'none'; script-src 'strict-dynamic' 'nonce-abc123'",
            "default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123'",
            "default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123' https://",
            "default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123' 'unsafe-inline'",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            result = content_security_policy(reqs)

            self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
            self.assertTrue(result['policy']['strictDynamic'])

    def test_policy_analysis(self):
        values = (
            "default-src 'none'",  # doesn't fall to frame-ancestors
            "frame-ancestors *",
            "frame-ancestors http:",
            "frame-ancestors https:",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            self.assertFalse(content_security_policy(reqs)['policy']['antiClickjacking'])

        # Now test where anticlickjacking is enabled
        reqs = empty_requests()
        set_header(reqs['responses']['auto'], 'Content-Security-Policy', "default-src *; frame-ancestors 'none'")
        self.assertTrue(content_security_policy(reqs)['policy']['antiClickjacking'])

        # Test unsafeObjects and insecureBaseUri
        values = (
            "default-src 'none'; base-uri *; object-src *",
            "default-src 'none'; base-uri https:; object-src https:",
            "default-src *",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            self.assertTrue(content_security_policy(reqs)['policy']['insecureBaseUri'])
            self.assertTrue(content_security_policy(reqs)['policy']['unsafeObjects'])

        # Other tests for insecureBaseUri
        values = (
            "default-src *; base-uri 'none'",
            "default-src 'none'; base-uri 'self'",
            "default-src 'none'; base-uri https://mozilla.org",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            self.assertFalse(content_security_policy(reqs)['policy']['insecureBaseUri'])

        # Test for insecureSchemePassive
        values = (
            "default-src * http: https: data: 'unsafe-inline' 'unsafe-eval'",
            "default-src 'none'; img-src http:",
            "default-src 'none' https://mozilla.org; img-src http://mozilla.org",
            "default-src https:; media-src http://mozilla.org; script-src http:",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            self.assertTrue(content_security_policy(reqs)['policy']['insecureSchemePassive'])

        # Test for insecureFormAction
        values = (
            "default-src *; form-action 'none'",
            "default-src *; form-action 'self'",
            "default-src 'none'; form-action 'self' https://mozilla.org",
            "form-action 'self' https://mozilla.org",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            self.assertFalse(content_security_policy(reqs)['policy']['insecureFormAction'])

        values = (
            "default-src *",
            "default-src 'none'",
            "form-action https:",
        )

        for value in values:
            reqs = empty_requests()
            set_header(reqs['responses']['auto'], 'Content-Security-Policy', value)
            self.assertTrue(content_security_policy(reqs)['policy']['insecureFormAction'])


class TestCookies(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = cookies(self.reqs)

        self.assertEquals('cookies-not-found', result['result'])
        self.assertTrue(result['pass'])
        self.assertIsNone(result['sameSite'])

    def test_secure_with_httponly_sessions(self):
        # Python cookies are the literal worst, seriously, the worst
        cookie = Cookie(
            name='SESSIONID',
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
            rest={'HttpOnly': True},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(
            name='foo',
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
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        # See: https://github.com/mozilla/http-observatory/issues/121 for the __cfduid insanity
        cookie = Cookie(
            name='__cfduid',
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
            rest={},
            rfc2109=False,
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        # See: https://github.com/mozilla/http-observatory/issues/282 for the heroku-session-affinity insanity
        cookie = Cookie(
            name='heroku-session-affinity',
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
            rest={},
            rfc2109=False,
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-secure-with-httponly-sessions', result['result'])
        self.assertTrue(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_secure_with_httponly_sessions_and_samesite(self):
        cookie = Cookie(
            name='SESSIONID_SAMESITE_STRICT',
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
            rest={'HttpOnly': True, 'SameSite': 'Strict'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(
            name='SESSIONID_SAMESITE_LAX',
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
            rest={'HttpOnly': True, 'SameSite': 'Lax'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(
            name='SESSIONID_SAMESITE_NONE',
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
            rest={'HttpOnly': True, 'SameSite': 'None'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-secure-with-httponly-sessions-and-samesite', result['result'])
        self.assertEquals(
            {
                'SESSIONID_SAMESITE_STRICT': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': 'Strict',
                    'secure': True,
                },
                'SESSIONID_SAMESITE_LAX': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': 'Lax',
                    'secure': True,
                },
                'SESSIONID_SAMESITE_NONE': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': 'None',
                    'secure': True,
                },
            },
            result['data'],
        )
        self.assertTrue(result['pass'])
        self.assertTrue(result['sameSite'])

    def test_secure_with_httponly_sessions_and_samesite_not_awarded_if_not_all_cookies_samesite(self):
        cookie = Cookie(
            name='SESSIONID_SAMESITE_STRICT',
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
            rest={'HttpOnly': True, 'SameSite': 'Strict'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(
            name='SESSIONID_NO_SAMESITE',
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
            rest={'HttpOnly': True},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(
            name='SESSIONID_SAMESITE_LAX',
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
            rest={'HttpOnly': True, 'SameSite': 'Lax'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        cookie = Cookie(
            name='SESSIONID_SAMESITE_NONE',
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
            rest={'HttpOnly': True, 'SameSite': 'None'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-secure-with-httponly-sessions', result['result'])
        self.assertEquals(
            {
                'SESSIONID_SAMESITE_STRICT': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': 'Strict',
                    'secure': True,
                },
                'SESSIONID_NO_SAMESITE': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': False,
                    'secure': True,
                },
                'SESSIONID_SAMESITE_LAX': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': 'Lax',
                    'secure': True,
                },
                'SESSIONID_SAMESITE_NONE': {
                    'domain': 'mozilla.com',
                    'expires': None,
                    'httponly': True,
                    'max-age': None,
                    'path': '/',
                    'port': 443,
                    'samesite': 'None',
                    'secure': True,
                },
            },
            result['data'],
        )
        self.assertTrue(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_anticsrf_without_samesite(self):
        cookie = Cookie(
            name='CSRFTOKEN',
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
            rest={'HttpOnly': True},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-anticsrf-without-samesite-flag', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_samesite_invalid_empty(self):
        cookie = Cookie(
            name='SESSIONID',
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
            rest={'HttpOnly': True, 'SameSite': None},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-samesite-flag-invalid', result['result'])
        self.assertFalse(result['pass'])
        self.assertIsNone(result['sameSite'])

    def test_samesite_invalid_true(self):
        cookie = Cookie(
            name='SESSIONID',
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
            rest={'HttpOnly': True, 'SameSite': True},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-samesite-flag-invalid', result['result'])
        self.assertFalse(result['pass'])
        self.assertIsNone(result['sameSite'])

    def test_samesite_invalid(self):
        cookie = Cookie(
            name='SESSIONID',
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
            rest={'HttpOnly': True, 'SameSite': 'Invalid'},
            secure=True,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-samesite-flag-invalid', result['result'])
        self.assertFalse(result['pass'])
        self.assertIsNone(result['sameSite'])

    def test_regular_cookie_no_secure_but_hsts(self):
        cookie = Cookie(
            name='foo',
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
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=15768000'

        result = cookies(self.reqs)

        self.assertEquals('cookies-without-secure-flag-but-protected-by-hsts', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_session_cookie_no_secure_but_hsts(self):
        cookie = Cookie(
            name='SESSIONID',
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
            rest={'HttpOnly': True},
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=15768000'

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag-but-protected-by-hsts', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_no_secure(self):
        cookie = Cookie(
            name='foo',
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
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_session_no_httponly(self):
        cookie = Cookie(
            name='SESSIONID',
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
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-httponly-flag', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])

    def test_session_no_secure(self):
        cookie = Cookie(
            name='SESSIONID',
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
            rest={'HttpOnly': True},
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])

        # https://github.com/mozilla/http-observatory/issues/97
        cookie = Cookie(
            name='SESSIONID',
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
            secure=False,
            version=1,
            value='bar',
        )
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['sameSite'])


class TestReferrerPolicy(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_header_private(self):
        for policy in [
            'no-referrer',
            'same-origin',
            'strict-origin',
            'STRICT-ORIGIN',
            'strict-origin-when-cross-origin',
        ]:
            self.reqs['responses']['auto'].headers['Referrer-Policy'] = policy

            result = referrer_policy(self.reqs)

            self.assertEquals('referrer-policy-private', result['result'])
            self.assertTrue(result['http'])
            self.assertFalse(result['meta'])
            self.assertTrue(result['pass'])

        # Do that same test with a <meta> http-equiv
        self.reqs = empty_requests('test_parse_http_equiv_headers_referrer1.html')
        result = referrer_policy(self.reqs)
        self.assertEquals('referrer-policy-private', result['result'])
        self.assertEquals('no-referrer, same-origin', result['data'])
        self.assertFalse(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

        # Note that <meta> http-equiv comes before the HTTP header
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'unsafe-url'
        result = referrer_policy(self.reqs)
        self.assertEquals('referrer-policy-private', result['result'])
        self.assertEquals('unsafe-url, no-referrer, same-origin', result['data'])
        self.assertTrue(result['http'])
        self.assertTrue(result['meta'])
        self.assertTrue(result['pass'])

    def test_header_no_referrer_when_downgrade(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'no-referrer-when-downgrade'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-no-referrer-when-downgrade', result['result'])
        self.assertTrue(result['pass'])

    def test_missing(self):
        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-not-implemented', result['result'])
        self.assertTrue(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'whimsy'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_header_unsafe(self):
        for policy in ['origin', 'origin-when-cross-origin', 'unsafe-url']:
            self.reqs['responses']['auto'].headers['Referrer-Policy'] = policy

            result = referrer_policy(self.reqs)

            self.assertEquals('referrer-policy-unsafe', result['result'])
            self.assertFalse(result['pass'])

    def test_multiple_value_header_all_valid(self):
        valid_but_unsafe_policies = [
            'origin-when-cross-origin, no-referrer, unsafe-url',  # safe in the middle
            'no-referrer, unsafe-url',
        ]  # safe at the beginning
        for policy in valid_but_unsafe_policies:
            self.reqs['responses']['auto'].headers['Referrer-Policy'] = policy

            result = referrer_policy(self.reqs)

            self.assertEquals('referrer-policy-unsafe', result['result'])
            self.assertFalse(result['pass'])

    def test_multiple_value_header_mix(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'no-referrer, whimsy'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-private', result['result'])
        self.assertTrue(result['pass'])

    def test_multiple_value_header_invalid(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'whimsy, whimsy1, whimsy2'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-invalid', result['result'])
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

        # If the header is set twice
        self.reqs['responses']['https'].headers[
            'Strict-Transport-Security'
        ] = 'max-age=15768000; includeSubDomains, max-age=15768000; includeSubDomains'

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

    def test_invalid_cert(self):
        self.reqs['responses']['https'].headers[
            'Strict-Transport-Security'
        ] = 'max-age=15768000; includeSubDomains; preload'
        self.reqs['responses']['https'].verified = False

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-invalid-cert', result['result'])
        self.assertFalse(result['pass'])

    def test_max_age_too_low(self):
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=86400'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-implemented-max-age-less-than-six-months', result['result'])
        self.assertFalse(result['pass'])

    def test_implemented(self):
        self.reqs['responses']['https'].headers[
            'Strict-Transport-Security'
        ] = 'max-age=15768000; includeSubDomains; preload'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-implemented-max-age-at-least-six-months', result['result'])
        self.assertEquals(result['max-age'], 15768000)
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['preload'])
        self.assertTrue(result['pass'])

    def test_preloaded(self):
        self.reqs['responses']['https'].url = 'https://bugzilla.mozilla.org/'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-preloaded', result['result'])
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])

        # Facebook doesn't include subdomains
        self.reqs['responses']['https'].url = 'https://facebook.com/'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-preloaded', result['result'])
        self.assertFalse(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])

        # dropboxusercontent.com is not preloaded
        self.reqs['responses']['https'].url = 'https://dropboxusercontent.com/'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-not-implemented', result['result'])
        self.assertFalse(result['includeSubDomains'])
        self.assertFalse(result['pass'])
        self.assertFalse(result['preloaded'])


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
        for value in ('whimsy', 'nosniff, nosniff'):
            self.reqs['responses']['auto'].headers['X-Content-Type-Options'] = value

            result = x_content_type_options(self.reqs)

            self.assertEquals('x-content-type-options-header-invalid', result['result'])
            self.assertFalse(result['pass'])

    def test_nosniff(self):
        for value in ('nosniff', 'nosniff '):
            self.reqs['responses']['auto'].headers['X-Content-Type-Options'] = value

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

        # common to see this header sent multiple times
        self.reqs['responses']['auto'].headers['X-Frame-Options'] = 'SAMEORIGIN, SAMEORIGIN'

        result = x_frame_options(self.reqs)

        self.assertEquals('x-frame-options-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_allow_from_origin(self):
        self.reqs['responses']['auto'].headers['X-Frame-Options'] = 'ALLOW-FROM https://mozilla.org'

        result = x_frame_options(self.reqs)

        self.assertEquals('x-frame-options-allow-from-origin', result['result'])
        self.assertTrue(result['pass'])

    def test_deny(self):
        for value in ('DENY', 'DENY '):
            self.reqs['responses']['auto'].headers['X-Frame-Options'] = value

            result = x_frame_options(self.reqs)

            self.assertEquals('x-frame-options-sameorigin-or-deny', result['result'])
            self.assertTrue(result['pass'])

    def test_enabled_via_csp(self):
        reqs = empty_requests()
        set_header(reqs['responses']['auto'], 'X-Frame-Options', 'DENY')
        set_header(reqs['responses']['auto'], 'Content-Security-Policy', 'frame-ancestors https://mozilla.org')

        result = x_frame_options(reqs)

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
        self.assertTrue(result['pass'])

    def test_header_invalid(self):
        for value in ('whimsy', '2; mode=block', '1; mode=block; mode=block', '1; mode=block, 1; mode=block'):
            self.reqs['responses']['auto'].headers['X-XSS-Protection'] = value

            result = x_xss_protection(self.reqs)

            self.assertEquals('x-xss-protection-header-invalid', result['result'])
            self.assertFalse(result['pass'])

    def test_disabled(self):
        self.reqs['responses']['auto'].headers['X-XSS-Protection'] = '0'

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-disabled', result['result'])
        self.assertTrue(result['pass'])

    def test_enabled_noblock(self):
        for value in ('1', '1 '):
            self.reqs['responses']['auto'].headers['X-XSS-Protection'] = value

            result = x_xss_protection(self.reqs)

            self.assertEquals('x-xss-protection-enabled', result['result'])
            self.assertTrue(result['pass'])

    def test_enabled_block(self):
        self.reqs['responses']['auto'].headers['X-XSS-Protection'] = '1; mode=block'

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-enabled-mode-block', result['result'])
        self.assertTrue(result['pass'])
