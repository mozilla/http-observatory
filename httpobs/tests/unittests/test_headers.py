from http.cookiejar import Cookie
from unittest import TestCase

from httpobs.scanner.analyzer.headers import (content_security_policy,
                                              cookies,
                                              public_key_pinning,
                                              referrer_policy,
                                              strict_transport_security,
                                              x_content_type_options,
                                              x_frame_options,
                                              x_xss_protection)
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
        values = ('  ',
                  '\r\n',
                  '')

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals(result['result'], 'csp-header-invalid')
            self.assertFalse(result['pass'])

    def test_insecure_scheme(self):
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = 'default-src http://mozilla.org'

        result = content_security_policy(self.reqs)

        self.assertEquals('csp-implemented-with-insecure-scheme', result['result'])
        self.assertFalse(result['pass'])

    def test_unsafe_inline(self):
        values = ("script-src 'unsafe-inline'",
                  "script-src data:",
                  "default-src 'unsafe-inline'",
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
                  "object-src https:; script-src 'none'")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-unsafe-inline', result['result'])
            self.assertFalse(result['pass'])

    def test_unsafe_eval(self):
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = \
            "default-src 'none'; script-src 'unsafe-eval'"

        result = content_security_policy(self.reqs)

        self.assertEquals('csp-implemented-with-unsafe-eval', result['result'])
        self.assertEquals(result['data']['script-src'], ["'unsafe-eval'"])
        self.assertFalse(result['pass'])

    def test_unsafe_inline_in_style_src_only(self):
        values = ("object-src 'none'; script-src 'none'; style-src 'unsafe-inline'",
                  "default-src 'none'; script-src https://mozilla.org; style-src 'unsafe-inline'",
                  "default-src 'unsafe-inline'; script-src https://mozilla.org",
                  "default-src 'none'; style-src data:",
                  "default-src 'none'; style-src *",
                  "default-src 'none'; style-src https:")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-unsafe-inline-in-style-src-only', result['result'])
            self.assertTrue(result['pass'])

    def test_no_unsafe(self):
        # See https://github.com/mozilla/http-observatory/issues/88 for 'unsafe-inline' + hash/nonce
        values = ("default-src https://mozilla.org",
                  "object-src 'none'; script-src https://mozilla.org; " +
                  "style-src https://mozilla.org; upgrade-insecure-requests;",
                  "object-src 'none'; script-src 'unsafe-inline' " +
                  "'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBA='" +
                  "'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB='",
                  "object-src 'none'; script-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-no-unsafe', result['result'])
            self.assertTrue(result['pass'])

    def test_no_unsafe_default_src_none(self):
        values = ("default-src 'none'; script-src https://mozilla.org;"
                  "style-src https://mozilla.org; upgrade-insecure-requests;",
                  "default-src 'none'; object-src https://mozilla.org")

        for value in values:
            self.reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(self.reqs)

            self.assertEquals('csp-implemented-with-no-unsafe-default-src-none', result['result'])
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
                        rest={'HttpOnly': True},
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
                        rest={},
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
                        rest={'HttpOnly': True},
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
                        rest={},
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
                        rest={'HttpOnly': True},
                        secure=False,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])

        # https://github.com/mozilla/http-observatory/issues/97
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
                        secure=False,
                        version=1,
                        value='bar')
        self.reqs['session'].cookies.set_cookie(cookie)

        result = cookies(self.reqs)

        self.assertEquals('cookies-session-without-secure-flag', result['result'])
        self.assertFalse(result['pass'])


class TestPublicKeyPinning(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-not-implemented', result['result'])
        self.assertTrue(result['pass'])

    def test_header_invalid(self):
        # No pins
        self.reqs['responses']['https'].headers['Public-Key-Pins'] = 'max-age=15768000; includeSubDomains; preload'

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-header-invalid', result['result'])
        self.assertEquals(0, result['numPins'])
        self.assertFalse(result['pass'])

        # No max-age
        self.reqs['responses']['https'].headers['Public-Key-Pins'] = (
            'pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="; '
            'pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; '
            'report-uri="http://example.com/pkp-report"')
        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-header-invalid', result['result'])
        self.assertEquals(None, result['max-age'])
        self.assertEquals(2, result['numPins'])
        self.assertFalse(result['pass'])

        # Not enough pins
        self.reqs['responses']['https'].headers['Public-Key-Pins'] = (
            'max-age=15768000; '
            'pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; '
            'report-uri="http://example.com/pkp-report"')

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-header-invalid', result['result'])
        self.assertEquals(15768000, result['max-age'])
        self.assertEquals(1, result['numPins'])
        self.assertFalse(result['pass'])

    def test_no_https(self):
        self.reqs['responses']['auto'].headers['Public-Key-Pins'] = 'max-age=15768000'
        self.reqs['responses']['http'].headers['Public-Key-Pins'] = 'max-age=15768000'
        self.reqs['responses']['https'] = None

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-not-implemented-no-https', result['result'])
        self.assertTrue(result['pass'])

    def test_invalid_cert(self):
        self.reqs['responses']['https'].headers['Public-Key-Pins'] = (
            'max-age=15768000; '
            'includeSubDomains; '
            'pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="; '
            'pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; '
            'report-uri="http://example.com/pkp-report"')
        self.reqs['responses']['https'].verified = False

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-invalid-cert', result['result'])
        self.assertTrue(result['pass'])

    def test_max_age_too_low(self):
        self.reqs['responses']['https'].headers['Public-Key-Pins'] = (
            'max-age=86400; '
            'pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="; '
            'pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; '
            'report-uri="http://example.com/pkp-report"')

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-implemented-max-age-less-than-fifteen-days', result['result'])
        self.assertTrue(result['pass'])

    def test_implemented(self):
        self.reqs['responses']['https'].headers['Public-Key-Pins'] = (
            'max-age=15768000; '
            'includeSubDomains; '
            'pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="; '
            'pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; '
            'report-uri="http://example.com/pkp-report"')

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-implemented-max-age-at-least-fifteen-days', result['result'])
        self.assertEquals(15768000, result['max-age'])
        self.assertEquals(15768000, result['max-age'])
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])

    def test_preloaded(self):
        # apis.google.com has regular includeSubDomains
        self.reqs['responses']['https'].url = 'https://apis.google.com/'

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-preloaded', result['result'])
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])
        self.reqs['responses']['https'].url = 'https://foo.apis.google.com'

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-preloaded', result['result'])
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])

        # Dropbox Static uses include_subdomains_for_pinning
        self.reqs['responses']['https'].url = 'https://foo.dropboxstatic.com/'

        result = public_key_pinning(self.reqs)

        self.assertEquals('hpkp-preloaded', result['result'])
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])


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
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = \
            'max-age=15768000; includeSubDomains, max-age=15768000; includeSubDomains'

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
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = \
            'max-age=15768000; includeSubDomains; preload'
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
        self.reqs['responses']['https'].headers['Strict-Transport-Security'] = \
            'max-age=15768000; includeSubDomains; preload'

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

        # Cloudflare doesn't include subdomains
        self.reqs['responses']['https'].url = 'https://cloudflare.com/'

        result = strict_transport_security(self.reqs)

        self.assertEquals('hsts-preloaded', result['result'])
        self.assertFalse(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])

        # Android.com is preloaded, but only for HPKP, not HSTS
        self.reqs['responses']['https'].url = 'https://android.com/'

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
        self.reqs['responses']['auto'].headers['Content-Security-Policy'] = "object-src 'none'; script-src 'none'"

        result = x_xss_protection(self.reqs)

        self.assertEquals('x-xss-protection-not-needed-due-to-csp', result['result'])
        self.assertTrue(result['pass'])


class TestReferrerPolicy(TestCase):
    def setUp(self):
        self.reqs = empty_requests()

    def tearDown(self):
        self.reqs = None

    def test_missing(self):
        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-not-implemented', result['result'])
        self.assertTrue(result['pass'])

    def test_header_invalid(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'whimsy'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-invalid', result['result'])
        self.assertFalse(result['pass'])

    def test_header_unsafe_url(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'unsafe-url'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-unsafe-url', result['result'])
        self.assertFalse(result['pass'])

    def test_header_no_referrer(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'no-referrer'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-no-referrer', result['result'])
        self.assertTrue(result['pass'])

    def test_header_no_referrer_when_downgrade(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'no-referrer-when-downgrade'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-no-referrer-when-downgrade', result['result'])
        self.assertTrue(result['pass'])

    def test_header_origin(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'origin'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-origin', result['result'])
        self.assertTrue(result['pass'])

    def test_header_origin_when_cross_origin(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'origin-when-cross-origin'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-origin-when-cross-origin', result['result'])
        self.assertTrue(result['pass'])

    def test_header_same_origin(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'same-origin'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-same-origin', result['result'])
        self.assertTrue(result['pass'])

    def test_header_strict_origin(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'strict-origin'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-strict-origin', result['result'])
        self.assertTrue(result['pass'])

    def test_header_strict_origin_when_cross_origin(self):
        self.reqs['responses']['auto'].headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        result = referrer_policy(self.reqs)

        self.assertEquals('referrer-policy-header-strict-origin-when-cross-origin', result['result'])
        self.assertTrue(result['pass'])
