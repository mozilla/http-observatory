from unittest import TestCase

from httpobs.scanner.analyzer.headers import *
from httpobs.tests.utils import empty_requests


class TestContentSecurityPolicy(TestCase):
    def test_missing(self):
        reqs = empty_requests()

        result = content_security_policy(reqs)

        self.assertEquals(result['result'], 'csp-not-implemented')
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['Content-Security-Policy'] = ''  # TODO: Try to think of anything!

        # result = content_security_policy(reqs)

        # self.assertEquals(result['result'], 'csp-header-invalid')
        # self.assertFalse(result['pass'])

    def test_insecure_scheme(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['Content-Security-Policy'] = 'default-src http://mozilla.org'

        result = content_security_policy(reqs)

        self.assertEquals(result['result'], 'csp-implemented-with-insecure-scheme')
        self.assertFalse(result['pass'])

    def test_unsafe_inline(self):
        reqs = empty_requests()
        values = ("script-src 'unsafe-inline'",
                  "script-src data:",
                  "default-src 'unsafe-inline'",
                  "upgrade-insecure-requests")

        for value in values:
            reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(reqs)

            self.assertEquals(result['result'], 'csp-implemented-with-unsafe-inline')
            self.assertFalse(result['pass'])

    def test_unsafe_eval(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['Content-Security-Policy'] = "script-src 'unsafe-eval'"

        result = content_security_policy(reqs)

        self.assertEquals(result['result'], 'csp-implemented-with-unsafe-eval')
        self.assertEquals(result['data']['script-src'], ["'unsafe-eval'"])
        self.assertFalse(result['pass'])

    def test_unsafe_inline_in_style_src_only(self):
        reqs = empty_requests()
        values = ("script-src 'none'; style-src 'unsafe-inline'",
                  "default-src 'none'; script-src https://mozilla.org; style-src 'unsafe-inline'",
                  "default-src 'unsafe-inline'; script-src https://mozilla.org;",
                  "default-src 'none'; style-src data:")

        for value in values:
            reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(reqs)

            self.assertEquals(result['result'], 'csp-implemented-with-unsafe-inline-in-style-src-only')
            self.assertFalse(result['pass'])

    def test_no_unsafe(self):
        reqs = empty_requests()
        values = ("default-src 'none'",
                  "script-src https://mozilla.org; style-src https://mozilla.org; upgrade-insecure-requests;")

        for value in values:
            reqs['responses']['auto'].headers['Content-Security-Policy'] = value

            result = content_security_policy(reqs)

            self.assertEquals(result['result'], 'csp-implemented-with-no-unsafe')
            self.assertTrue(result['pass'])


# TODO: class TestCookies(TestCase):


class TestStrictTransportSecurity(TestCase):
    def test_missing(self):
        reqs = empty_requests()

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-not-implemented')
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        reqs = empty_requests()
        reqs['responses']['https'].headers['Strict-Transport-Security'] = 'includeSubDomains; preload'

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-header-invalid')
        self.assertFalse(result['pass'])

    def test_no_https(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['Strict-Transport-Security'] = 'max-age=15768000'
        reqs['responses']['http'].headers['Strict-Transport-Security'] = 'max-age=15768000'
        reqs['responses']['https'] = None

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-not-implemented-no-https')
        self.assertFalse(result['pass'])

    def test_max_age_too_low(self):
        reqs = empty_requests()
        reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=86400'

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-implemented-max-age-less-than-six-months')
        self.assertFalse(result['pass'])

    def test_implemented(self):
        reqs = empty_requests()
        reqs['responses']['https'].headers['Strict-Transport-Security'] = 'max-age=15768000; includeSubDomains; preload'

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-implemented-max-age-at-least-six-months')
        self.assertEquals(result['max-age'], 15768000)
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['preload'])
        self.assertTrue(result['pass'])

    def test_preloaded(self):
        reqs = empty_requests()
        reqs['responses']['https'].url = 'https://www.google.com/'

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-preloaded')
        self.assertTrue(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])

        reqs['responses']['https'].url = 'https://cloudflare.com/'

        result = strict_transport_security(reqs)

        self.assertEquals(result['result'], 'hsts-preloaded')
        self.assertFalse(result['includeSubDomains'])
        self.assertTrue(result['pass'])
        self.assertTrue(result['preloaded'])


class TestXContentTypeOptions(TestCase):
    def test_missing(self):
        reqs = empty_requests()

        result = x_content_type_options(reqs)

        self.assertEquals(result['result'], 'x-content-type-options-not-implemented')
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-Content-Type-Options'] = 'whimsy'

        result = x_content_type_options(reqs)

        self.assertEquals(result['result'], 'x-content-type-options-header-invalid')
        self.assertFalse(result['pass'])

    def test_nosniff(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-Content-Type-Options'] = 'nosniff'

        result = x_content_type_options(reqs)

        self.assertEquals(result['result'], 'x-content-type-options-nosniff')
        self.assertTrue(result['pass'])


class TestXFrameOptions(TestCase):
    def test_missing(self):
        reqs = empty_requests()

        result = x_frame_options(reqs)

        self.assertEquals(result['result'], 'x-frame-options-not-implemented')
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-Frame-Options'] = 'whimsy'

        result = x_frame_options(reqs)

        self.assertEquals(result['result'], 'x-frame-options-header-invalid')
        self.assertFalse(result['pass'])

    def test_deny(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-Frame-Options'] = 'DENY'

        result = x_frame_options(reqs)

        self.assertEquals(result['result'], 'x-frame-options-sameorigin-or-deny')
        self.assertTrue(result['pass'])

    def test_enabled_via_csp(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-Frame-Options'] = 'DENY'
        reqs['responses']['auto'].headers['Content-Security-Policy'] = 'frame-ancestors https://mozilla.org'

        result = x_frame_options(reqs)

        self.assertEquals(result['result'], 'x-frame-options-implemented-via-csp')
        self.assertTrue(result['pass'])


class TestXXSSProtection(TestCase):
    def test_missing(self):
        reqs = empty_requests()

        result = x_xss_protection(reqs)

        self.assertEquals(result['result'], 'x-xss-protection-not-implemented')
        self.assertFalse(result['pass'])

    def test_header_invalid(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-XSS-Protection'] = 'whimsy'

        result = x_xss_protection(reqs)

        self.assertEquals(result['result'], 'x-xss-protection-header-invalid')
        self.assertFalse(result['pass'])

    def test_disabled(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-XSS-Protection'] = '0'

        result = x_xss_protection(reqs)

        self.assertEquals(result['result'], 'x-xss-protection-disabled')
        self.assertFalse(result['pass'])

    def test_enabled_noblock(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-XSS-Protection'] = '1'

        result = x_xss_protection(reqs)

        self.assertEquals(result['result'], 'x-xss-protection-enabled')
        self.assertTrue(result['pass'])

    def test_enabled_block(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['X-XSS-Protection'] = '1; mode=block'

        result = x_xss_protection(reqs)

        self.assertEquals(result['result'], 'x-xss-protection-enabled-mode-block')
        self.assertTrue(result['pass'])

    def test_enabled_via_csp(self):
        reqs = empty_requests()
        reqs['responses']['auto'].headers['Content-Security-Policy'] = 'script-src \'none\''

        result = x_xss_protection(reqs)

        self.assertEquals(result['result'], 'x-xss-protection-not-needed-due-to-csp')
        self.assertTrue(result['pass'])
