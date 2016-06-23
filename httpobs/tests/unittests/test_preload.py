from unittest import TestCase

from httpobs.scanner.analyzer.utils import is_hpkp_preloaded, is_hsts_preloaded


class TestPreloadPublicKeyPinning(TestCase):
    def test_not_preloaded(self):
        result = is_hpkp_preloaded('totallyfakehostname.insertsuperduperfakedomainhere.wtftld')

        self.assertFalse(result)

    def test_preloaded(self):
        result = is_hpkp_preloaded('apis.google.com')

        self.assertTrue(result['pinned'])
        self.assertTrue(result['includeSubDomainsForPinning'])

        result = is_hpkp_preloaded('foo.apis.google.com')

        self.assertTrue(result['pinned'])
        self.assertTrue(result['includeSubDomainsForPinning'])

        # uses include_subdomains_for_pinning
        result = is_hpkp_preloaded('dropboxstatic.com')

        self.assertTrue(result['pinned'])
        self.assertTrue(result['includeSubDomainsForPinning'])

        # this domain is manually pinned
        result = is_hpkp_preloaded('aus4.mozilla.org')

        self.assertTrue(result['pinned'])
        self.assertTrue(result['includeSubDomainsForPinning'])


class TestPreloadStrictTransportSecurity(TestCase):
    def test_not_preloaded(self):
        result = is_hsts_preloaded('totallyfakehostname.insertsuperduperfakedomainhere.wtftld')

        self.assertFalse(result)

    def test_preloaded(self):
        result = is_hsts_preloaded('bugzilla.mozilla.org')

        self.assertEquals('force-https', result['mode'])
        self.assertTrue(result['includeSubDomains'])

        result = is_hsts_preloaded('foo.bugzilla.mozilla.org')

        self.assertEquals('force-https', result['mode'])
        self.assertTrue(result['includeSubDomains'])

        result = is_hsts_preloaded('mail.yahoo.com')

        self.assertEqual('force-https', result['mode'])
        self.assertFalse(result['includeSubDomains'])

        # this domain is manually pinned
        result = is_hsts_preloaded('aus4.mozilla.org')

        self.assertTrue(result['pinned'])
        self.assertTrue(result['includeSubDomainsForPinning'])
