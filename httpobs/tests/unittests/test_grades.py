from unittest import TestCase

from httpobs.scanner.grader import get_score_description, get_score_modifier


class TestGrader(TestCase):
    def test_get_score_description(self):
        self.assertEquals('Preloaded via the HTTP Public Key Pinning (HPKP) preloading process',
                          get_score_description('hpkp-preloaded'))

    def test_get_score_modifier(self):
        self.assertEquals(0, get_score_modifier('hpkp-preloaded'))
