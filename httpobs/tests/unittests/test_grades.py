from unittest import TestCase

from httpobs.scanner.grader import get_score_description, get_score_modifier


class TestGrader(TestCase):
    def test_get_score_description(self):
        self.assertEquals(
            'Content Security Policy (CSP) header not implemented',
            get_score_description('csp-not-implemented'),
        )

    def test_get_score_modifier(self):
        self.assertEquals(-25, get_score_modifier('csp-not-implemented'))
