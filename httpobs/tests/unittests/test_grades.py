from unittest import TestCase

from httpobs.scanner.grader import get_score_description, get_score_modifier


class TestGrader(TestCase):
    def test_get_score_description(self):
        self.assertEquals(
            'Contribute.json implemented with the required contact information',
            get_score_description('contribute-json-with-required-keys'),
        )

    def test_get_score_modifier(self):
        self.assertEquals(0, get_score_modifier('contribute-json-with-required-keys'))
