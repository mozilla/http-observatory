from unittest import TestCase

from httpobs.scanner.analyzer.headers import __parse_csp as parse_csp


class TestContentSecurityPolicyParser(TestCase):
    def test_csp_parser(self):
        # one policy with one directive
        policy = ["default-src 'none'"]

        self.assertEquals(parse_csp(policy), {'default-src': {"'none'"}})

        # one policy with multiple directives
        policy = ["default-src 'none'; script-src 'self' https://mozilla.org"]
        self.assertEquals(
            parse_csp(policy), {'default-src': {"'none'"}, 'script-src': {"'self'", 'https://mozilla.org'}}
        )

        # two identical policies
        policy = [
            "default-src 'none'; script-src 'self' https://mozilla.org",
            "default-src 'none'; script-src 'self' https://mozilla.org",
        ]
        self.assertEquals(
            parse_csp(policy), {'default-src': {"'none'"}, 'script-src': {"'self'", 'https://mozilla.org'}}
        )

        # two policies, one of which has a source that isn't in the other
        policy = [
            "default-src 'none'; script-src 'self' https://mozilla.org",
            "default-src 'none'; script-src 'self' https://mozilla.org https://example.com",
        ]
        self.assertEquals(
            parse_csp(policy), {'default-src': {"'none'"}, 'script-src': {"'self'", 'https://mozilla.org'}}
        )

        # same thing as the previous policy, but the sources are in different orders
        policy = [
            "default-src 'none'; script-src 'self' https://mozilla.org",
            "default-src 'none'; script-src https://example.com 'self' https://mozilla.org",
        ]
        self.assertEquals(
            parse_csp(policy), {'default-src': {"'none'"}, 'script-src': {"'self'", 'https://mozilla.org'}}
        )

        # a policy with two differing websites that should end up with 'none'
        policy = [
            "default-src https://mozilla.org",
            "default-src https://mozilla.com",
        ]
        self.assertEquals(
            parse_csp(policy),
            {
                'default-src': {"'none'"},
            },
        )

        # a policy with four differing websites that should end up with 'none'
        policy = [
            "default-src https://mozilla.org https://mozilla.net",
            "default-src https://mozilla.com https://mozilla.io",
        ]
        self.assertEquals(
            parse_csp(policy),
            {
                'default-src': {"'none'"},
            },
        )

        # a policy with a bunch of websites, with only two in common
        policy = [
            "default-src https://mozilla.org https://mozilla.net https://mozilla.com https://mozilla.io",
            "default-src https://mozilla.pizza https://mozilla.ninja https://mozilla.net https://mozilla.org",
        ]
        self.assertEquals(
            parse_csp(policy),
            {
                'default-src': {"https://mozilla.net", "https://mozilla.org"},
            },
        )

        # a four policies with a bunch of websites, with only two in common
        policy = [
            "default-src https://mozilla.org https://mozilla.net https://mozilla.com https://mozilla.io",
            "default-src https://mozilla.pizza https://mozilla.ninja https://mozilla.net https://mozilla.org",
            "default-src https://mozilla.net https://mozilla.fox https://mozilla.fire https://mozilla.org",
            "default-src https://mozilla.browser https://mozilla.web https://mozilla.net https://mozilla.org",
        ]
        self.assertEquals(
            parse_csp(policy),
            {
                'default-src': {"https://mozilla.net", "https://mozilla.org"},
            },
        )

        # a policy with http: and https:, two differing sources that should end up with 'none'
        policy = [
            "default-src http:",
            "default-src https:",
        ]
        self.assertEquals(
            parse_csp(policy),
            {
                'default-src': {"'none'"},
            },
        )

        # a policy with http: and https:, two differing sources that should end up with 'none'
        policy = [
            "default-src http: http:",
            "default-src https: https:",
        ]
        self.assertEquals(
            parse_csp(policy),
            {
                'default-src': {"'none'"},
            },
        )

        # policies that are too short
        policies = (
            ["  "],
            ["\r\n"],
            ["\r\n\r\n\r\n\r\n\r\n\r\n"],
            [""],
            ["default-src 'none'; default-src 'none'"],  # Repeated directives not allowed
            ["default-src 'none'; img-src 'self'; default-src 'none'"],
            ["defa"],
        )
        for policy in policies:
            with self.assertRaises(ValueError):
                parse_csp(policy)
