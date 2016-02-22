GRADE_CHART = {
    100: 'A+',
    95: 'A',
    90: 'A',
    85: 'A-',
    80: 'B+',
    75: 'B',
    70: 'B',
    65: 'B-',
    60: 'C+',
    55: 'C',
    50: 'C-',
    45: 'D+',
    40: 'D',
    35: 'D-',
    30: 'E',
    25: 'E',
    20: 'F',
    15: 'F',
    10: 'F',
    5: 'F',
    0: 'F'
}

SCORE_TABLE = {
    # contribute.json
    'contribute-json-with-required-keys': {
        'description': 'Contribute.json implemented with the required contact information',
        'modifier': 0,
    },
    'contribute-json-only-required-on-mozilla-properties': {
        'description': 'Contribute.json isn\'t required on websites that don\'t belong to Mozilla',
        'modifier': 0,
    },
    'contribute-json-missing-required-keys': {
        'description': 'Contribute.json exists, but is missing some of the required keys',
        'modifier': -5,
    },
    'contribute-json-not-implemented': {
        'description': 'Contribute.json file missing from root of website',
        'modifier': -10,
    },
    'contribute-json-invalid-json': {
        'description': 'Contribute.json file cannot be parsed',
        'modifier': -10,
    },

    # CSP
    'csp-implemented-with-no-unsafe': {
        'description': 'Content Security Policy (CSP) implemented without unsafe-inline or unsafe-eval',
        'modifier': 0,
    },
    'csp-implemented-with-unsafe-allowed-in-style-src-only': {
        'description': 'Content Security Policy (CSP) implemented with unsafe-inline inside style-src directive',
        'modifier': -5,
    },
    'csp-implemented-with-unsafe': {
        'description': 'Content Security Policy (CSP) implemented, but allows unsafe-inline or unsafe-eval',
        'modifier': -25,
    },
    'csp-implemented-with-insecure-scheme': {
        'description': 'Content Security Policy (CSP) implemented, but allows resources to be loaded from http',
        'modifier': -25,
    },
    'csp-header-invalid': {
        'description': 'Content Security Policy (CSP) header cannot be parsed successfully',
        'modifier': -25,
    },
    'csp-not-implemented': {
        'description': 'Content Security Policy (CSP) header missing',
        'modifier': -25,
    },

    # Cookies
    'cookies-secure-with-httponly-sessions': {
        'description': 'All cookies use the Secure flag and all session cookies use the HttpOnly flag',
        'modifier': 0,
    },
    'cookies-not-found': {
        'description': 'No cookies detected',
        'modifier': 0,
    },
    'cookies-without-secure-flag': {
        'description': 'Cookies set without using the Secure flag',
        'modifier': -25,
    },
    'cookies-session-without-httponly-flag': {
        'description': 'Session cookie set without using the HttpOnly flag',
        'modifier': -40,
    },
    'cookies-session-without-secure-flag': {
        'description': 'Session cookie set without using the Secure flag',
        'modifier': -100,
    },

    # Cross-origin resource sharing
    'cross-origin-resource-sharing-not-implemented': {
        'description': 'Content is visible via cross-origin resource sharing (CORS) files or headers',
        'modifier': 0,
    },
    'cross-origin-resource-sharing-implemented': {
        'description': 'Content is visible via cross-origin resource sharing (CORS) file or headers',
        'modifier': -50,
    },

    # Redirection
    'redirection-to-https': {
        'description': 'Initial redirection is not to https',
        'modifier': 0,
    },
    'redirection-not-needed-no-http': {
        'description': 'Not able to connect via http, so no redirection necessary',
        'modifier': 0,
    },
    'redirection-off-host-from-http': {
        'description': 'Initial redirection from http to https is to a different host, preventing HSTS',
        'modifier': -10,
    },
    'redirection-not-to-https': {
        'description': 'Redirects, but final destination is not over https',
        'modifier': -100,
    },
    'redirection-missing': {
        'description': 'Does not redirect to an https site',
        'modifier': -100,
    },

    # Strict Transport Security (HSTS)
    'hsts-implemented-max-age-at-least-six-months': {
        'description': 'HTTP Strict Transport Security (HSTS) header set to a minimum of six months (15768000)',
        'modifier': 0,
    },
    'hsts-implemented-max-age-less-than-six-months': {
        'description': 'HTTP Strict Transport Security (HSTS) header set to less than six months (15768000)',
        'modifier': -10,
    },
    'hsts-not-implemented': {
        'description': 'HTTP Strict Transport Security (HSTS) header is not set',
        'modifier': -25,
    },
    'hsts-not-implemented-no-https': {
        'description': 'HTTP Strict Transport Security (HSTS) header cannot be set for sites not available over https',
        'modifier': -100,
    },

    # Subresource Integrity (SRI)
    'sri-implemented-and-external-scripts-loaded-securely': {
        'description': 'Subresource Integrity (SRI) is implemented and all scripts are loaded securely',
        'modifier': 0,
    },
    'sri-not-implemented-response-not-html': {
        'description': 'Subresource Integrity (SRI) is only needed for html resources',
        'modifier': 0,
    },
    'sri-not-implemented-but-no-scripts-loaded': {
        'description': 'Subresource Integrity (SRI) is not needed since site contains no script tags',
        'modifier': 0,
    },
    'sri-not-implemented-but-all-scripts-loaded-from-secure-origin': {
        'description': 'Subresource Integrity (SRI) not implemented as all scripts are loaded from the same origin',
        'modifier': 0,
    },
    'sri-not-implemented-but-external-scripts-loaded-securely':{
        'description': 'Subresource Integrity (SRI) not implemented, but all external scripts are loaded over https',
        'modifier': -5,
    },
    'sri-implemented-but-external-scripts-not-loaded-securely': {
        'description': 'Subresource Integrity (SRI) implemented, but external scripts are loaded over http',
        'modifier': -20,
    },
    'sri-not-implemented-and-scripts-loaded-insecurely': {
        'description': 'Subresource Integrity (SRI) is not implemented, and external scripts are loaded over http',
        'modifier': -100,
    },

    # TLS Configuration (TLS Observatory)
    'tls-configuration-modern': {
        'description': 'Transport Layer Security (TLS/SSL) configuration uses the Mozilla modern recommendations',
        'modifier': 0,
    },
    'tls-configuration-intermediate-or-modern': {
        'description': 'Transport Layer Security (TLS/SSL) configuration uses the Mozilla modern or intermediate recommendations',
        'modifier': 0,
    },
    'tls-configuration-intermediate': {
        'description': 'Transport Layer Security (TLS/SSL) configuration uses the Mozilla intermediate recommendations',
        'modifier': 0,
    },
    'tls-configuration-weak-dhe': {
        'description': 'Transport Layer Security (TLS/SSL) configuration has a weak DHE group < 2048-bits',
        'modifier': -15,
    },
    'tls-configuration-old': {
        'description': 'Transport Layer Security (TLS/SSL) configuration uses the Mozilla old configuration',
        'modifier': -25,
    },
    'tls-configuration-bad': {
        'description': 'Transport Layer Security (TLS/SSL) configuration doesn\'t match any known Mozilla configurations',
        'modifier': -40,
    },
    'tls-observatory-scan-failed-no-https': {
        'description': 'Cannot be loaded over https',
        'modifier': -100,
    },

    # X-Content-Type-Options
    'x-content-type-options-nosniff': {
        'description': 'X-Content-Type-Options header set to "nosniff"',
        'modifier': 0,
    },
    'x-content-type-options-not-implemented': {
        'description': 'X-Content-Type-Options header not implemented',
        'modifier': -5,
    },
    'x-content-type-options-header-invalid': {
        'description': 'X-Content-Type-Options header cannot be recognized',
        'modifier': -5,
    },

    # X-Frame-Options
    'x-frame-options-sameorigin-or-deny': {
        'description': 'X-Frame-Options (XFO) header set to SAMEORIGIN or DENY',
        'modifier': 0,
    },
    'x-frame-options-allow-from-origin': {
        'description': 'X-Frame-Options (XFO) header uses ALLOW-FROM uri directive',
        'modifier': 0,
    },
    'x-frame-options-not-implemented': {
        'description': 'X-Frame-Options (XFO) header not implemented',
        'modifier': -40,
    },
    'x-frame-options-header-invalid': {
        'description': 'X-Frame-Options (XFO) header cannot be recognized',
        'modifier': -40,
    },

    # X-XSS-Protection
    'x-xss-protection-1-mode-block': {
        'description': 'X-XSS-Protection header set to "1; mode=block"',
        'modifier': 0,
    },
    'x-xss-protection-0': {
        'description': 'X-XSS-Protection header set to "0" (disabled)',
        'modifier': -5,
    },
    'x-xss-protection-not-implemented': {
        'description': 'X-XSS-Protection header not implemented',
        'modifier': -10,
    },
    'x-xss-protection-header-invalid': {
        'description': 'X-XSS-Protection header cannot be recognized',
        'modifier': -10,
    },

    # Generic results
    'html-not-parsable': {
        'description': 'Claims to be html, but cannot be parsed',
        'modifier': -20,  # can't run an SRI check if the HTML isn't parsable
    },
    'request-did-not-return-status-code-200': {
        'description': '/ did not return a status code of 200',
        'modifier': -5,  # can't run an SRI check on pages that don't return a 200
    }
}


def grade(scan_id) -> tuple:
    """
    :param scan_id: the scan_id belonging to the tests to grade
    :return: the overall test score and grade
    """
    from httpobs.database import select_test_results, insert_scan_grade  # avoid import loops

    # Get all the tests
    tests = select_test_results(scan_id)

    # TODO: this needs a ton of fleshing out
    score = 100
    for test in tests:
        if not tests[test]['pass']:
            score += tests[test]['score_modifier']

    score = min(max(score, 0), 100)

    # Insert the test score
    insert_scan_grade(scan_id, GRADE_CHART[score], score)

    return score, grade


def get_test_score_description(result) -> str:
    return SCORE_TABLE[result]['description']


def get_test_score_modifier(result) -> int:
    return SCORE_TABLE[result]['modifier']
