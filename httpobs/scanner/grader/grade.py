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
    'contribute-json-with-required-keys': 0,
    'contribute-json-only-required-on-mozilla-properties': 0,
    'contribute-json-missing-required-keys': -5,
    'contribute-json-not-implemented': -15,

    # CSP
    'csp-implemented-with-no-unsafe': 0,
    'csp-implemented-with-unsafe-allowed-in-style-src-only': -5,
    'csp-implemented-with-unsafe': -25,
    'csp-implemented-with-insecure-scheme': -25,
    'csp-header-invalid': -25,
    'csp-not-implemented': -25,

    # Cookies
    'cookies-secure-with-httponly-sessions': 0,
    'cookies-not-found': 0,
    'cookies-without-secure-flag': -25,
    'cookies-session-without-httponly-flag': -40,
    'cookies-session-without-secure-flag': -100,

    # Cross-origin resource sharing
    'cross-origin-resource-sharing-not-implemented': 0,
    'cross-origin-resource-sharing-implemented': -50,

    # Redirection
    'redirection-to-https': 0,
    'redirection-not-needed-no-http': 0,
    'redirection-off-host-from-http': -10,
    'redirection-not-to-https': -100,
    'redirection-missing': -100,

    # Strict Transport Security (HSTS)
    'hsts-implemented-max-age-at-least-six-months': 0,
    'hsts-implemented-max-age-less-than-six-months': -10,
    'hsts-not-implemented': -25,
    'hsts-not-implemented-no-https': -100,

    # Subresource Integrity (SRI)
    'sri-implemented-and-external-scripts-loaded-securely': 0,
    'sri-not-implemented-response-not-html': 0,
    'sri-not-implemented-but-no-scripts-loaded': 0,
    'sri-not-implemented-but-all-scripts-loaded-from-secure-origin': 0,
    'sri-not-implemented-but-external-scripts-loaded-securely': -5,
    'sri-implemented-but-external-scripts-not-loaded-securely': -20,
    'sri-not-implemented-and-scripts-loaded-insecurely': -100,

    # TLS Configuration (TLS Observatory)
    'tls-configuration-modern': 0,
    'tls-configuration-intermediate-or-modern': 0,
    'tls-configuration-intermediate': 0,
    'tls-configuration-weak-dhe': -15,
    'tls-configuration-old': -25,
    'tls-configuration-bad': -40,
    'tls-observatory-scan-failed-no-https': -100,

    # X-Content-Type-Options
    'x-content-type-options-nosniff': 0,
    'x-content-type-options-not-implemented': -5,
    'x-content-type-options-header-invalid': -5,

    # X-Frame-Options
    'x-frame-options-sameorigin-or-deny': 0,
    'x-frame-options-allow-from-origin': 0,
    'x-frame-options-not-implemented': -40,
    'x-frame-options-header-invalid': -40,

    # X-XSS-Protection
    'x-xss-protection-1-mode-block': 0,
    'x-xss-protection-0': -5,
    'x-xss-protection-not-implemented': -10,
    'x-xss-protection-header-invalid': -10,

    # Generic results
    'html-not-parsable': -20,  # can't run an SRI check if the HTML isn't parsable
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


def get_test_score_modifier(result) -> int:
    return SCORE_TABLE[result]
