from functools import wraps

from httpobs.scanner.grader.utils import GRADES


GRADE_TABLE = {
    # contribute.json
    'contribute-json-with-required-keys': 'A+',
    'contribute-json-only-required-on-mozilla-properties': 'A+',
    'contribute-json-missing-required-keys': 'A-',
    'contribute-json-not-implemented': 'B+',

    # CSP
    'csp-implemented-with-no-unsafe': 'A+',
    'csp-implemented-with-unsafe-allowed-in-style-src-only': 'A',
    'csp-implemented-with-unsafe': 'B',
    'csp-implemented-with-insecure-scheme': 'B',
    'csp-header-invalid': 'B',
    'csp-not-implemented': 'B',

    # Cookies
    'cookies-secure-with-httponly-sessions': 'A+',
    'cookies-not-found': 'A+',
    'cookies-without-secure-flag': 'B',
    'cookies-session-without-httponly-flag': 'C',
    'cookies-session-without-secure-flag': 'F',

    # Cross-origin resource sharing
    'cross-origin-resource-sharing-not-implemented': 'A+',
    'cross-origin-resource-sharing-implemented': 'D',

    # Redirection
    'redirection-to-https': 'A+',
    'redirection-not-needed-no-http': 'A+',
    'redirection-off-host-from-http': 'A-',
    'redirection-not-to-https': 'F',
    'redirection-missing': 'F',

    # Strict Transport Security (HSTS)
    'hsts-implemented-max-age-at-least-six-months': 'A+',
    'hsts-implemented-max-age-less-than-six-months': 'A-',
    'hsts-not-implemented': 'B',
    'hsts-not-implemented-no-https': 'F',

    # Subresource Integrity (SRI)
    'sri-implemented-and-external-scripts-loaded-securely': 'A+',
    'sri-not-implemented-response-not-html': 'A+',
    'sri-not-implemented-but-no-scripts-loaded': 'A+',
    'sri-not-implemented-but-all-scripts-loaded-from-secure-origin': 'A+',
    'sri-not-implemented-but-scripts-loaded-securely': 'A',
    'sri-implemented-but-external-scripts-not-loaded-securely': 'B+',
    'sri-not-implemented-and-scripts-loaded-insecurely': 'F',

    # TLS Configuration (TLS Observatory)
    'tls-configuration-modern': 'A+',
    'tls-configuration-intermediate-or-modern': 'A+',
    'tls-configuration-intermediate': 'A+',
    'tls-configuration-weak-dhe': 'B',
    'tls-configuration-old': 'C',
    'tls-configuration-bad': 'D',
    'tls-observatory-scan-failed-no-https': 'F',

    # X-Content-Type-Options
    'x-content-type-options-nosniff': 'A+',
    'x-content-type-options-not-implemented': 'A',
    'x-content-type-options-header-invalid': 'A',

    # X-Frame-Options
    'x-frame-options-sameorigin-or-deny': 'A+',
    'x-frame-options-allow-from-origin': 'A+',
    'x-frame-options-not-implemented': 'C',
    'x-frame-options-header-invalid': 'C',

    # X-XSS-Protection
    'x-xss-protection-1-mode-block': 'A+',
    'x-xss-protection-0': 'B+',
    'x-xss-protection-not-implemented': 'B+',
    'x-xss-protection-header-invalid': 'B+',

    # Generic results
    'html-not-parsable': 'C',
}


def graded_test(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        test_result = func(*args, **kwargs)
        test_result['grade'] = GRADES.index(GRADE_TABLE[test_result['result']])
        return test_result

    return wrapper