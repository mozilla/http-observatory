from httpobs.scanner.analyzer import NUM_TESTS, tests
from httpobs.scanner.grader import (
    MINIMUM_SCORE_FOR_EXTRA_CREDIT,
    get_grade_and_likelihood_for_score,
    get_score_description,
)
from httpobs.scanner.retriever import retrieve_all
from httpobs.scanner.utils import sanitize_headers

# Current algorithm version
ALGORITHM_VERSION = 3


def scan(hostname: str, **kwargs):
    """Performs an Observatory scan.

    Args:
        hostname (str): domain name for host to be scanned. Must not include
            protocol (http://, https://) or port number (:80).

    Kwargs:
        http_port (int): port to scan for HTTP, instead of 80
        https_port (int): port to be scanned for HTTPS, instead of 443
        path (str): path to scan, instead of "/"
        verify (bool): whether to enable or disable certificate verification,
            enabled by default. This can allow tested sites to pass the HSTS
            and HPKP tests, even with self-signed certificates.

        cookies (dict): Cookies sent to the system being scanned. Matches the
            requests cookie dict.
        headers (dict): HTTP headers sent to the system being scanned. Format
            matches the requests headers dict.

    Returns:
        A dict representing the analyze (scan) and getScanResults (test) API call.  Example:

        {
            'scan': {
                'grade': 'A'
                ...
            },
            'test': {
                'content-security-policy': {
                    'pass': True
                    ...
                }
            }
        }
    """

    # Attempt to retrieve all the resources
    reqs = retrieve_all(hostname, **kwargs)

    # If we can't connect at all, let's abort the test
    if reqs['responses']['auto'] is None:
        return {'error': 'site down'}

    results = [test(reqs) for test in tests]
    response_headers = sanitize_headers(reqs["responses"]["auto"].headers)
    status_code = reqs["responses"]["auto"].status_code

    tests_passed = 0
    score_with_extra_credit = uncurved_score = 100

    for result in results:
        result["score_description"] = get_score_description(result['result'])

        passed = result.get("pass")
        score_modifier = result.get("score_modifier")

        # Keep track of how many tests passed or failed
        if passed:
            tests_passed += 1

        # And keep track of the score
        score_with_extra_credit += score_modifier
        if score_modifier < 0:
            uncurved_score += score_modifier

    # Only record the full score if the uncurved score already receives an A
    score = score_with_extra_credit if uncurved_score >= MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved_score

    # Now we need to update the scans table
    score, grade, likelihood_indicator = get_grade_and_likelihood_for_score(score)

    return {
        "scan": {
            "algorithm_version": ALGORITHM_VERSION,
            "grade": grade,
            "likelihood_indicator": likelihood_indicator,
            "response_headers": response_headers,
            "score": score,
            "tests_failed": NUM_TESTS - tests_passed,
            "tests_passed": tests_passed,
            "tests_quantity": NUM_TESTS,
            "status_code": status_code,
        },
        "tests": {result.pop("name"): result for result in results},
    }
