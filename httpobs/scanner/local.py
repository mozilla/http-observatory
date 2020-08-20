import httpobs.conf

from httpobs.scanner.analyzer import NUM_TESTS, tests
from httpobs.scanner.grader import (get_grade_and_likelihood_for_score,
                                    get_score_description,
                                    MINIMUM_SCORE_FOR_EXTRA_CREDIT)
from httpobs.scanner.retriever import retrieve_all


def scan(hostname, **kwargs):
    """Performs an Observatory scan, but doesn't require any database/redis
    backing. Given the lowered security concerns due to not being a public
    API, you can use this to scan arbitrary ports and paths.

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
    # Always allow localhost scans when run in this way
    httpobs.conf.SCANNER_ALLOW_LOCALHOST = True

    # Attempt to retrieve all the resources, not capturing exceptions
    reqs = retrieve_all(hostname, **kwargs)

    # If we can't connect at all, let's abort the test
    if reqs['responses']['auto'] is None:
        return {'error': 'site down'}

    # Code based on httpobs.database.insert_test_results
    tests_failed = tests_passed = 0
    score_with_extra_credit = uncurved_score = 100
    results = {}

    for test in tests:
        # Get result for this test
        result = test(reqs)

        # Add the result with a score_description
        result['score_description'] = get_score_description(result['result'])
        results[result.pop('name')] = result

        # Keep track of how many tests passed or failed
        if result.get('pass'):
            tests_passed += 1
        else:
            tests_failed += 1

        # And keep track of the score
        score_modifier = result.get('score_modifier')
        score_with_extra_credit += score_modifier
        if score_modifier < 0:
            uncurved_score += score_modifier

    # Only record the full score if the uncurved score already receives an A
    score = score_with_extra_credit if uncurved_score >= MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved_score

    # Get the score, grade, etc.
    score, grade, likelihood_indicator = get_grade_and_likelihood_for_score(score)

    # Return the results
    return({
        'scan': {
            'grade': grade,
            'likelihood_indicator': likelihood_indicator,
            'response_headers': dict(reqs['responses']['auto'].headers),
            'score': score,
            'tests_failed': tests_failed,
            'tests_passed': tests_passed,
            'tests_quantity': NUM_TESTS,
        },
        'tests': results
    })
