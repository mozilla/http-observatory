import httpobs.conf

from httpobs.scanner.analyzer import NUM_TESTS, tests
from httpobs.scanner.grader import get_grade_and_likelihood_for_score, get_score_description
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

    # Get all the results
    results = [test(reqs) for test in tests]
    for result in results:
        result['score_description'] = get_score_description(result['result'])

    # Get the score, grade, etc.
    grades = get_grade_and_likelihood_for_score(100 + sum([result.get('score_modifier', 0) for result in results]))
    tests_passed = sum([1 if result.get('pass') else 0 for result in results])

    # Return the results
    return({
        'scan': {
            'grade': grades[1],
            'likelihood_indicator': grades[2],
            'response_headers': dict(reqs['responses']['auto'].headers),
            'score': grades[0],
            'tests_failed': NUM_TESTS - tests_passed,
            'tests_passed': tests_passed,
            'tests_quantity': NUM_TESTS,
        },
        'tests': {result.pop('name'): result for result in results}
    })
