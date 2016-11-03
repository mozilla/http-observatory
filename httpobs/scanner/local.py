import argparse
import httpobs.conf
import json

from httpobs.scanner.analyzer import NUM_TESTS, tests
from httpobs.scanner.grader import get_grade_and_likelihood_for_score, get_score_description
from httpobs.scanner.retriever import retrieve_all

from operator import itemgetter


def scan(hostname, **kwargs):
    """Performs an Observatory scan, but doesn't require any database/redis
    backing. Given the lowered security concerns due to not being a public
    API, you can use this to scan arbitrary ports and paths.

    Args:
        hostname (str): domain name for host to be scanned

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Add the various arguments
    parser.add_argument('--http-port',
                        default=80,
                        help='port to use for the HTTP scan (instead of 80)',
                        type=int)
    parser.add_argument('--https-port',
                        default=443,
                        help='port to use for the HTTPS scan (instead of 443)',
                        type=int)
    parser.add_argument('--path',
                        default=argparse.SUPPRESS,
                        help='path to scan, instead of /',
                        type=str)
    parser.add_argument('--no-verify',
                        action='store_true',
                        help='disable certificate verification in the HSTS/HPKP tests')
    parser.add_argument('--cookies',
                        default=argparse.SUPPRESS,
                        help='cookies to send in scan (json formatted)',
                        type=json.loads)
    parser.add_argument('--headers',
                        default=argparse.SUPPRESS,
                        help='headers to send in scan (json formatted)',
                        type=str)
    parser.add_argument('--format',
                        default='json',
                        help='output format (json or report), default of json',
                        type=str)
    parser.add_argument('hostname',
                        help='host to scan',
                        type=str)

    args = vars(parser.parse_args())

    # Remove the -- from the name, change - to underscore
    args = {k.split('--')[-1].replace('-', '_'): v for k, v in args.items()}
    format = args.pop('format').lower()

    # print out help if no arguments are specified, or bad arguments
    if len(args) == 0 or format not in ('json', 'report'):
        parser.print_help()
        parser.exit(-1)

    # Because it makes sense this way
    if args['http_port'] == 80:
        del(args['http_port'])

    if args['https_port'] == 443:
        del (args['https_port'])

    if args.pop('no_verify'):
        args['verify'] = False

    # Get the scan results
    r = scan(**args)

    # print out the results to the command line
    if format == 'json':
        print(json.dumps(r, indent=4, sort_keys=True))
    elif format == 'report':
        print('Score: {0} [{1}]'.format(r['scan']['score'],
                                        r['scan']['grade']))

        print('Modifiers:')

        # Get all the scores by test name
        scores = [[k.replace('-', ' ').title(), v['score_modifier'], v['score_description']]
                  for k, v in r['tests'].items()]
        scores = sorted(scores, key=itemgetter(0))  # [('test1', -5, 'foo'), ('test2', -10, 'bar')]

        for score in scores:
            if score[1] > 0:
                score[1] = '+' + str(score[1])  # display 5 as +5
            print('  {test:<30} [{modifier:>3}]  {reason}'.format(test=score[0],
                                                                  modifier=score[1],
                                                                  reason=score[2]))
