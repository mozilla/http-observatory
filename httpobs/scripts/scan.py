#!/usr/bin/env python3

import argparse
import json
from operator import itemgetter
from urllib.parse import urlparse

import httpobs.scanner


def main():
    parser = argparse.ArgumentParser()

    # Add the various arguments
    parser.add_argument('--http-port', default=80, help='port to use for the HTTP scan (instead of 80)', type=int)
    parser.add_argument('--https-port', default=443, help='port to use for the HTTPS scan (instead of 443)', type=int)
    parser.add_argument('--path', default=argparse.SUPPRESS, help='path to scan, instead of /', type=str)
    parser.add_argument('--no-verify', action='store_true', help='disable certificate verification in the HSTS tests')
    parser.add_argument(
        '--cookies', default=argparse.SUPPRESS, help='cookies to send in scan (json formatted)', type=json.loads
    )
    parser.add_argument(
        '--headers', default=argparse.SUPPRESS, help='headers to send in scan (json formatted)', type=json.loads
    )
    parser.add_argument('--format', default='json', help='output format (json or report), default of json', type=str)
    parser.add_argument('hostname', help='host to scan (hostname only, no protocol or port)', type=str)

    args = vars(parser.parse_args())

    # Remove the -- from the name, change - to underscore
    args = {k.split('--')[-1].replace('-', '_'): v for k, v in args.items()}
    output_format = args.pop('format').lower()

    # print out help if no arguments are specified, or bad arguments
    if len(args) == 0 or output_format not in ('json', 'report'):
        parser.print_help()
        parser.exit(-1)

    # port can't be appended to hostname because we need both HTTP and HTTPS ports.
    # protocol can't be prefixed either, as we scan both of those ports.
    #
    # use urlparse to ensure that neither of these are present in the hostname.
    if urlparse(args['hostname']).scheme or urlparse('http://' + args['hostname']).port:
        parser.print_help()
        parser.exit(-1)

    # Because it makes sense this way
    if args['http_port'] == 80:
        del args['http_port']

    if args['https_port'] == 443:
        del args['https_port']

    if args.pop('no_verify'):
        args['verify'] = False

    # Get the scan results
    r = httpobs.scanner.scan(**args)

    # print out the results to the command line
    if output_format == 'json':
        print(json.dumps(r, indent=4, sort_keys=True))
    elif output_format == 'report':
        print('Score: {0} [{1}]'.format(r['scan']['score'], r['scan']['grade']))

        print('Modifiers:')

        # Get all the scores by test name
        scores = [
            [k.replace('-', ' ').title(), v['score_modifier'], v['score_description']] for k, v in r['tests'].items()
        ]
        scores = sorted(scores, key=itemgetter(0))  # [('test1', -5, 'foo'), ('test2', -10, 'bar')]

        for score in scores:
            if score[1] > 0:
                score[1] = '+' + str(score[1])  # display 5 as +5
            print('  {test:<30} [{modifier:>3}]  {reason}'.format(test=score[0], modifier=score[1], reason=score[2]))


if __name__ == "__main__":
    main()
