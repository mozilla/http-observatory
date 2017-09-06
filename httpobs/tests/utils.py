from collections import UserDict
from copy import deepcopy
from requests.cookies import RequestsCookieJar

import os.path

from httpobs.scanner.utils import parse_http_equiv_headers


def empty_requests(http_equiv_file=None) -> dict:
    req = {
        'hostname': 'http-observatory.security.mozilla.org',
        'resources': {
            '/': None,
            '/clientaccesspolicy.xml': None,
            '/contribute.json': None,
            '/crossdomain.xml': None,
            '/robots.txt': None,
        },
        'responses': {
            'auto': UserDict(),
            'cors': None,
            'http': None,
            'https': None,
        },
        'session': UserDict(),
    }

    req['responses']['auto'].headers = {
        'Content-Type': 'text/html',
    }
    req['responses']['auto'].history = []
    req['responses']['auto'].request = UserDict()
    req['responses']['auto'].request.headers = UserDict()
    req['responses']['auto'].status_code = 200
    req['responses']['auto'].url = 'https://http-observatory.security.mozilla.org/'
    req['responses']['auto'].verified = True

    req['session'].cookies = RequestsCookieJar()

    req['responses']['cors'] = deepcopy(req['responses']['auto'])
    req['responses']['http'] = deepcopy(req['responses']['auto'])
    req['responses']['https'] = deepcopy(req['responses']['auto'])

    # Parse the HTML file for its own headers, if requested
    if http_equiv_file:
        __dirname = os.path.abspath(os.path.dirname(__file__))

        with open(os.path.join(__dirname, 'unittests', 'files', http_equiv_file), 'r') as f:
            html = f.read()

        req['responses']['auto'].http_equiv = parse_http_equiv_headers(html)
    else:
        req['responses']['auto'].http_equiv = {}

    return req
