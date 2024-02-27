import os.path
from collections import UserDict
from copy import deepcopy
from typing import Union

from requests.cookies import RequestsCookieJar
from urllib3 import HTTPResponse
from urllib3._collections import HTTPHeaderDict

from httpobs.scanner.utils import parse_http_equiv_headers


def empty_requests(http_equiv_file=None) -> dict:
    req = {
        'hostname': 'http-observatory.security.mozilla.org',
        'resources': {
            '__path__': None,
            '/': None,
            '/clientaccesspolicy.xml': None,
            '/crossdomain.xml': None,
            '/robots.txt': None,
        },
        'responses': {
            'auto': HTTPResponse(),
            'cors': None,
            'http': None,
            'https': None,
        },
        'session': UserDict(),
    }

    # Parse the HTML file for its own headers, if requested
    if http_equiv_file:
        __dirname = os.path.abspath(os.path.dirname(__file__))

        with open(os.path.join(__dirname, 'unittests', 'files', http_equiv_file), 'r') as f:
            html = f.read()

        # Load the HTML file into the object for content tests.
        req['resources']['__path__'] = html

    req['responses']['auto'].headers = {
        'Content-Type': 'text/html',
    }
    req['responses']['auto'].history = []
    req['responses']['auto'].raw = HTTPResponse()
    req['responses']['auto'].raw.headers = HTTPHeaderDict()
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
        req['responses']['auto'].http_equiv = parse_http_equiv_headers(req['resources']['__path__'])
    else:
        req['responses']['auto'].http_equiv = {}

    return req


# if we want to handle multiple of the same header, we need to add it to both headers and raw headers
def set_header(response: HTTPResponse, header: str, values: Union[str, list]):
    if isinstance(values, str):
        values = [values]

    for value in values:
        response.headers[header] = response.headers[header] + ', ' + value if header in response.headers else value
        response.raw.headers.add(header, value)
