from collections import UserDict
from http.cookiejar import CookieJar
from copy import deepcopy


def empty_requests() -> dict:
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

    req['session'].cookies = CookieJar()

    req['responses']['cors'] = deepcopy(req['responses']['auto'])
    req['responses']['http'] = deepcopy(req['responses']['auto'])
    req['responses']['https'] = deepcopy(req['responses']['auto'])

    return req
