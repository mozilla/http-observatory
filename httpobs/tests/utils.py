from collections import UserDict
from copy import deepcopy


def empty_requests() -> dict:
    req = {
        'hostname': 'http-observatory.services.mozilla.com',
        'resources': {
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
        'session': None,
    }

    req['responses']['auto'].headers = {}
    req['responses']['auto'].url = 'https://http-observatory.services.mozilla.com'

    req['responses']['http'] = deepcopy(req['responses']['auto'])
    req['responses']['https'] = deepcopy(req['responses']['auto'])

    return req
