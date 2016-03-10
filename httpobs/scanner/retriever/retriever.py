from celery.exceptions import SoftTimeLimitExceeded, TimeLimitExceeded
from urllib.parse import urlparse

from httpobs.database import select_site_headers

import requests


# Maximum timeout for requests for all GET requests for anything but the TLS Observatory
# The default ConnectionTimeout is something like 75 seconds, which means that things like
# tiles can take ~600s to timeout, since they have 8 DNS entries.  Setting it to lower
# should hopefully keep requests from taking forever
TIMEOUT = (6.05, 30)  # connect, read


# Create a session, returning the session and the HTTP response in a dictionary
# Don't create the sessions if it can't connect and retrieve the root of the website
# TODO: Allow people to scan a subdirectory instead of using '/' as the default path?
def __create_session(url: str, headers=None) -> dict:
    s = requests.Session()

    # Add the headers to the session
    if headers:
        s.headers.update(headers)

    # Override the User-Agent; some sites (like twitter) don't send the CSP header unless you have a modern
    # user agent
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0',
    })

    try:
        r = s.get(url, timeout=TIMEOUT)

        # Store the domain and scheme in the session
        s.url = urlparse(r.url)
    # Let celery exceptions percolate upward
    except (SoftTimeLimitExceeded, TimeLimitExceeded):
        raise
    except:
        r = None
        s = None

    return {'session': s, 'response': r}


def __get(session, relative_path='/', headers=None):
    try:
        # TODO: limit the maximum size of the response, to keep malicious site operators from killing us
        # TODO: Perhaps we can naively do it for now by simply setting a timeout?
        # TODO: catch TLS errors instead of just setting it to None?
        return session.get(session.url.scheme + '://' + session.url.netloc + relative_path, timeout=TIMEOUT)
    # Let celery exceptions percolate upward
    except (SoftTimeLimitExceeded, TimeLimitExceeded):
        raise
    except:
        return None


def __get_page_text(response: requests.Response) -> str:
    if not response:
        return None
    elif response.status_code == 200:
        # A quick and dirty check to make sure that somebody's 404 page didn't actually return 200 with html
        ext = response.url.split('.')[-1]
        if 'text/html' in response.headers.get('Content-Type', '') and ext in ('json', 'txt', 'xml'):
            return None

        return response.text
    else:
        return None


def retrieve_all(hostname: str) -> dict:
    retrievals = {
        'hostname': hostname,
        'resources': {
        },
        'responses': {
            'auto': None,  # whichever of 'http' or 'https' actually works, with 'https' as higher priority
            'cors': None,  # CORS preflight test
            'http': None,
            'https': None,
        },
        'session': None,
    }

    # The list of resources to get
    resources = (
        '/clientaccesspolicy.xml',
        '/contribute.json',
        '/crossdomain.xml',
        '/robots.txt'
    )

    # Get the headers from the database
    # TODO: Allow headers to be overridden on a per-scan basis?
    headers = select_site_headers(hostname)

    # Create some reusable sessions, one for HTTP and one for HTTPS
    http_session = __create_session('http://' + hostname + '/', headers=headers)
    https_session = __create_session('https://' + hostname + '/', headers=headers)

    # If neither one works, then the site just can't be loaded
    if not http_session['session'] and not https_session['session']:
        return retrievals

    else:
        # Store the HTTP only and HTTPS only responses (some things can only be retrieved over one or the other)
        retrievals['responses']['http'] = http_session['response']
        retrievals['responses']['https'] = https_session['response']

        if https_session['session']:
            retrievals['responses']['auto'] = https_session['response']
            retrievals['session'] = https_session['session']
        else:
            retrievals['responses']['auto'] = http_session['response']
            retrievals['session'] = http_session['session']

        # Store the contents of the base page
        retrievals['resources']['/'] = __get_page_text(retrievals['responses']['auto'])

        # Do a CORS preflight request
        retrievals['responses']['cors'] = __get(retrievals['session'], headers={'Origin': 'https://www.httplabs.org'})

        # Store all the files we retrieve
        for resource in resources:
            resp = __get(retrievals['session'], resource)
            retrievals['resources'][resource] = __get_page_text(resp)

    return retrievals
