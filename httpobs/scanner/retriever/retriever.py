from celery.exceptions import SoftTimeLimitExceeded, TimeLimitExceeded
from urllib.parse import urlparse

from httpobs.conf import (RETRIEVER_CONNECT_TIMEOUT,
                          RETRIEVER_CORS_ORIGIN,
                          RETRIEVER_READ_TIMEOUT,
                          RETRIEVER_USER_AGENT)
from httpobs.database import select_site_headers

import requests


# Disable the requests InsecureRequestWarning -- we will track certificate errors manually when
# verification is disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Maximum timeout for requests for all GET requests for anything but the TLS Observatory
# The default ConnectionTimeout is something like 75 seconds, which means that things like
# tiles can take ~600s to timeout, since they have 8 DNS entries.  Setting it to lower
# should hopefully keep requests from taking forever
TIMEOUT = (RETRIEVER_CONNECT_TIMEOUT, RETRIEVER_READ_TIMEOUT)


# Create a session, returning the session and the HTTP response in a dictionary
# Don't create the sessions if it can't connect and retrieve the root of the website
# TODO: Allow people to scan a subdirectory instead of using '/' as the default path?
def __create_session(url: str, headers=None, cookies=None) -> dict:
    s = requests.Session()

    # Add the headers to the session
    if headers:
        s.headers.update(headers)

    # Set all the cookies and force them to be sent only over HTTPS; this might change in the future
    if cookies:
        s.cookies.update(cookies)

        for cookie in s.cookies:
            cookie.secure = True

    # Override the User-Agent; some sites (like twitter) don't send the CSP header unless you have a modern
    # user agent
    s.headers.update({
        'User-Agent': RETRIEVER_USER_AGENT,
    })

    try:
        r = s.get(url, timeout=TIMEOUT)

        # No tls errors
        r.verified = True
    # Let celery exceptions percolate upward
    except (SoftTimeLimitExceeded, TimeLimitExceeded):
        raise
    # We can try again if there's an SSL error, making sure to note it in the session
    except requests.exceptions.SSLError:
        try:
            r = s.get(url, timeout=TIMEOUT, verify=False)
            r.verified = False
        except:
            r = None
            s = None
    except:
        r = None
        s = None

    # Store the domain name and scheme in the session
    if r and s:
        s.url = urlparse(r.url)

    return {'session': s, 'response': r}


def __get(session, relative_path='/', headers=None, cookies=None):
    if not headers:
        headers = {}

    if not cookies:
        cookies = {}

    try:
        # TODO: limit the maximum size of the response, to keep malicious site operators from killing us
        # TODO: Perhaps we can naively do it for now by simply setting a timeout?
        # TODO: catch TLS errors instead of just setting it to None?
        return session.get(session.url.scheme + '://' + session.url.netloc + relative_path,
                           headers=headers,
                           cookies=cookies,
                           timeout=TIMEOUT)
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
        ext = (response.history[0].url if response.history else response.url).split('.')[-1]
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

    # Get the headers and cookies from the database
    # TODO: Allow headers to be overridden on a per-scan basis?
    headers = select_site_headers(hostname)

    # Create some reusable sessions, one for HTTP and one for HTTPS
    http_session = __create_session('http://' + hostname + '/',
                                    headers=headers['headers'],
                                    cookies=headers['cookies'])
    https_session = __create_session('https://' + hostname + '/',
                                     headers=headers['headers'],
                                     cookies=headers['cookies'])

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
        retrievals['responses']['cors'] = __get(retrievals['session'],
                                                headers={'Origin': RETRIEVER_CORS_ORIGIN})

        # Store all the files we retrieve
        for resource in resources:
            resp = __get(retrievals['session'], resource)
            retrievals['resources'][resource] = __get_page_text(resp)

    return retrievals
