from time import sleep
from urllib.parse import urlparse

from httpobs.database import select_site_headers

import requests


# Create a session, returning the session and the HTTP response in a dictionary
def __create_session(url: str, headers=None) -> dict:
    s = requests.Session()

    # Add the headers to the session
    if headers:
        s.headers.update(headers)

    r = s.get(url)

    # Store the domain and scheme in the session
    s.url = urlparse(r.url)

    return {'session': s, 'response': r}


def __get(session, relative_path='/'):
    try:
        return session.get(session.url.scheme + '://' + session.url.netloc + relative_path)
    except:
        return None


def __get_page_text(response: requests.Response) -> str:
    if response.status_code == 200:
        return response.text
    else:
        return None


def __get_tlsobs_result(hostname: str) -> dict:
    TLSOBS_SCAN_URI = 'https://tls-observatory.services.mozilla.com/api/v1/scan?target={hostname}'
    TLSOBS_RESULT_URI = 'https://tls-observatory.services.mozilla.com/api/v1/results?id={scan_id}'

    s = requests.Session()

    try:
        # First, make a POST to the TLS observatory API to initiate a scan
        r = s.post(TLSOBS_SCAN_URI.format(hostname=hostname))
        scan_id = str(r.json()['scan_id'])

        # Then, let's just keep polling until we get the completion percentage to 100
        count = 0

        while True:
            r = s.get(TLSOBS_RESULT_URI.format(scan_id=scan_id))

            # Keep scanning until the completion percentage is at 100%
            if r.json()['completion_perc'] == 100:
                return r.json()
            else:
                # Keep contacting the observatory every 1-5 seconds, and go for 5 minutes max
                count += 1
                if count >= 156:  # 5 minutes
                    break
                sleep(1) if count <= 120 else sleep(5)
    except:
        pass


def retrieve_all(hostname: str, headers=None) -> dict:
    retrievals = {
        'hostname': hostname,
        'resources': {
        },
        'responses': {
            'auto': None,  # whichever of 'http' or 'https' actually works, with 'https' as higher priority
            'http': None,
            'https': None,
            'tlsobs': None
        },
        'session': None,
    }

    # The list of resources to get
    resources = (
        '/clientaccesspolicy.xml',
        '/contribute.json',
        '/crossorigin.xml',
        '/robots.txt'
    )

    # Get the headers from the database
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

        # Store all the files we retrieve
        for resource in resources:
            resp = __get(retrievals['session'], resource)
            retrievals['resources'][resource] = __get_page_text(resp)

        # Store the TLS Observatory response
        retrievals['responses']['tlsobs'] = __get_tlsobs_result(hostname)

    return retrievals
