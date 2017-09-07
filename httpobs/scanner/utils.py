import json
import os.path
import requests
import socket
import sys

from base64 import b64decode
from bs4 import BeautifulSoup as bs
from httpobs.conf import (SCANNER_ALLOW_LOCALHOST,
                          SCANNER_PINNED_DOMAINS)
from requests.structures import CaseInsensitiveDict


HSTS_URL = ('https://chromium.googlesource.com/chromium'
            '/src/net/+/master/http/transport_security_state_static.json?format=TEXT')


def parse_http_equiv_headers(html: str) -> CaseInsensitiveDict:
    http_equiv_headers = CaseInsensitiveDict()

    # Try to parse the HTML
    try:
        soup = bs(html, 'html.parser')
    except:
        return http_equiv_headers

    # Find all the meta tags
    metas = soup.find_all('meta')

    for meta in metas:
        if meta.has_attr('http-equiv') and meta.has_attr('content'):
            # Add support for multiple CSP policies specified via http-equiv
            # See issue: https://github.com/mozilla/http-observatory/issues/266
            # Note that this is so far only done for CSP and not for other types
            # of http-equiv
            if (meta.get('http-equiv', '').lower().strip() == 'content-security-policy' and
               'Content-Security-Policy' in http_equiv_headers):
                http_equiv_headers['Content-Security-Policy'] += '; ' + meta.get('content')
            else:
                http_equiv_headers[meta.get('http-equiv')] = meta.get('content')

        # Technically not HTTP Equiv, but I'm treating it that way
        elif meta.get('name', '').lower().strip() == 'referrer' and meta.has_attr('content'):
            http_equiv_headers['Referrer-Policy'] = meta.get('content')

    return http_equiv_headers


def retrieve_store_hsts_preload_list():
    # Download the Google HSTS Preload List
    try:
        r = b64decode(requests.get(HSTS_URL).text).decode('utf-8').split('\n')

        # Remove all the comments
        r = ''.join([line.split('// ')[0] for line in r if line.strip() != '//'])

        r = json.loads(r)

        # Mapping of site -> whether it includes subdomains
        hsts = {site['name']: {
            'includeSubDomains': site.get('include_subdomains', False),
            'includeSubDomainsForPinning':
                site.get('include_subdomains', False) or site.get('include_subdomains_for_pinning', False),
            'mode': site.get('mode'),
            'pinned': True if 'pins' in site else False,
        } for site in r['entries']}

        # Add in the manually pinned domains
        for pinned_domain in SCANNER_PINNED_DOMAINS:
            hsts[pinned_domain] = {
                'includeSubDomains': True,
                'includeSubDomainsForPinning': True,
                'mode': 'force-https',
                'pinned': True
            }

        # Write json file to disk
        __dirname = os.path.abspath(os.path.dirname(__file__))
        __filename = os.path.join(__dirname, '..', 'conf', 'hsts-preload.json')

        with open(__filename, 'w') as f:
            json.dump(hsts, f, indent=2, sort_keys=True)

    except:
        print('Unable to download the Chromium HSTS preload list.', file=sys.stderr)


def sanitize_headers(headers: dict) -> dict:
    """
    :param headers: raw headers object from a request's response
    :return: that same header, after sanitization
    """
    try:
        if len(str(headers)) <= 16384:
            return dict(headers)
        else:
            return None

    except:
        return None


def valid_hostname(hostname: str):
    """
    :param hostname: The hostname requested in the scan
    :return: Hostname if it's valid, None if it's an IP address, otherwise False
    """

    # Block attempts to scan things like 'localhost' if not allowed
    if ('.' not in hostname or 'localhost' in hostname) and not SCANNER_ALLOW_LOCALHOST:
        return False

    # First, let's try to see if it's an IPv4 address
    try:
        socket.inet_aton(hostname)  # inet_aton() will throw an exception if hostname is not a valid IP address
        return None                 # If we get this far, it's an IP address and therefore not a valid fqdn
    except:
        pass

    # And IPv6
    try:
        socket.inet_pton(socket.AF_INET6, hostname)  # same as inet_aton(), but for IPv6
        return None
    except:
        pass

    # Then, try to do a lookup on the hostname; this should return at least one entry and should be the first time
    # that the validator is making a network connection -- the same that requests would make.
    try:
        hostname_ips = socket.getaddrinfo(hostname, 443)

        # This shouldn't trigger, since getaddrinfo should generate saierror if there's no A records.  Nevertheless,
        # I want to be careful in case of edge cases.  This does make it hard to test.
        if len(hostname_ips) < 1:
            return False
    except:
        return False

    # If we've made it this far, then everything is good to go!  Woohoo!
    return hostname
