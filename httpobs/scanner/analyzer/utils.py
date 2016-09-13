from httpobs.conf import SCANNER_PINNED_DOMAINS

import requests
import sys

from base64 import b64decode
from json import loads
from sys import exit


HSTS_URL = ('https://chromium.googlesource.com/chromium'
            '/src/net/+/master/http/transport_security_state_static.json?format=TEXT')
hsts = {}

# Download the Google HSTS Preload List
try:
    print('Retrieving the Chromium HSTS preload list', file=sys.stderr)
    r = b64decode(requests.get(HSTS_URL).text).decode('utf-8').split('\n')

    # Remove all the comments
    r = ''.join([line.split('// ')[0] for line in r if line.strip() != '//'])

    r = loads(r)

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

    # Print confirmation that preload list has been successfully downloaded and parsed
    print('Successfully downloaded and parsed the Chromium HSTS preload list', file=sys.stderr)
except:
    print('Unable to download the Chromium HSTS preload list; exiting', file=sys.stderr)
    exit(1)


def is_hpkp_preloaded(hostname):
    # Just see if the hostname is in the HSTS list and pinned
    if hsts.get(hostname, {}).get('pinned'):
        return hsts[hostname]

    # Either the hostname is in the list *or* one of its subdomains is
    host = hostname.split('.')
    levels = len(host)

    # If hostname is foo.bar.baz.mozilla.org, check bar.baz.mozilla.org, baz.mozilla.org, mozilla.org, and .org
    for i in range(1, levels):
        domain = '.'.join(host[i:levels])

        if hsts.get(domain, {}).get('pinned') is True and hsts.get(domain, {}).get('includeSubDomainsForPinning'):
            return hsts[domain]

    return False


def is_hsts_preloaded(hostname):
    # Just see if the hostname is the HSTS list with the right mode -- no need to check includeSubDomains
    if hsts.get(hostname, {}).get('mode') == 'force-https':
        return hsts[hostname]

    # Either the hostname is in the list *or* the TLD is and includeSubDomains is true
    host = hostname.split('.')
    levels = len(host)

    # If hostname is foo.bar.baz.mozilla.org, check bar.baz.mozilla.org, baz.mozilla.org, mozilla.org, and .org
    for i in range(1, levels):
        domain = '.'.join(host[i:levels])

        if hsts.get(domain, {}).get('mode') == 'force-https' and hsts.get(domain, {}).get('includeSubDomains'):
            return hsts[domain]

    return False


# Return the new result if it's worse than the existing result, otherwise just the current result
def only_if_worse(new_result: str, old_result: str, order) -> str:
    if not old_result:
        return new_result
    elif order.index(new_result) > order.index(old_result):
        return new_result
    else:
        return old_result


# Let this file be run directly so you can see the JSON for the Google HSTS thingie
if __name__ == '__main__':
    print(hsts)
