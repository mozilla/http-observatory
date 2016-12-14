import json
import os.path


# Load the HSTS list from disk
__dirname = os.path.abspath(os.path.dirname(__file__))
__filename = os.path.join(__dirname, '..', '..', 'conf', 'hsts-preload.json')

with open(__filename, 'r') as f:
    hsts = json.load(f)


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
