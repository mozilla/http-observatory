from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import scored_test


def __parse_acao_xml_get_domains(xml, type='crossdomain') -> list:
    if xml is None:
        return []

    # Attempt to parse the XML file
    try:
        soup = bs(xml, 'html.parser')
    except:
        return None

    # Parse the files
    if type == 'crossdomain':
        return [domains.get('domain').strip() for domains in soup.find_all('allow-access-from') if domains.get('domain')]
    elif type == 'clientaccesspolicy':
        return [domains.get('uri').strip() for domains in soup.find_all('domain') if domains.get('uri')]


@scored_test
def cross_origin_resource_sharing(reqs: dict, expectation='cross-origin-resource-sharing-not-implemented') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        cross-origin-resource-sharing-not-implemented-with-universal-access: Allow origin *
        cross-origin-resource-sharing-not-implemented-with-restricted-access: Allow a specific origin
        cross-origin-resource-sharing-implemented: One of them does
        xml-not-parsable: Cannot parse one of the .xml files
    :return: dictionary with:
        data: the ACAO header, clientaccesspolicy.xml file, and crossorigin.xml file
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """
    # TODO: only store part of the xml files, in case they're huge?

    output = {
        'data': {
            'acao': None,
            'clientaccesspolicy': None,
            'crossdomain': None
        },
        'expectation': expectation,
        'pass': False,
        'result': 'cross-origin-resource-sharing-not-implemented',
    }

    acao = reqs['responses']['cors']

    if acao:
        if 'Access-Control-Allow-Origin' in acao.headers:
            output['data']['acao'] = acao.headers['Access-Control-Allow-Origin']

            if output['data']['acao'].strip() == '*':
                output['result'] = 'cross-origin-resource-sharing-implemented-with-public-access'
            elif (acao.request.headers.get('Origin') == acao.headers['Access-Control-Allow-Origin'] and
                  acao.headers.get('Access-Control-Allow-Credentials', '').lower().strip() == 'true'):
                output['result'] = 'cross-origin-resource-sharing-implemented-with-universal-access'
            else:
                output['result'] = 'cross-origin-resource-sharing-implemented-with-restricted-access'

    if reqs['resources']['/crossdomain.xml'] or reqs['resources']['/clientaccesspolicy.xml']:
        # Store the files in the database
        output['data']['crossdomain'] = reqs['resources']['/crossdomain.xml']
        output['data']['clientaccesspolicy'] = reqs['resources']['/clientaccesspolicy.xml']

        # Get the domains from each
        try:
            domains = (__parse_acao_xml_get_domains(reqs['resources']['/crossdomain.xml'], 'crossdomain') +
                       __parse_acao_xml_get_domains(reqs['resources']['/clientaccesspolicy.xml'], 'clientaccesspolicy'))
        except KeyError:
            domains = []
            output['result'] = 'xml-not-parsable'

        # If we can't parse either of those xml files
        if '*' in domains:
            output['result'] = 'cross-origin-resource-sharing-implemented-with-universal-access'
        else:
            output['result'] = 'cross-origin-resource-sharing-implemented-with-restricted-access'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True
    elif output['result'] in ('cross-origin-resource-sharing-implemented-with-public-access',
                              'cross-origin-resource-sharing-implemented-with-restricted-access'):
        output['pass'] = True

    return output


@scored_test
def redirection(reqs: dict, expectation='redirection-to-https') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        redirection-to-https: Redirects from http to https,
          first redirection stays on host [default]
        redirection-not-to-https: Redirection takes place, but to another HTTP address
        redirection-not-to-https-on-initial-redirection: final destination HTTPS, but not initial redirection
        redirection-missing: No redirection takes place, staying on HTTP
        redirection-not-needed-no-http: Site doesn't listen for HTTP requests at all
        redirection-off-host-from-http: Initial HTTP allowed to go from one host to another, still redirects to HTTPS
    :return: dictionary with:
        destination: final location of where GET / over HTTP ends
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        path: the URLs that the requests followed to get to destination
        redirects: whether the site does any redirections at all
        result: short string describing the result of the test
        status-code: HTTP status code for the final redirection (typically 301 or 302)
    """

    response = reqs['responses']['http']
    output = {
        'destination': response.url if response else None,
        'expectation': expectation,
        'pass': False,
        'redirects': True,
        'result': None,
        'route': [],
        'status_code': response.status_code if response else None,
    }

    if not response:
        output['result'] = 'redirection-not-needed-no-http'
    else:
        # Construct the route
        output['route'] = [r.request.url for r in response.history] if response.history else []
        output['route'] += [response.url]

        # No redirection, so you just stayed on the http website
        if len(output['route']) == 1:
            output['redirects'] = False
            output['result'] = 'redirection-missing'

        # Final destination wasn't an https website
        elif urlparse(output['route'][-1]).scheme != 'https':
            output['result'] = 'redirection-not-to-https'

        # http should never redirect to another http location -- should always go to https first
        elif urlparse(output['route'][1]).scheme == 'http':
            output['result'] = 'redirection-not-to-https-on-initial-redirection'

        # If it's an http -> https redirection, make sure it redirects to the same host. If that's not done, then
        # HSTS cannot be properly set on the original host
        elif (urlparse(output['route'][0]).scheme == 'http' and urlparse(output['route'][1]).scheme == 'https'and
                       urlparse(output['route'][0]).netloc != urlparse(output['route'][1]).netloc):
            output['result'] = 'redirection-off-host-from-http'
            output['status_code'] = response.history[-1].status_code
        else:
            output['result'] = 'redirection-to-https'

    # Check to see if the test passed or failed
    if expectation == output['result'] or output['result'] == 'redirection-not-needed-no-http':
        output['pass'] = True

    return output


@scored_test
def tls_configuration(reqs: dict, expectation='tls-configuration-intermediate-or-modern') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        tls-configuration-intermediate-or-modern: intermediate or modern TLS configuration [default]
        tls-configuration-modern: modern TLS configuration only
        tls-configuration-intermediate: intermediate TLS configuration only
        tls-configuration-old: old TLS configuration only
        tls-configuration-bad: known bad TLS configuration
        tls-configuration-weak-dhe: intermediate, but the only known problem is a weak DHE
        tls-observatory-scan-failed-no-https: site lacks HTTPS/TLS
        tls-observatory-scan-failed: TLS Observatory scan failed
    :return: dictionary with:
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
        tls_observatory_scan_id: TLS observatory scan id, for result lookups
    """

    output = {
        'expectation': expectation,
        'pass': False,
        'result': None,
        'tls_observatory_scan_id': None,
    }
    tlsobs = reqs['responses']['tlsobs']

    if tlsobs is None:
        output['result'] = 'tls-observatory-scan-failed'
    elif tlsobs['has_tls'] is False:
        output['result'] = 'tls-observatory-scan-failed-no-https'
    else:
        output['tls_observatory_scan_id'] = tlsobs['id']
        level = tlsobs['analysis'][0]['result']['level']

        # Some things trigger 'bad' when they shouldn't-ish
        if level == 'bad':
            failures = tlsobs['analysis'][0]['result']['failures']

            # Check to see if the only thing holding us back was a weak DHE (this is too common to fail every site)
            if all('consider ' in _ or 'use DHE of at least 2048bits' in _ for _ in failures['intermediate']):
                level = 'weak-dhe'

            # Also check to see if it's 'bad' but the only thing keeping it from old is a SHA-256 cert; this can be
            # a sign that cert switching is in use.  TODO: fix this once TLS Observatory is fixed
            # See also: https://github.com/mozilla/tls-observatory/issues/103
            elif all('consider ' in _ or 'use sha1WithRSAEncryption' in _ for _ in failures['old']):
                level = 'old'

        output['result'] = 'tls-configuration-' + level  # tls-configuration-intermediate

        # Quick shortcut to see if the test passed or failed (tls-configuration-intermediate is in default expectation)
        if level in expectation:
            output['pass'] = True

    return output
