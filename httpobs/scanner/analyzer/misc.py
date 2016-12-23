from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import scored_test
from httpobs.scanner.analyzer.utils import is_hsts_preloaded


def __parse_acao_xml_get_domains(xml, type='crossdomain') -> list:
    if xml is None:
        return []

    # Attempt to parse the XML file
    try:
        soup = bs(xml, 'html.parser')
    except:
        raise KeyError

    # Parse the files
    if type == 'crossdomain':
        return [domains.get('domain').strip()
                for domains in soup.find_all('allow-access-from') if domains.get('domain')]
    elif type == 'clientaccesspolicy':
        return [domains.get('uri').strip() for domains in soup.find_all('domain') if domains.get('uri')]


@scored_test
def cross_origin_resource_sharing(reqs: dict, expectation='cross-origin-resource-sharing-not-implemented') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        cross-origin-resource-sharing-implemented-with-public-access: Allow origin *
        cross-origin-resource-sharing-implemented-with-restricted-access: Allow a specific origin
        cross-origin-resource-sharing-implemented-with-universal-access: Reflect Origin, or have open .XML files
        cross-origin-resource-sharing-implemented: One of them does
        xml-not-parsable: Cannot parse one of the .xml files
    :return: dictionary with:
        data: the ACAO header, clientaccesspolicy.xml file, and crossorigin.xml file
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """
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

    # TODO: Fix ACAO being null?
    acao = reqs['responses']['cors']

    if acao is not None:
        if 'Access-Control-Allow-Origin' in acao.headers:
            output['data']['acao'] = acao.headers['Access-Control-Allow-Origin'].strip()[0:256]

            if output['data']['acao'] == '*':
                output['result'] = 'cross-origin-resource-sharing-implemented-with-public-access'
            elif (acao.request.headers.get('Origin') == acao.headers['Access-Control-Allow-Origin'] and
                  acao.headers.get('Access-Control-Allow-Credentials', '').lower().strip() == 'true'):
                output['result'] = 'cross-origin-resource-sharing-implemented-with-universal-access'
            else:
                output['result'] = 'cross-origin-resource-sharing-implemented-with-restricted-access'

    if reqs['resources']['/crossdomain.xml'] or reqs['resources']['/clientaccesspolicy.xml']:
        # Get the domains from each
        try:
            cd = __parse_acao_xml_get_domains(reqs['resources']['/crossdomain.xml'], 'crossdomain')
            cl = __parse_acao_xml_get_domains(reqs['resources']['/clientaccesspolicy.xml'], 'clientaccesspolicy')
            domains = cd + cl

            # Code defensively against infinitely sized xml files when storing their contents
            if len(str(domains)) < 32768:
                output['data']['clientaccesspolicy'] = cl if cl else None
                output['data']['crossdomain'] = cd if cd else None
        except KeyError:
            domains = []
            output['result'] = 'xml-not-parsable'  # If we can't parse either of those xml files

        if '*' in domains:
            output['result'] = 'cross-origin-resource-sharing-implemented-with-universal-access'

        # No downgrades from the ACAO result
        elif domains and output['result'] != 'cross-origin-resource-sharing-implemented-with-universal-access':
            output['result'] = 'cross-origin-resource-sharing-implemented-with-restricted-access'

    # Check to see if the test passed or failed
    if output['result'] in ('cross-origin-resource-sharing-implemented-with-public-access',
                            'cross-origin-resource-sharing-implemented-with-restricted-access',
                            expectation):
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
        redirection-invalid-cert: Invalid certificate chain encountered
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
        'destination': response.url[0:2048] if response else None,  # code defensively against long URLs
        'expectation': expectation,
        'pass': False,
        'redirects': True,
        'result': None,
        'route': [],
        'status_code': response.status_code if response else None,
    }

    if response is None:
        output['result'] = 'redirection-not-needed-no-http'

    # If we encountered an invalid certificate during the redirection process, that's a no-go
    elif not response.verified:
        output['result'] = 'redirection-invalid-cert'

    else:
        # Construct the route
        output['route'] = [r.request.url for r in response.history] if response.history else []
        output['route'] += [response.url]

        # Internally, we just use the port-trimmed urlparsed versions
        route = [urlparse(url) for url in output['route']]

        # Check to see if every redirection was covered by the preload list
        if all([is_hsts_preloaded(url.hostname) for url in route]):
            output['result'] = 'redirection-all-redirects-preloaded'

        # No redirection, so you just stayed on the http website
        elif len(output['route']) == 1:
            output['redirects'] = False
            output['result'] = 'redirection-missing'

        # Final destination wasn't an https website
        elif route[-1].scheme != 'https':
            output['result'] = 'redirection-not-to-https'

        # http should never redirect to another http location -- should always go to https first
        elif route[1].scheme == 'http':
            output['result'] = 'redirection-not-to-https-on-initial-redirection'

        # If it's an http -> https redirection, make sure it redirects to the same host. If that's not done, then
        # HSTS cannot be properly set on the original host
        # TODO: Check for redirections like: http://www.example.com -> https://example.com -> https://www.example.com
        elif (route[0].scheme == 'http' and route[1].scheme == 'https' and
              route[0].hostname != route[1].hostname):
            output['result'] = 'redirection-off-host-from-http'
            output['status_code'] = response.history[-1].status_code
        else:
            output['result'] = 'redirection-to-https'

    # Code defensively against infinite routing loops and other shenanigans
    output['route'] = output['route'] if len(str(output['route'])) < 8192 else []
    output['status_code'] = output['status_code'] if len(str(output['status_code'])) < 5 else None

    # Check to see if the test passed or failed
    if output['result'] in ('redirection-not-needed-no-http',
                            'redirection-all-redirects-preloaded',
                            expectation):
        output['pass'] = True

    return output
