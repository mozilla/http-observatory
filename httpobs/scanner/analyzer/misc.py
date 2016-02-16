from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import graded_test


@graded_test
def cross_origin_resource_sharing(reqs: dict, expectation='cross-origin-resource-sharing-not-implemented') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        cross-origin-resource-sharing-not-implemented: ACAO and the XML files don't exist [default]
        cross-origin-resource-sharing-implemented: One of them does
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
            'crossorigin': None
        },
        'expectation': expectation,
        'pass': False,
        'result': None,
    }

    acao = reqs['responses']['auto']

    if 'Access-Control-Allow-Origin' in acao.headers:
        output['data']['acao'] = acao.headers['Access-Control-Allow-Origin']

        if '*' in output['data']['acao']:
            output['result'] = 'cross-origin-resource-sharing-implemented'

    # TODO: check to see if it's a limited clientaccesspolicy.xml file
    if reqs['resources']['/clientaccesspolicy.xml'] == 200:
        output['result'] = 'cross-origin-resource-sharing-implemented'
        output['data']['clientaccesspolicy'] = reqs['resources']['/clientaccesspolicy.xml']

    # TODO: check to see if it's a limited crossorigin.xml file
    if reqs['resources']['/crossorigin.xml']:
        output['result'] = 'cross-origin-resource-sharing-implemented'
        output['data']['crossorigin'] = reqs['resources']['/crossorigin.xml']

    if not output['data']['acao'] and not output['data']['clientaccesspolicy'] and not output['data']['crossorigin']:
        output['result'] = 'cross-origin-resource-sharing-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True

    return output


@graded_test
def redirection(reqs: dict, expectation='redirection-to-https') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        redirection-to-https: Redirects from http to https,
          first redirection stays on host [default]
        redirection-not-to-https: Redirection takes place, but to another HTTP address
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
        'destination': response.url,
        'expectation': expectation,
        'pass': False,
        'redirects': True,
        'result': None,
        'route': [],
        'status_code': response.status_code,
    }

    if not response:
        output['result'] = 'redirection-not-needed-no-http'

    elif response.history:
        for entry in response.history:
            src = urlparse(entry.url)
            dst = urlparse(entry.headers['Location'])

            # Add the result to the path that requests followed
            output['route'].append(entry.url)

            # http should never redirect to another http location -- should always go to https first
            if dst.scheme != 'https':
                output['result'] = 'redirection-not-to-https'
                output['status_code'] = entry.status_code
                break

            # If it's an http -> https redirection, make sure it redirects to the same host. If that's not done, then
            # HSTS cannot be properly set on the original host
            elif src.scheme == 'http' and dst.scheme == 'https' and src.netloc != dst.netloc:
                output['result'] = 'redirection-off-host-from-http'
                output['status_code'] = entry.status_code
                break

            else:
                # Store the final status code for the redirection
                output['status_code'] = response.history[-1].status_code

        if not output['result']:
            output['result'] = 'redirection-to-https'

    # No redirections took place
    else:
        output['result'] = 'redirection-missing'
        output['redirects'] = False

    # Append the final location to the path
    output['route'].append(response.url)

    # Check to see if the test passed or failed
    if expectation == output['result'] or output['result'] == 'redirection-not-needed-no-http':
        output['pass'] = True

    return output


@graded_test
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
        output['result'] = 'tls-configuration-' + level  # tls-configuration-intermediate

        # Check to see if the only thing holding it back was a weak DHE (this is too common to fail every site)
        if level == 'bad':
            bad = False
            for consideration in tlsobs['analysis'][0]['result']['failures']['intermediate']:
                if 'consider ' not in consideration and 'use DHE of at least 2048bits' not in consideration:
                    print(consideration)
                    bad = True

            if not bad:
                output['result'] = 'tls-configuration-weak-dhe'

        # Quick shortcut to see if the test passed or failed (tls-configuration-intermediate is in default expectation)
        if level in expectation:
            output['pass'] = True

    return output
