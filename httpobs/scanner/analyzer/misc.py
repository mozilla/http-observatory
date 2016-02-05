from urllib.parse import urlparse


def cross_origin_resource_sharing(reqs: dict, expectation='cross-origin-resource-sharing-not-implemented') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        cross-origin-resource-sharing-not-implemented: ACAO and the XML files don't exist [default]
        cross-origin-research-sharing-implemented: One of them does
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
            'crossorigin': None
        },
        'expectation': expectation,
        'pass': False,
        'result': None,
    }

    acao = reqs['responses']['auto']

    if 'Access-Control-Allow-Origin' in acao.headers:
        output['data']['acao'] = acao.headers['Access-Control-Allow-Origin']

        if '*' in output['acao']:
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


def redirection(reqs: dict, expectation='http-to-https-with-initial-redirect-to-same-host') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        http-to-https-with-initial-redirect-to-same-host: Redirects from http to https,
          first redirection stays on host [default]
        no-https-redirect: Site allowed to be served over HTTP
        not-listening-for-http: Site doesn't listen for HTTP requests at all
        off-host-redirection-from-http: Initial HTTP allowed to go from one host to another, still redirects to HTTPS
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
        output['result'] = 'not-listening-for-http'

    elif response.history:
        for entry in response.history:
            src = urlparse(entry.url)
            dst = urlparse(entry.headers['Location'])

            # Add the result to the path that requests followed
            output['route'].append(entry.url)

            # http should never redirect to another http location -- should always go to https first
            if dst.scheme != 'https':
                output['result'] = 'no-https-redirect'
                output['status_code'] = entry.status_code

            # If it's an http -> https redirection, make sure it redirects to the same host. If that's not done, then
            # HSTS cannot be properly set on the original host
            elif src.scheme == 'http' and dst.scheme == 'https' and src.netloc != dst.netloc:
                output['result'] = 'off-host-redirection-from-http'
                output['status_code'] = entry.status_code

            else:
                # Store the final status code for the redirection
                output['status_code'] = response.history[-1].status_code

        if not output['result']:
            output['result'] = 'http-to-https-with-initial-redirect-to-same-host'

    # No redirections took place
    else:
        output['result'] = 'no-https-redirect'
        output['redirects'] = False

    # Append the final location to the path
    output['route'].append(response.url)

    # Check to see if the test passed or failed
    if expectation == output['result'] or output['result'] == 'not-listening-for-http':
        output['pass'] = True

    return output


def tls_configuration(reqs: dict, expectation='intermediate-or-modern-tls-configuration') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        intermediate-or-modern-tls-configuration: intermediate or modern TLS configuration [default]
        modern-tls-configuration: modern TLS configuration only
        intermediate-tls-configuration: intermediate TLS configuration only
        old-tls-configuration: old TLS configuration only
        bad-tls-configuration: known bad TLS configuration
    :return: dictionary with:
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
        tls_observatory_scan_id: TLS observatory scan id, for result lookups
    """

    EVALUATION_HEADER = '* Mozilla evaluation: '
    SCANNING_HEADER = 'Scanning '

    output = {
        'expectation': expectation,
        'pass': False,
        'result': None,
        'tls_observatory_scan_id': None,
    }
    tlsobs = reqs['responses']['tlsobs']

    if tlsobs is None:
        output['result'] = 'tls-observatory-scan-failed'

    else:
        for line in tlsobs.split('\n'):
            if line.startswith(SCANNING_HEADER):
                output['tls_observatory_scan_id'] = int(line.split(' ')[-1][:-1])

            elif line.startswith(EVALUATION_HEADER):
                level = line.split(EVALUATION_HEADER)[-1]
                output['result'] = level + '-tls-configuration'  # intermediate-tls-configuration

                # Quick shortcut to see if the test passed or failed
                if level in expectation:
                    output['pass'] = True

    return output
