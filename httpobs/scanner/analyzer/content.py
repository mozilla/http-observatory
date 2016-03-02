from bs4 import BeautifulSoup as bs
from publicsuffixlist import PublicSuffixList
from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import scored_test

import json


MOZILLA_DOMAINS = ('mozilla', 'allizom', 'webmaker')


@scored_test
def contribute(reqs: dict, expectation='contribute-json-with-required-keys') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        contribute-json-with-required-keys: contribute.json exists, with all the required_keys [default]
        contribute-json-missing-required-keys: contribute.json exists, but missing some of the required_keys (A-)
        contribute-json-only-required-on-mozilla-properties: contribute.json isn't required,
          since it's not a Mozilla domain
        contribute-json-not-implemented: contribute.json file missing (B+)
    :return: dictionary with:
        data: the parsed contribute.json file
        expectation: test expectation
        pass: whether the site's configuration met its expectation (null for non-Mozilla sites)
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'grade': None,
        'pass': False,
        'result': None,
    }

    # The keys that are required to be in contribute.json
    required_keys = ('name', 'description', 'participate', 'bugs', 'urls')

    response = reqs['responses']['auto']

    # If there's no contribute.json file
    if reqs['resources']['/contribute.json']:
        try:
            output['data'] = json.loads(reqs['resources']['/contribute.json'])

            if all(key in output['data'] for key in required_keys):
                output['result'] = 'contribute-json-with-required-keys'
            else:
                output['result'] = 'contribute-json-missing-required-keys'
        except (json.JSONDecodeError, TypeError):
            output['result'] = 'contribute-json-invalid-json'

    elif urlparse(response.url).netloc.split('.')[-2] not in MOZILLA_DOMAINS:
        output['expectation'] = output['result'] = 'contribute-json-only-required-on-mozilla-properties'
    else:
        output['result'] = 'contribute-json-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True
    elif output['result'] == 'contribute-json-only-required-on-mozilla-properties':
        output['pass'] = True

    return output


@scored_test
def subresource_integrity(reqs: dict, expectation='sri-implemented-and-external-scripts-loaded-securely') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        sri-implemented-and-external-scripts-loaded-securely: integrity attribute exists on all external scripts,
          and scripts loaded [default for HTML]
        sri-implemented-but-external-scripts-not-loaded-securely: SRI implemented, but with scripts loaded over HTTP
        sri-not-implemented-but-external-scripts-loaded-securely: SRI isn't implemented,
          but all scripts are loaded over HTTPS
        sri-not-implemented-and-scripts-loaded-insecurely: SRI isn't implemented, and scripts are downloaded over HTTP
        sri-not-implemented-but-all-scripts-loaded-from-secure-origin: SRI isn't implemented,
          but all scripts come from secure origins (self)
        sri-not-implemented-but-no-scripts-loaded: SRI isn't implemented, because the page doesn't load any scripts
        sri-not-implemented-response-not-html: SRI isn't needed, because the page isn't HTML [default for non-HTML]
        request-did-not-return-status-code-200: Let's only look for SRI on pages that returned 200, not things like 404s
        html-not-parsable: Can't parse the page's content
    :return: dictionary with:
        data: all external scripts and their integrity / crossorigin attributes
        expectation: test expectation
        pass: whether the site's external scripts met expectations
        result: short string describing the result of the test
    """
    output = {
        'data': {},
        'expectation': expectation,
        'pass': False,
        'result': None,
    }
    response = reqs['responses']['auto']

    # Return the new result if it's worse than the existing result, otherwise just the current result
    def only_if_worse(result: str) -> str:
        goodness = ['sri-implemented-and-external-scripts-loaded-securely',
                    'sri-implemented-but-external-scripts-not-loaded-securely',
                    'sri-not-implemented-but-external-scripts-loaded-securely',
                    'sri-not-implemented-and-scripts-loaded-insecurely',
                    'sri-not-implemented-response-not-html']

        if not output['result']:
            return result
        elif goodness.index(result) > goodness.index(output['result']):
            return result
        else:
            return output['result']

    # If the response to get / fails
    if response.status_code != 200:
        output['result'] = 'request-did-not-return-status-code-200'

    # If the content isn't HTML, there's no scripts to load; this is okay
    elif response.headers.get('Content-Type', '').split(';')[0] not in ('text/html', 'application/xhtml+xml'):
        output['result'] = 'sri-not-implemented-response-not-html'

    else:
        # Try to parse the HTML
        try:
            soup = bs(reqs['resources']['/'], 'html.parser')
        except:
            output['result'] = 'html-not-parsable'
            return output

        # Track to see if any scripts were on foreign TLDs
        scripts_on_foreign_origin = False

        # Get all the scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.has_attr('src'):
                # Script tag parameters
                src = urlparse(script['src'])
                integrity = script.get('integrity')
                crossorigin = script.get('crossorigin')

                # Check to see if they're on the same TLD
                # TODO: update the PSL list on startup
                psl = PublicSuffixList()
                sametld = True if psl.privatesuffix(response.url) == psl.privatesuffix(script['src']) else False

                # Check to see if it's the same origin, same or a trusted Mozilla subdomain
                if src.netloc != '' and '.' not in src.netloc:  # like localhost
                    secureorigin = False
                    scripts_on_foreign_origin = True
                elif (src.netloc == '' or
                    sametld or
                    src.netloc.split('.')[-2] in MOZILLA_DOMAINS):
                    secureorigin = True
                else:
                    secureorigin = False
                    scripts_on_foreign_origin = True

                # Add it to the scripts data result, if it's not a relative URI or on a Mozilla subdomain
                if not secureorigin:
                    output['data'][script['src']] = {
                                                        'crossorigin': crossorigin,
                                                        'integrity': integrity
                                                    }

                    # See if it's a secure scheme
                    if src.scheme == 'https' or (src.scheme == '' and urlparse(response.url).scheme == 'https'):
                        securescheme = True
                    else:
                        securescheme = False

                    if integrity and not securescheme:
                        output['result'] = only_if_worse('sri-implemented-but-external-scripts-not-loaded-securely')
                    elif not integrity and securescheme:
                        output['result'] = only_if_worse('sri-not-implemented-but-external-scripts-loaded-securely')
                    elif not integrity and not securescheme:
                        output['result'] = only_if_worse('sri-not-implemented-and-scripts-loaded-insecurely')

        # If the page doesn't load any scripts
        if not scripts:
            output['result'] = 'sri-not-implemented-but-no-scripts-loaded'

        # If all the scripts are loaded from a secure origin, not triggering a need for SRI
        elif scripts and not scripts_on_foreign_origin:
            output['result'] = 'sri-not-implemented-but-all-scripts-loaded-from-secure-origin'

        # If the page loaded from a foreign origin, but everything included SRI
        elif scripts and scripts_on_foreign_origin and not output['result']:
            output['result'] = 'sri-implemented-and-external-scripts-loaded-securely'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True
    elif output['result'] in ('sri-not-implemented-response-not-html',
                              'sri-not-implemented-but-all-scripts-loaded-from-secure-origin',
                              'sri-not-implemented-but-no-scripts-loaded'):
        output['pass'] = True

    return output
