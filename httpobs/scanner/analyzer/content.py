import json
from urllib.parse import urlparse

from bs4 import BeautifulSoup as bs
from publicsuffixlist import PublicSuffixList

from httpobs.scanner.analyzer.decorators import scored_test
from httpobs.scanner.analyzer.utils import only_if_worse
from httpobs.scanner.retriever.retriever import HTML_TYPES

# Compat between Python 3.4 and Python 3.5 (see: https://github.com/mozilla/http-observatory-website/issues/14)
if not hasattr(json, 'JSONDecodeError'):  # pragma: no cover
    json.JSONDecodeError = ValueError


@scored_test
def subresource_integrity(reqs: dict, expectation='sri-implemented-and-external-scripts-loaded-securely') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        sri-implemented-and-all-scripts-loaded-securely: all same origin, and uses SRI
        sri-implemented-and-external-scripts-loaded-securely: integrity attribute exists on all external scripts,
          and scripts loaded [default for HTML]
        sri-implemented-but-external-scripts-not-loaded-securely: SRI implemented, but with scripts loaded over HTTP
        sri-not-implemented-but-external-scripts-loaded-securely: SRI isn't implemented,
          but all scripts are loaded over HTTPS
        sri-not-implemented-and-external-scripts-not-loaded-securely: SRI isn't implemented,
          and scripts are downloaded over HTTP
        sri-not-implemented-but-all-scripts-loaded-from-secure-origin: SRI isn't implemented,
          but all scripts come from secure origins (self)
        sri-not-implemented-but-no-scripts-loaded: SRI isn't implemented, because the page doesn't load any scripts
        sri-not-implemented-response-not-html: SRI isn't needed, because the page isn't HTML [default for non-HTML]
        request-did-not-return-status-code-200: Only look for SRI on pages that returned 200, not things like 404s
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

    # The order of how "good" the results are
    goodness = [
        'sri-implemented-and-all-scripts-loaded-securely',
        'sri-implemented-and-external-scripts-loaded-securely',
        'sri-implemented-but-external-scripts-not-loaded-securely',
        'sri-not-implemented-but-external-scripts-loaded-securely',
        'sri-not-implemented-and-external-scripts-not-loaded-securely',
        'sri-not-implemented-response-not-html',
    ]

    # If the content isn't HTML, there's no scripts to load; this is okay
    if response.headers.get('Content-Type', '').split(';')[0] not in HTML_TYPES:
        output['result'] = 'sri-not-implemented-response-not-html'

    else:
        # Try to parse the HTML
        try:
            soup = bs(reqs['resources']['__path__'], 'html.parser')
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

                # Check to see if they're on the same second-level domain
                # TODO: update the PSL list on startup
                psl = PublicSuffixList()
                samesld = (
                    True
                    if (psl.privatesuffix(urlparse(response.url).netloc) == psl.privatesuffix(src.netloc))
                    else False
                )

                if src.scheme == '':
                    if src.netloc == '':
                        # Relative URL (src="/path")
                        relativeorigin = True
                        relativeprotocol = False
                    else:
                        # Relative protocol (src="//host/path")
                        relativeorigin = False
                        relativeprotocol = True
                else:
                    relativeorigin = False
                    relativeprotocol = False

                # Check to see if it's the same origin or second-level domain
                if relativeorigin or (samesld and not relativeprotocol):
                    secureorigin = True
                else:
                    secureorigin = False
                    scripts_on_foreign_origin = True

                # See if it's a secure scheme
                if src.scheme == 'https' or (relativeorigin and urlparse(response.url).scheme == 'https'):
                    securescheme = True
                else:
                    securescheme = False

                # Add it to the scripts data result, if it's not a relative URI
                if not secureorigin:
                    output['data'][script['src']] = {'crossorigin': crossorigin, 'integrity': integrity}

                    if integrity and not securescheme:
                        output['result'] = only_if_worse(
                            'sri-implemented-but-external-scripts-not-loaded-securely', output['result'], goodness
                        )
                    elif not integrity and securescheme:
                        output['result'] = only_if_worse(
                            'sri-not-implemented-but-external-scripts-loaded-securely', output['result'], goodness
                        )
                    elif not integrity and not securescheme and samesld:
                        output['result'] = only_if_worse(
                            'sri-not-implemented-and-external-scripts' '-not-loaded-securely',
                            output['result'],
                            goodness,
                        )
                    elif not integrity and not securescheme:
                        output['result'] = only_if_worse(
                            'sri-not-implemented-and-external-scripts' '-not-loaded-securely',
                            output['result'],
                            goodness,
                        )

                # Grant bonus even if they use SRI on the same origin
                else:
                    if integrity and securescheme and not output['result']:
                        output['result'] = 'sri-implemented-and-all-scripts-loaded-securely'

        # If the page doesn't load any scripts
        if not scripts:
            output['result'] = 'sri-not-implemented-but-no-scripts-loaded'

        # If all the scripts are loaded from a secure origin, not triggering a need for SRI
        elif scripts and not scripts_on_foreign_origin and not output['result']:
            output['result'] = 'sri-not-implemented-but-all-scripts-loaded-from-secure-origin'

        # If the page loaded from a foreign origin, but everything included SRI
        elif scripts and scripts_on_foreign_origin and not output['result']:
            output['result'] = only_if_worse(
                'sri-implemented-and-external-scripts-loaded-securely', output['result'], goodness
            )

    # Code defensively on the size of the data
    output['data'] = output['data'] if len(str(output['data'])) < 32768 else {}

    # Check to see if the test passed or failed
    if output['result'] in (
        'sri-implemented-and-all-scripts-loaded-securely',
        'sri-implemented-and-external-scripts-loaded-securely',
        'sri-not-implemented-response-not-html',
        'sri-not-implemented-but-all-scripts-loaded-from-secure-origin',
        'sri-not-implemented-but-no-scripts-loaded',
        expectation,
    ):
        output['pass'] = True

    return output
