from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import scored_test
from httpobs.scanner.analyzer.utils import is_hpkp_preloaded, is_hsts_preloaded, only_if_worse


@scored_test
def content_security_policy(reqs: dict, expectation='csp-implemented-with-no-unsafe') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        csp-implemented-with-no-unsafe: CSP implemented with no unsafe inline keywords [default]
        csp-implemented-with-unsafe-in-style-src-only: Allow the 'unsafe' keyword in style-src only
        csp-implemented-with-unsafe-inline: CSP implemented with unsafe-inline
        csp-implemented-with-unsafe-eval: CSP implemented with unsafe-eval
        csp-implemented-with-insecure-scheme: CSP implemented with having sources over http:
        csp-invalid-header: Invalid CSP header
        csp-not-implemented: CSP not implemented
    :return: dictionary with:
        data: the CSP lookup dictionary
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'pass': False,
        'result': None,
    }
    response = reqs['responses']['auto']

    # TODO: check for CSP meta tags
    # TODO: try to parse when there are multiple CSP headers

    # Check to see the state of the CSP header
    if 'Content-Security-Policy' in response.headers:
        # Decompose the CSP; could probably do this in one step, but it's complicated enough
        # Should look like:
        # {
        #   'default-src': ['\'none\''],
        #   'script-src': ['https://mozilla.org', '\'unsafe-inline\''],
        #   'style-src': ['\'self\', 'https://mozilla.org'],
        #   'upgrade-insecure-requests': [],
        # }
        try:
            header = response.headers['Content-Security-Policy']
            csp = [directive.strip().split(maxsplit=1) for directive in header.split(';') if directive]
            csp = {directive[0].lower():
                   (directive[1].split() if len(directive) > 1 else []) for directive in csp}
        except:
            output['result'] = 'csp-header-invalid'
            return output

        # Replicate default-src to script-src and style-src, if they don't exist and default-src does
        csp['default-src'] = csp.get('default-src', '')
        for directive in ['script-src', 'style-src']:
            csp[directive] = csp.get(directive) if directive in csp else csp.get('default-src')

        # Do all of our tests
        if '\'unsafe-inline\'' in csp.get('script-src') or 'data:' in csp.get('script-src'):
            output['result'] = 'csp-implemented-with-unsafe-inline'
        elif not csp.get('default-src') and not csp.get('script-src'):
            output['result'] = 'csp-implemented-with-unsafe-inline'
        elif urlparse(response.url).scheme == 'https' and 'http:' in header:
            output['result'] = 'csp-implemented-with-insecure-scheme'
        elif '\'unsafe-eval\'' in csp.get('script-src') or '\'unsafe-eval\'' in csp.get('style-src'):
            output['result'] = 'csp-implemented-with-unsafe-eval'
        elif '\'unsafe-inline\'' in csp.get('style-src') or 'data:' in csp.get('style-src'):
            output['result'] = 'csp-implemented-with-unsafe-inline-in-style-src-only'
        else:
            output['result'] = 'csp-implemented-with-no-unsafe'

        # TODO: allow a small bonus for upgrade-insecure-requests?

        # Code defensively on the size of the data
        output['data'] = csp if len(str(csp)) < 32768 else {}

    else:
        output['result'] = 'csp-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True

    return output


@scored_test
def cookies(reqs: dict, expectation='cookies-secure-with-httponly-sessions') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        cookies-secure-with-httponly-sessions: All cookies have secure flag set, all session cookies are HttpOnly
        cookies-without-secure-flag-but-protected-by-hsts: Cookies don't have secure, but site uses HSTS
        cookies-session-without-secure-flag-but-protected-by-hsts: Same, but session cookie
        cookies-without-secure-flag: Cookies set without secure flag
        cookies-session-without-secure-flag: Session cookies lack the Secure flag
        cookies-session-without-httponly-flag: Session cookies lack the HttpOnly flag
        cookies-not-found: No cookies found in HTTP requests
    :return: dictionary with:
        data: the cookie jar
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'pass': False,
        'result': None,
    }
    session = reqs['session']  # all requests and their associated cookies

    # The order of how bad the various results are
    goodness = ['cookies-without-secure-flag-but-protected-by-hsts',
                'cookies-without-secure-flag',
                'cookies-session-without-secure-flag-but-protected-by-hsts',
                'cookies-session-without-secure-flag',
                'cookies-session-without-httponly-flag']

    # Get their HTTP Strict Transport Security status, which can help when cookies are set without Secure
    hsts = strict_transport_security(reqs)['pass']

    # If there are no cookies
    if not session.cookies:
        output['result'] = 'cookies-not-found'

    else:
        jar = {}

        for cookie in session.cookies:
            # The httponly functionality is a bit broken
            if not hasattr(cookie, 'httponly'):
                if 'httponly' in [key.lower() for key in cookie._rest]:
                    cookie.httponly = True
                else:
                    cookie.httponly = False

            # Add it to the jar
            jar[cookie.name] = {i: getattr(cookie, i, None) for i in ['domain', 'expires', 'httponly',
                                                                      'max-age', 'path', 'port', 'secure']}

            # Is it a session identifier?
            sessionid = any(i in cookie.name.lower() for i in ('login', 'sess'))

            if not cookie.secure and hsts:
                output['result'] = only_if_worse('cookies-without-secure-flag-but-protected-by-hsts',
                                                 output['result'],
                                                 goodness)

            elif not cookie.secure:
                output['result'] = only_if_worse('cookies-without-secure-flag',
                                                 output['result'],
                                                 goodness)

            # Login and session cookies should be set with Secure
            if sessionid and not cookie.secure and hsts:
                output['result'] = only_if_worse('cookies-session-without-secure-flag-but-protected-by-hsts',
                                                 output['result'],
                                                 goodness)
            elif sessionid and not cookie.secure:
                output['result'] = only_if_worse('cookies-session-without-secure-flag',
                                                 output['result'],
                                                 goodness)

            # Login and session cookies should be set with HttpOnly
            if sessionid and not cookie.httponly:
                output['result'] = only_if_worse('cookies-session-without-httponly-flag',
                                                 output['result'],
                                                 goodness)

        # Save the cookie jar
        output['data'] = jar if len(str(jar)) < 32768 else {}

        # Got through the cookie check properly
        if not output['result']:
            output['result'] = 'cookies-secure-with-httponly-sessions'

    # Check to see if the test passed or failed
    if output['result'] in ('cookies-not-found', expectation):
        output['pass'] = True

    return output


@scored_test
def public_key_pinning(reqs: dict, expectation='hpkp-not-implemented') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation; possible results:
      hpkp-not-implemented-no-https
      hpkp-not-implemented
      hpkp-implemented-max-age-less-than-fifteen-days
      hpkp-implemented-max-age-at-least-fifteen-days
      hpkp-preloaded
      hpkp-header-invalid
    :return: dictionary with:
      data: the raw HPKP header
        includesubdomains: whether the includeSubDomains directive is set
        max-age: what the max
        num-pins: the number of pins
      expectation: test expectation
      pass: whether the site's configuration met its expectation
      result: short string describing the result of the test
    """
    FIFTEEN_DAYS = 1296000

    output = {
        'data': None,
        'expectation': expectation,
        'includeSubDomains': False,
        'max-age': None,
        'numPins': None,
        'pass': True,
        'preloaded': False,
        'result': 'hpkp-not-implemented',
    }
    response = reqs['responses']['https']

    # If there's no HTTPS, we can't have HPKP
    if response is None:
        output['result'] = 'hpkp-not-implemented-no-https'

    elif 'Public-Key-Pins' in response.headers:
        output['data'] = response.headers['Public-Key-Pins'][0:2048]  # code against malicious headers

        try:
            pkp = [i.lower().strip() for i in output['data'].split(';')]
            pins = []

            for parameter in pkp:
                if parameter.startswith('max-age='):
                    output['max-age'] = int(parameter[8:128])  # defense
                elif parameter.startswith('pin-sha256=') and parameter not in pins:
                    pins.append(parameter)
                elif parameter == 'includesubdomains':
                    output['includeSubDomains'] = True
            output['numPins'] = len(pins)

            # You must set a max-age with HPKP
            if output['max-age']:
                if output['max-age'] < FIFTEEN_DAYS:
                    output['result'] = 'hpkp-implemented-max-age-less-than-fifteen-days'
                else:
                    output['result'] = 'hpkp-implemented-max-age-at-least-fifteen-days'

            # You must have at least two pins with HPKP and set max-age
            if not output['max-age'] or len(pins) < 2:
                raise ValueError

        except:
            output['result'] = 'hpkp-header-invalid'
            output['pass'] = False

    # If they're in the preloaded list, this overrides most anything else
    if response is not None:
        preloaded = is_hpkp_preloaded(urlparse(response.url).netloc)
        if preloaded:
            output['result'] = 'hpkp-preloaded'
            output['includeSubDomains'] = preloaded['includeSubDomainsForPinning']
            output['preloaded'] = True

    # No need to check pass/fail here, the only way to fail is to have an invalid header
    return output


@scored_test
def strict_transport_security(reqs: dict, expectation='hsts-implemented-max-age-at-least-six-months') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        hsts-implemented-max-age-at-least-six-months: HSTS implemented with a max age of at least six months (15768000)
        hsts-implemented-max-age-less-than-six-months: HSTS implemented with a max age of less than six months
        hsts-not-implemented-no-https: HSTS can't be implemented on http only sites
        hsts-not-implemented: HSTS not implemented
        hsts-header-invalid: HSTS header isn't parsable
    :return: dictionary with:
        data: the raw HSTS header
        expectation: test expectation
        includesubdomains: whether the includeSubDomains directive is set
        pass: whether the site's configuration met its expectation
        preload: whether the preload flag is set
        result: short string describing the result of the test
    """
    SIX_MONTHS = 15552000  # 15768000 is six months, but a lot of sites use 15552000, so a white lie is in order

    output = {
        'data': None,
        'expectation': expectation,
        'includeSubDomains': False,
        'max-age': None,
        'pass': False,
        'preload': False,
        'preloaded': False,
        'result': 'hsts-not-implemented',
    }
    response = reqs['responses']['https']

    # If there's no HTTPS, we can't have HSTS
    if response is None:
        output['result'] = 'hsts-not-implemented-no-https'

    elif 'Strict-Transport-Security' in response.headers:
        output['data'] = response.headers['Strict-Transport-Security'][0:1024]  # code against malicious headers

        try:
            sts = [i.lower().strip() for i in output['data'].split(';')]

            # Throw an error if the header is set twice
            if ',' in output['data']:
                raise ValueError

            for parameter in sts:
                if parameter.startswith('max-age='):
                    output['max-age'] = int(parameter[8:128])  # defense
                elif parameter == 'includesubdomains':
                    output['includeSubDomains'] = True
                elif parameter == 'preload':
                    output['preload'] = True

            if output['max-age']:
                if output['max-age'] < SIX_MONTHS:  # must be at least six months
                    output['result'] = 'hsts-implemented-max-age-less-than-six-months'
                else:
                    output['result'] = 'hsts-implemented-max-age-at-least-six-months'
            else:
                raise ValueError

        except:
            output['result'] = 'hsts-header-invalid'

    # If they're in the preloaded list, this overrides most anything else
    if response is not None:
        preloaded = is_hsts_preloaded(urlparse(response.url).netloc)
        if preloaded:
            output['result'] = 'hsts-preloaded'
            output['includeSubDomains'] = preloaded['includeSubDomains']
            output['preloaded'] = True

    # Check to see if the test passed or failed
    if output['result'] in ('hsts-implemented-max-age-at-least-six-months',
                            'hsts-preloaded',
                            expectation):
        output['pass'] = True

    return output


@scored_test
def x_content_type_options(reqs: dict, expectation='x-content-type-options-nosniff') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-content-type-options-nosniff: X-Content-Type-Options set to "nosniff" [default]
        x-content-type-options-not-implemented: X-Content-Type-Options header missing
        x-content-type-options-header-invalid
    :return: dictionary with:
        data: the raw X-Content-Type-Options header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'pass': False,
        'result': None,
    }
    response = reqs['responses']['auto']

    if 'X-Content-Type-Options' in response.headers:
        output['data'] = response.headers['X-Content-Type-Options'][0:256]  # code defensively

        if output['data'].lower() == 'nosniff':
            output['result'] = 'x-content-type-options-nosniff'
        else:
            output['result'] = 'x-content-type-options-header-invalid'
    else:
        output['result'] = 'x-content-type-options-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True

    return output


@scored_test
def x_frame_options(reqs: dict, expectation='x-frame-options-sameorigin-or-deny') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-frame-options-sameorigin-or-deny: X-Frame-Options set to "sameorigin" or "deny" [default]
        x-frame-options-allow-from-origin: X-Frame-Options set to ALLOW-FROM uri
        x-frame-options-implemented-via-csp: X-Frame-Options implemented via CSP frame-ancestors directive
        x-frame-options-not-implemented: X-Frame-Options header missing
        x-frame-options-header-invalid: Invalid X-Frame-Options header
    :return: dictionary with:
        data: the raw X-Frame-Options header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'pass': False,
        'result': None,
    }
    response = reqs['responses']['auto']

    if 'X-Frame-Options' in response.headers:
        output['data'] = response.headers['X-Frame-Options'][0:1024]  # code defensively
        xfo = output['data'].strip().lower()

        if xfo in ('deny', 'sameorigin'):
            output['result'] = 'x-frame-options-sameorigin-or-deny'
        elif xfo.startswith('allow-from '):
            output['result'] = 'x-frame-options-allow-from-origin'
        else:
            output['result'] = 'x-frame-options-header-invalid'
    else:
        output['result'] = 'x-frame-options-not-implemented'

    # Check to see if frame-ancestors is implemented in CSP; if it is, then it isn't needed
    csp = content_security_policy(reqs)
    if csp['data']:
        if 'frame-ancestors' in csp['data']:  # specifically not checking for * in frame-ancestors
            output['result'] = 'x-frame-options-implemented-via-csp'

    # Check to see if the test passed or failed
    if output['result'] in ('x-frame-options-allow-from-origin',
                            'x-frame-options-sameorigin-or-deny',
                            'x-frame-options-implemented-via-csp',
                            expectation):
        output['pass'] = True

    return output


@scored_test
def x_xss_protection(reqs: dict, expectation='x-xss-protection-1-mode-block') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-xss-protection-enabled-mode-block: X-XSS-Protection set to "1; block" [default]
        x-xss-protection-enabled: X-XSS-Protection set to "1"
        x-xss-protection-not-needed-due-to-csp: no X-XSS-Protection header, but CSP blocks inline nonsense
        x-xss-protection-disabled: X-XSS-Protection set to "0" (disabled)
        x-xss-protection-not-implemented: X-XSS-Protection header missing
        x-xss-protection-header-invalid
    :return: dictionary with:
        data: the raw X-XSS-Protection header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'pass': False,
        'result': None,
    }
    response = reqs['responses']['auto']

    xxssp = response.headers.get('X-XSS-Protection')

    if xxssp:
        output['data'] = xxssp[0:256]  # code defensively

        # Parse out the X-XSS-Protection header
        try:
            if xxssp[0] not in ('0', '1'):
                raise ValueError

            enabled = True if xxssp[0] == '1' else False

            # {'1': None, 'mode': 'block', 'report': 'https://www.example.com/__reporturi__'}
            xxssp = {d.split('=')[0].strip():
                     (d.split('=')[1].strip() if '=' in d else None) for d in xxssp.split(';')}
        except:
            output['result'] = 'x-xss-protection-header-invalid'
            return output

        if enabled and xxssp.get('mode') == 'block':
            output['result'] = 'x-xss-protection-enabled-mode-block'
        elif enabled:
            output['result'] = 'x-xss-protection-enabled'
        elif not enabled:
            output['result'] = 'x-xss-protection-disabled'

    else:
        output['result'] = 'x-xss-protection-not-implemented'

    # The test passes if X-XSS-Protection is enabled in any capacity
    if 'enabled' in output['result']:
        output['pass'] = True

    # Allow sites to skip out of having X-XSS-Protection if they implement a strong CSP policy
    if output['pass'] is False:
        if content_security_policy(reqs)['pass']:
            output['pass'] = True
            output['result'] = 'x-xss-protection-not-needed-due-to-csp'

    return output
