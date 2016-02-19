from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import scored_test


@scored_test
def content_security_policy(reqs: dict, expectation='csp-implemented-with-no-unsafe') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        csp-implemented-with-no-unsafe: CSP implemented with no unsafe inline keywords [default]
        csp-implemented-with-unsafe-allowed-in-style-src-only: Allow the 'unsafe' keyword in style-src only
        csp-implemented-with-unsafe: CSP implemented with using either unsafe-eval or unsafe-inline
        csp-implemented-with-insecure-scheme: CSP implemented with having sources over http:
        csp-invalid-header: Invalid CSP header
        csp-not-implemented: CSP not implemented
    :return: dictionary with:
        data: the raw CSP header
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

    # Check to see the state of the CSP header
    if 'Content-Security-Policy' in response.headers:
        # Store the CSP policy, if it's implemented
        output['data'] = response.headers['Content-Security-Policy'].strip()

        # Decompose the CSP; could probably do this in one step, but it's complicated enough
        try:
            csp = [directive.strip().split(' ', 1) for directive in output['data'].split(';')]
            csp = {directive[0].lower(): (directive[1] if len(directive) > 1 else '') for directive in csp}
        except:
            output['result'] = 'csp-invalid-header'
            return output

        for directive, value in csp.items():
            if 'unsafe-' in value and directive == 'style-src' and not output['result']:
                output['result'] = 'csp-implemented-with-unsafe-allowed-in-style-src-only'
            elif 'unsafe-' in value:
                output['result'] = 'csp-implemented-with-unsafe'
            elif urlparse(response.url).scheme == 'https' and 'http:' in value:
                output['result'] = 'csp-implemented-with-insecure-scheme'

        if not output['result']:
            output['result'] = 'csp-implemented-with-no-unsafe'

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

            # All cookies must be set with the secure flag, but httponly not being set overrides it
            # TODO: Check to see if it was set over http, where Secure wouldn't work
            if not cookie.secure and not output['result']:
                output['result'] = 'cookies-without-secure-flag'

            # Login and session cookies should be set with Secure
            # TODO: See if they're saved by HSTS?
            elif any(i in cookie.name.lower() for i in ['login', 'sess']) and not cookie.secure:
                output['result'] = 'cookies-session-without-secure-flag'

            # Login and session cookies should be set with HttpOnly
            elif any(i in cookie.name.lower() for i in ['login', 'sess']) and not cookie.httponly:
                output['result'] = 'cookies-session-without-httponly-flag'

        # Save the cookie jar
        output['data'] = jar

        # Got through the cookie check properly
        if not output['result']:
            output['result'] = 'cookies-secure-with-httponly-sessions'

    # Check to see if the test passed or failed
    if not session.cookies:
        output['pass'] = True
    elif expectation == output['result']:
        output['pass'] = True

    return output


# TODO: def public_key_pinning()


@scored_test
def strict_transport_security(reqs: dict, expectation='hsts-implemented-max-age-at-least-six-months') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        hsts-implemented-max-age-at-least-six-months: HSTS implemented with a max age of at least six months (15768000)
        hsts-implemented-max-age-less-than-six-months: HSTS implemented with a max age of less than six months
        hsts-not-implemented-no-https: HSTS can't be implemented on http only sites
        hsts-not-implemented: HSTS not implemented
    :return: dictionary with:
        data: the raw HSTS header
        expectation: test expectation
        includesubdomains: whether the includeSubDomains directive is set
        pass: whether the site's configuration met its expectation
        preload: whether the preload flag is set
        result: short string describing the result of the test
    """
    SIX_MONTHS = 15768000

    output = {
        'data': None,
        'expectation': expectation,
        'includesubdomains': None,
        'max-age': None,
        'pass': False,
        'preload': None,
        'result': None,
    }
    response = reqs['responses']['https']

    # If there's no HTTPS, we can't have HSTS
    if response is None:
        output['result'] = 'hsts-not-implemented-no-https'

    elif 'Strict-Transport-Security' in response.headers:
        output['data'] = response.headers['Strict-Transport-Security']

        try:
            sts = [i.lower().strip() for i in output['data'].split(';')]

            for parameter in sts:
                if parameter.startswith('max-age='):
                    output['max-age'] = int(parameter[8:])
                elif parameter == 'includesubdomains':
                    output['includesubdomains'] = True
                elif parameter == 'preload':
                    output['preload'] = True

            if output['max-age']:
                if output['max-age'] < SIX_MONTHS:  # must be at least six months
                    output['result'] = 'hsts-implemented-max-age-less-than-six-months'
                else:
                    output['result'] = 'hsts-implemented-max-age-at-least-six-months'
            else:
                output['result'] = 'hsts-invalid-header'

            # If they're not included, then they're considered to be unset
            if not output['includesubdomains']:
                output['includesubdomains'] = False
            if not output['preload']:
                output['preload'] = False

        except:
            output['result'] = 'hsts-invalid-header'

    # If HSTS isn't set in the headers
    else:
        output['result'] = 'hsts-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
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
        output['data'] = response.headers['X-Content-Type-Options']

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
        x-frame-options-not-implemented: X-Frame-Options header missing
        x-frame-options-header-invalid: Invalid X-Frame-Options header
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

    if 'X-Frame-Options' in response.headers:
        output['data'] = response.headers['X-Frame-Options']

        if output['data'].lower() in ('deny', 'sameorigin'):
            output['result'] = 'x-frame-options-sameorigin-or-deny'
        elif 'allow-from ' in output['data'].lower():
            output['result'] = 'x-frame-options-allow-from-origin'
        else:
            output['result'] = 'x-frame-options-header-invalid'
    else:
        output['result'] = 'x-frame-options-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True

    return output


@scored_test
def x_xss_protection(reqs: dict, expectation='x-xss-protection-1-mode-block') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-xss-protection-1-mode-block: X-XSS-Protection set to "1; block" [default]
        x-xss-protection-0: X-XSS-Protection set to "0" (disabled)
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

    if 'X-XSS-Protection' in response.headers:
        output['data'] = response.headers['X-XSS-Protection']

        if output['data'].lower().replace(' ', '').strip() == '1;mode=block':
            output['result'] = 'x-xss-protection-1-mode-block'
        elif output['data'].strip().startswith('0'):
            output['result'] = 'x-xss-protection-0'
        else:
            output['result'] = 'x-xss-protection-header-invalid'
    else:
        output['result'] = 'x-xss-protection-not-implemented'

    # Check to see if the test passed or failed
    if expectation == output['result']:
        output['pass'] = True
        
    return output
