from urllib.parse import urlparse

from httpobs.scanner.analyzer.decorators import scored_test
from httpobs.scanner.analyzer.utils import is_hpkp_preloaded, is_hsts_preloaded, only_if_worse


# Ignore the CloudFlare __cfduid tracking cookies. They *are* actually bad, but it is out of a site's
# control.  See https://github.com/mozilla/http-observatory/issues/121 for additional details. Hopefully
# this will eventually be fixed on CloudFlare's end.

# Also ignore the Heroku sticky session cookie, see:
# https://github.com/mozilla/http-observatory/issues/282
COOKIES_TO_DELETE = ['__cfduid', 'heroku-session-affinity']

# CSP settings
SHORTEST_DIRECTIVE = 'img-src'
SHORTEST_DIRECTIVE_LENGTH = len(SHORTEST_DIRECTIVE) - 1  # the shortest policy accepted by the CSP test


def __parse_csp(csp_string: str) -> dict:
    """
    Decompose the CSP; could probably do this in one step, but it's complicated enough
    Should look like:
    {
      'default-src': {'\'none\''},
      'object-src': {'\'none\''},
      'script-src': {'https://mozilla.org', '\'unsafe-inline\''},
      'style-src': {'\'self\', 'https://mozilla.org'},
      'upgrade-insecure-requests': {},
    }
    """

    # Clean out all the junk
    csp_string = csp_string.replace('\r', '').replace('\n', '').strip()

    # So technically the shortest directive is img-src, so lets just assume that
    # anything super short is invalid
    if len(csp_string) < SHORTEST_DIRECTIVE_LENGTH or csp_string.isspace():
        raise ValueError('CSP policy does not meet minimum length requirements')

    # It's actually rather up in the air if CSP is case sensitive or not for directives, see:
    # https://github.com/w3c/webappsec-csp/issues/236
    # For now, we shall treat it as case-sensitive, since it's the safer thing to do, even though
    # Firefox, Safari, and Edge all treat them as case-insensitive.
    csp = {}

    for entry in [directive.strip().split(maxsplit=1) for directive in csp_string.split(';') if directive]:
        if not entry:  # Catch errant semi-colons
            continue

        # Why not use .lower()? See: https://github.com/w3c/webappsec-csp/issues/236
        directive = entry[0]

        # Technically the path part of any source is case-sensitive, but since we don't test
        # any paths, we can cheat a little bit here
        values = set([source.lower() for source in entry[-1].split()]) if len(entry) > 1 else {'\'none\''}

        # While technically valid in that you just use the first entry, we are saying that repeated
        # directives are invalid so that people notice it
        if directive in csp:
            raise ValueError('Repeated policy directives are invalid')
        else:
            csp[directive] = values

    return csp


@scored_test
def content_security_policy(reqs: dict, expectation='csp-implemented-with-no-unsafe') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        csp-implemented-with-no-unsafe: CSP implemented with no unsafe inline keywords [default]
        csp-implemented-with-unsafe-in-style-src-only: Allow the 'unsafe' keyword in style-src only
        csp-implemented-with-insecure-scheme-in-passive-content-only:
          CSP implemented with insecure schemes (http, ftp) in img/media-src
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
        'http': False,    # whether an HTTP header was available
        'meta': False,    # whether an HTTP meta-equiv was available
        'pass': False,
        'policy': None,
        'result': None,
    }
    response = reqs['responses']['auto']

    # TODO: check for CSP meta tags
    # TODO: try to parse when there are multiple CSP headers

    # Obviously you can get around it with things like https://*.org, but you're only hurting yourself
    DANGEROUSLY_BROAD = ('ftp:', 'http:', 'https:', '*', 'http://*', 'http://*.*', 'https://*', 'https://*.*')
    UNSAFE_INLINE = ('\'unsafe-inline\'', 'data:')

    # Passive content check
    PASSIVE_DIRECTIVES = ('img-src', 'media-src')

    # What do nonces and hashes start with?
    NONCES_HASHES = ('\'sha256-', '\'sha384-', '\'sha512-', '\'nonce-')

    # First we need to combine the HTTP header and HTTP Equiv "header"
    try:
        headers = {
            'http': __parse_csp(response.headers.get('Content-Security-Policy'))
            if 'Content-Security-Policy' in response.headers else None,
            'meta': __parse_csp(response.http_equiv.get('Content-Security-Policy'))
            if 'Content-Security-Policy' in response.http_equiv else None,
        }
    except:
        output['result'] = 'csp-header-invalid'
        return output

    # If we have neither HTTP header nor meta, then there isn't any CSP
    if headers['http'] is None and headers['meta'] is None:
        output['result'] = 'csp-not-implemented'
        return output

    # If we make it this far, we have a policy object
    output['policy'] = {
        'antiClickjacking': False,
        'defaultNone': False,
        'insecureBaseUri': False,
        'insecureFormAction': False,
        'insecureSchemeActive': False,
        'insecureSchemePassive': False,
        'strictDynamic': False,
        'unsafeEval': False,
        'unsafeInline': False,
        'unsafeInlineStyle': False,
        'unsafeObjects': False,
    }

    # Store in our response object if we're using a header or meta
    output['http'] = True if headers.get('http') else False
    output['meta'] = True if headers.get('meta') else False

    if headers['http'] and headers['meta']:
        # This is technically incorrect. It's very easy to see if a given resource will be allowed
        # given multiple policies, but it's extremely difficult to generate a singular policy to
        # represent this. For the purposes of the Observatory, we just create a union of the two
        # policies. This is incorrect, since if one policy had 'unsafe-inline' and the other one
        # did not, the policy would not allow 'unsafe-inline'. Nevertheless, we are going to flag
        # it, because the behavior is probably indicative of something bad and if the other policy
        # ever disappeared, then bad things could happen that had previously been prevented.
        csp = {}
        for k in set(list(headers['http'].keys()) + list(headers['meta'].keys())):
            csp[k] = headers['http'].get(k, set()).union(headers['meta'].get(k, set()))
    else:
        csp = headers['http'] or headers['meta']

    # Get the various directives we look at
    base_uri = csp.get('base-uri') or {'*'}
    frame_ancestors = headers['http'].get('frame-ancestors', {'*'}) if headers['http'] is not None else {'*'}
    form_action = csp.get('form-action') or {'*'}
    object_src = csp.get('object-src') or csp.get('default-src') or {'*'}
    script_src = csp.get('script-src') or csp.get('default-src') or {'*'}
    style_src = csp.get('style-src') or csp.get('default-src') or {'*'}

    # Remove 'unsafe-inline' if nonce or hash are used in script-src or style-src
    # See: https://github.com/mozilla/http-observatory/issues/88
    #      https://github.com/mozilla/http-observatory/issues/277
    for source_list in (script_src, style_src):
        if any(source.startswith(NONCES_HASHES) for source in source_list) and '\'unsafe-inline\'' in source_list:
            source_list.remove('\'unsafe-inline\'')

    # If a script-src uses 'strict-dynamic', we need to:
    # 1. Check to make sure there's a valid nonce/hash source
    # 2. Remove any source that starts with as scheme
    # 3. Remove 'self' and 'unsafe-inline'
    if any(source.startswith(NONCES_HASHES) for source in script_src) and '\'strict-dynamic\'' in script_src:
        for source in set(script_src):
            if (source.startswith(DANGEROUSLY_BROAD) or
               source == '\'self\'' or
               source == '\'unsafe-inline\''):
                script_src.remove(source)
        output['policy']['strictDynamic'] = True
    # 'strict-dynamic' in script-src without hash or nonce
    elif '\'strict-dynamic\'' in script_src:
        output['result'] = ('csp-header-invalid' if output['result'] is None
                            else output['result'])

    # Some checks look only at active/passive CSP directives
    # This could be inlined, but the code is quite hard to read at that point
    active_csp_sources = [source for directive, source_list in csp.items() for source in source_list if
                          directive not in PASSIVE_DIRECTIVES and directive not in 'script-src'] + list(script_src)
    passive_csp_sources = [source for source_list in
                           [csp.get(directive, csp.get('default-src', [])) for directive in PASSIVE_DIRECTIVES]
                           for source in source_list]

    # Now to make the piggies squeal

    # No 'unsafe-inline' or data: in script-src
    # Also don't allow overly broad schemes such as https: in either object-src or script-src
    # Likewise, if you don't have object-src or script-src defined, then all sources are allowed
    if (script_src.intersection(DANGEROUSLY_BROAD + UNSAFE_INLINE) or
       object_src.intersection(DANGEROUSLY_BROAD)):
        output['result'] = ('csp-implemented-with-unsafe-inline' if output['result'] is None
                            else output['result'])
        output['policy']['unsafeInline'] = True

    # If the site is https, it shouldn't allow any http: as a source (active content)
    if (urlparse(response.url).scheme == 'https' and
       [source for source in active_csp_sources if 'http:' in source or 'ftp:' in source] and
       not output['policy']['strictDynamic']):
        output['result'] = ('csp-implemented-with-insecure-scheme' if output['result'] is None
                            else output['result'])
        output['policy']['insecureSchemeActive'] = True

    # Don't allow 'unsafe-eval' in script-src or style-src
    if script_src.union(style_src).intersection({'\'unsafe-eval\''}):
        output['result'] = ('csp-implemented-with-unsafe-eval' if output['result'] is None
                            else output['result'])
        output['policy']['unsafeEval'] = True

    # If the site is https, it shouldn't allow any http: as a source (passive content)
    if (urlparse(response.url).scheme == 'https' and
       [source for source in passive_csp_sources if 'http:' in source or 'ftp:' in source]):
        output['result'] = ('csp-implemented-with-insecure-scheme-in-passive-content-only' if output['result'] is None
                            else output['result'])
        output['policy']['insecureSchemePassive'] = True

    # Don't allow 'unsafe-inline', data:, or overly broad sources in style-src
    if style_src.intersection(DANGEROUSLY_BROAD + UNSAFE_INLINE):
        output['result'] = ('csp-implemented-with-unsafe-inline-in-style-src-only' if output['result'] is None
                            else output['result'])
        output['policy']['unsafeInlineStyle'] = True

    # Only if default-src is 'none' and 'none' alone, since additional uris override 'none'
    if csp.get('default-src') == {'\'none\''}:
        output['result'] = ('csp-implemented-with-no-unsafe-default-src-none' if output['result'] is None
                            else output['result'])
        output['policy']['defaultNone'] = True
    else:
        output['result'] = ('csp-implemented-with-no-unsafe' if output['result'] is None
                            else output['result'])

    # Some other checks for the CSP analyzer
    output['policy']['antiClickjacking'] = (not bool(frame_ancestors.intersection(DANGEROUSLY_BROAD)))
    output['policy']['insecureBaseUri'] = bool(base_uri.intersection(DANGEROUSLY_BROAD + UNSAFE_INLINE))
    output['policy']['insecureFormAction'] = (bool(form_action.intersection(DANGEROUSLY_BROAD)))
    output['policy']['unsafeObjects'] = bool(object_src.intersection(DANGEROUSLY_BROAD))

    # Once we're done, convert every set() in csp to an array
    csp = {k: list(v) for k, v in csp.items()}

    # TODO: allow a small bonus for upgrade-insecure-requests?

    # Code defensively on the size of the data
    output['data'] = csp if len(str(csp)) < 32768 else {}

    # Check to see if the test passed or failed
    if output['result'] in (expectation,
                            'csp-implemented-with-no-unsafe-default-src-none',
                            'csp-implemented-with-unsafe-inline-in-style-src-only',
                            'csp-implemented-with-insecure-scheme-in-passive-content-only'):
        output['pass'] = True

    return output


@scored_test
def cookies(reqs: dict, expectation='cookies-secure-with-httponly-sessions') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        cookies-secure-with-httponly-sessions-and-samesite: All cookies are secure,
          use HttpOnly if needed, and SameSite
        cookies-secure-with-httponly-sessions: All cookies have secure flag set, all session cookies are HttpOnly
        cookies-without-secure-flag-but-protected-by-hsts: Cookies don't have secure, but site uses HSTS
        cookies-session-without-secure-flag-but-protected-by-hsts: Same, but session cookie
        cookies-without-secure-flag: Cookies set without secure flag
        cookies-samesite-flag-invalid: Cookies set with invalid SameSite value (must be either unset, Strict, or Lax)
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
        'sameSite': None,
    }
    session = reqs['session']  # all requests and their associated cookies

    # The order of how bad the various results are
    goodness = ['cookies-without-secure-flag-but-protected-by-hsts',
                'cookies-without-secure-flag',
                'cookies-session-without-secure-flag-but-protected-by-hsts',
                'cookies-samesite-flag-invalid',
                'cookies-anticsrf-without-samesite-flag',
                'cookies-session-without-httponly-flag',
                'cookies-session-without-secure-flag']

    # TODO: Support cookies set over http-equiv (ugh)
    # https://github.com/mozilla/http-observatory/issues/265

    # Get their HTTP Strict Transport Security status, which can help when cookies are set without Secure
    hsts = strict_transport_security(reqs)['pass']

    # If there are no cookies
    if not session.cookies:
        output['result'] = 'cookies-not-found'

    else:
        jar = {}

        # There are certain cookies we ignore, because they are set by service providers and sites have
        # no control over them.
        for cookie in COOKIES_TO_DELETE:
            del(session.cookies[cookie])

        for cookie in session.cookies:
            # The HttpOnly and SameSite functionality is a bit broken
            cookie.httponly = cookie.samesite = False
            for key in cookie._rest:
                if key.lower() == 'httponly' and getattr(cookie, 'httponly') is False:
                    cookie.httponly = True
                elif key.lower() == 'samesite' and getattr(cookie, 'samesite') is False:
                    if cookie._rest[key] in (None, True) or cookie._rest[key].strip().lower() == 'lax':
                        cookie.samesite = 'Lax'
                        output['sameSite'] = True
                    elif cookie._rest[key].strip().lower() == 'strict':
                        cookie.samesite = 'Strict'
                        output['sameSite'] = True
                    else:
                        output['result'] = only_if_worse('cookies-samesite-flag-invalid',
                                                         output['result'],
                                                         goodness)

            # Add it to the jar
            jar[cookie.name] = {i: getattr(cookie, i, None) for i in ['domain', 'expires', 'httponly',
                                                                      'max-age', 'path', 'port', 'samesite', 'secure']}

            # Is it a session identifier or an anti-csrf token?
            sessionid = any(i in cookie.name.lower() for i in ('login', 'sess'))
            anticsrf = True if 'csrf' in cookie.name.lower() else False

            if not cookie.secure and hsts:
                output['result'] = only_if_worse('cookies-without-secure-flag-but-protected-by-hsts',
                                                 output['result'],
                                                 goodness)

            elif not cookie.secure:
                output['result'] = only_if_worse('cookies-without-secure-flag',
                                                 output['result'],
                                                 goodness)

            # Anti-CSRF tokens should be set using the SameSite option
            if anticsrf and not cookie.samesite:
                output['result'] = only_if_worse('cookies-anticsrf-without-samesite-flag',
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

        # Store whether or not we saw SameSite cookies, if cookies were set
        if output['result'] is None:
            if output['sameSite']:
                output['result'] = 'cookies-secure-with-httponly-sessions-and-samesite'
            else:
                output['result'] = 'cookies-secure-with-httponly-sessions'
                output['sameSite'] = False

        # Save the cookie jar
        output['data'] = jar if len(str(jar)) < 32768 else {}

    # Check to see if the test passed or failed
    if output['result'] in ('cookies-not-found',
                            'cookies-secure-with-httponly-sessions-and-samesite',
                            expectation):
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
      hpkp-invalid-cert
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

    # Can't have HPKP without a valid certificate chain
    elif not response.verified:
        output['result'] = 'hpkp-invalid-cert'

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
def referrer_policy(reqs: dict, expectation='referrer-policy-private') -> dict:
    """
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        referrer-policy-private: Referrer-Policy header set to "no-referrer" or "same-origin", "strict-origin"
          or "strict-origin-when-origin"
        referrer-policy-no-referrer-when-downgrade: Referrer-Policy header set to "no-referrer-when-downgrade"
        referrer-policy-origin: Referrer-Policy header set to "origin"
        referrer-policy-origin-when-cross-origin: Referrer-Policy header set to "origin-when-cross-origin"
        referrer-policy-unsafe-url: Referrer-Policy header set to "unsafe-url"
        referrer-policy-not-implemented: Referrer-Policy header not implemented
        referrer-policy-header-invalid
    :return: dictionary with:
        data: the raw HTTP Referrer-Policy header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
    """

    output = {
        'data': None,
        'expectation': expectation,
        'http': False,    # whether an HTTP header was available
        'meta': False,    # whether an HTTP meta-equiv was available
        'pass': False,
        'result': None,
    }

    goodness = ['no-referrer',
                'same-origin',
                'strict-origin',
                'strict-origin-when-cross-origin']

    badness = ['origin',
               'origin-when-cross-origin',
               'unsafe-url']

    valid = goodness + badness + ['no-referrer-when-downgrade']

    response = reqs['responses']['auto']

    # Store whether the header or meta were present
    output['http'] = True if 'Referrer-Policy' in response.headers else False
    output['meta'] = True if 'Referrer-Policy' in response.http_equiv else False

    # If it's in both a header and http-equiv, http-equiv gets precedence (aka comes last)
    if 'Referrer-Policy' in response.headers and 'Referrer-Policy' in response.http_equiv:
        output['data'] = ', '.join([response.headers['Referrer-Policy'],
                                   response.http_equiv['Referrer-Policy']])[0:256]  # Code defensively
    elif 'Referrer-Policy' in response.headers or 'Referrer-Policy' in response.http_equiv:
        output['data'] = (response.http_equiv.get('Referrer-Policy') or response.headers.get('Referrer-Policy'))[0:256]
    else:
        output['result'] = 'referrer-policy-not-implemented'
        output['pass'] = True
        return output

    # Find the last known valid policy value in the Referer Policy
    policy = [token.strip() for token in output['data'].lower().split(',') if token.strip() in valid]
    policy = policy.pop() if policy else None

    if policy in goodness:
        output['result'] = 'referrer-policy-private'
    elif policy == 'no-referrer-when-downgrade':
        output['result'] = 'referrer-policy-no-referrer-when-downgrade'
    elif policy in badness:
        output['result'] = 'referrer-policy-unsafe'
    else:
        output['result'] = 'referrer-policy-header-invalid'

    # Test passed or failed
    if output['result'] in ('referrer-policy-private',
                            'referrer-policy-not-implemented',
                            'referrer-policy-no-referrer-when-downgrade',
                            expectation):
        output['pass'] = True

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
        hsts-invalid-cert: Invalid certificate chain
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

    # Also need a valid certificate chain for HSTS
    elif not response.verified:
        output['result'] = 'hsts-invalid-cert'

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
    # TODO: Check to see if all redirect domains are preloaded
    # TODO: Check every redirect along the way for HSTS
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

        if output['data'].strip().lower() == 'nosniff':
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
    VALID_DIRECTIVES = ('0', '1', 'mode', 'report')
    VALID_MODES = ('block',)

    output = {
        'data': None,
        'expectation': expectation,
        'pass': False,
        'result': None,
    }

    enabled = False  # XXSSP enabled or not
    valid = True     # XXSSP header valid or not
    response = reqs['responses']['auto']
    header = response.headers.get('X-XSS-Protection', '').strip()
    xxssp = {}

    if header:
        output['data'] = header[0:256]  # code defensively

        # Parse out the X-XSS-Protection header
        try:
            if header[0] not in ('0', '1'):
                raise ValueError

            if header[0] == '1':
                enabled = True

            # {'1': None, 'mode': 'block', 'report': 'https://www.example.com/__reporturi__'}
            for directive in header.lower().split(';'):
                k, v = [d.strip() for d in directive.split('=')] if '=' in directive else (directive.strip(), None)

                # An invalid directive, like foo=bar
                if k not in VALID_DIRECTIVES:
                    raise ValueError

                # An invalid mode, like mode=allow
                if k == 'mode' and v not in VALID_MODES:
                    raise ValueError

                # A repeated directive, such as 1; mode=block; mode=block
                if k in xxssp:
                    raise ValueError

                xxssp[k] = v
        except:
            output['result'] = 'x-xss-protection-header-invalid'
            valid = False

        if valid and enabled and xxssp.get('mode') == 'block':
            output['result'] = 'x-xss-protection-enabled-mode-block'
            output['pass'] = True
        elif valid and enabled:
            output['result'] = 'x-xss-protection-enabled'
            output['pass'] = True
        elif valid and not enabled:
            output['result'] = 'x-xss-protection-disabled'

    else:
        output['result'] = 'x-xss-protection-not-implemented'

    # Allow sites to skip out of having X-XSS-Protection if they implement a strong CSP policy
    # Note that having an invalid XXSSP setting will still trigger, even with a good CSP policy
    if valid and output['pass'] is False:
        if content_security_policy(reqs)['pass']:
            output['pass'] = True
            output['result'] = 'x-xss-protection-not-needed-due-to-csp'

    return output
