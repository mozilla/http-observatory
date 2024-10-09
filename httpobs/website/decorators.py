from functools import wraps

from flask import jsonify, make_response, request


def add_sunset_headers():
    """
    Adds a "Sunset" header to the response
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            resp = make_response(fn(*args, **kwargs))
            resp.headers['Sunset'] = 'Thu, 31 Oct 2024 23:59:59 GMT'
            return resp

        return wrapper

    return decorator


def check_for_deprecation_override_header(fn):
    """
    Checks for the "X-Deprecation-Override" header and sets the response accordingly:
    - If the header is set to "yes", it will return the response as normal
    - If the header is set to anything else, it will return a 410 Gone response
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get('X-Deprecation-Override', 'no').lower() == 'yes':
            return fn(*args, **kwargs)
        else:
            return make_response(
                """
This API has been deprecated and is no longer available.
Please use https://observatory-api.mdn.mozilla.net/.
For details about the new endpint, see
https://github.com/mdn/mdn-http-observatory/blob/main/README.md#post-apiv2scan.

If you really want to continue with this endpoint for now,
please add a header to your request in the form of

X-Deprecation-Override: yes

Be aware that this API will go away without further warning on Oct 31, 2024.
    """,
                410,
            )

    return wrapper


def add_response_headers(headers=None, default_headers=None, cors=False):
    """
    Adds a bunch of headers to the Flask responses
    :param headers: a dictionary of headers and values to add to the response
    :param default_headers: a bunch of default security headers that all websites should have
    :return: decorator
    """
    if not headers:
        headers = {}

    if not default_headers:
        default_headers = {
            'Content-Security-Policy': (
                "default-src 'none'; base-uri 'none'; " "form-action 'none'; frame-ancestors 'none'"
            ),
            'Referrer-Policy': 'no-referrer',
            'Strict-Transport-Security': 'max-age=63072000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
        }
    headers.update(default_headers)

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Don't call the underlying function if the method is OPTIONS
            if request.method == 'OPTIONS':
                resp = make_response()
            else:
                resp = make_response(fn(*args, **kwargs))

            # Append the CORS headers
            if cors:
                headers.update(
                    {
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': ', '.join(request.url_rule.methods),
                        'Access-Control-Max-Age': '86400',
                        'Access-Control-Allow-Headers': 'X-Deprecation-Override',
                    }
                )

            # Append the headers to the response
            for header, value in headers.items():
                resp.headers[header] = value
            return resp

        return wrapper

    return decorator


def sanitized_api_response(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        output = fn(*args, **kwargs)

        SCAN_VALID_KEYS = (
            'algorithm_version',
            'end_time',
            'error',
            'grade',
            'hidden',
            'likelihood_indicator',
            'response_headers',
            'scan_id',
            'score',
            'start_time',
            'state',
            'status_code',
            'tests_completed',
            'tests_failed',
            'tests_passed',
            'tests_quantity',
        )
        TEST_RESULT_VALID_KEYS = (
            'error',
            'expectation',
            'name',
            'output',
            'pass',
            'result',
            'score_description',
            'score_modifier',
        )

        # Convert it to a dict (in case it's a DictRow)
        output = dict(output)

        if 'tests_quantity' in output:  # autodetect that it's a scan
            # Rename 'id' to 'result_id':
            output['scan_id'] = output.pop('id')

            # Remove 'error' if it's null
            if output['error'] is None:
                del output['error']

            # Delete any other things that might have made their way into the results
            output = {k: output[k] for k in SCAN_VALID_KEYS if k in output}

        elif 'content-security-policy' in output:  # autodetect that it's a test result
            for test in output:
                # Delete unnecessary keys
                output[test] = {k: output[test][k] for k in output[test] if k in TEST_RESULT_VALID_KEYS}

        return jsonify(output)

    return wrapper
