from flask import jsonify, make_response, request
from functools import wraps


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
            'Content-Security-Policy': ("default-src 'none'; base-uri 'none'; "
                                        "form-action 'none'; frame-ancestors 'none'"),
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
                headers.update({
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': ', '.join(request.url_rule.methods),
                    'Access-Control-Max-Age': '86400',
                })

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

        SCAN_VALID_KEYS = ('algorithm_version', 'end_time', 'error', 'grade', 'hidden', 'likelihood_indicator',
                           'response_headers', 'scan_id', 'score', 'start_time', 'state', 'status_code',
                           'tests_completed', 'tests_failed', 'tests_passed', 'tests_quantity')
        TEST_RESULT_VALID_KEYS = ('error', 'expectation', 'name', 'output', 'pass', 'result',
                                  'score_description', 'score_modifier')

        # Convert it to a dict (in case it's a DictRow)
        output = dict(output)

        if 'tests_quantity' in output:  # autodetect that it's a scan
            # Rename 'id' to 'result_id':
            output['scan_id'] = output.pop('id')

            # Remove 'error' if it's null
            if output['error'] is None:
                del(output['error'])

            # Delete any other things that might have made their way into the results
            output = {k: output[k] for k in SCAN_VALID_KEYS if k in output}

        elif 'content-security-policy' in output:  # autodetect that it's a test result
            for test in output:
                # Delete unnecessary keys
                output[test] = {k: output[test][k] for k in output[test] if k in TEST_RESULT_VALID_KEYS}

        return jsonify(output)
    return wrapper
