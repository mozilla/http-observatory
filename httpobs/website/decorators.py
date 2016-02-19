from flask import jsonify, make_response
from functools import wraps


def add_response_headers(headers=None, default_headers=None):
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
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
        }
    headers.update(default_headers)

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            resp = make_response(fn(*args, **kwargs))
            for header, value in headers.items():
                resp.headers[header] = value
            return resp
        return wrapper

    return decorator


def sanitized_api_response(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        output = fn(*args, **kwargs)

        SCAN_VALID_KEYS = ('end_time', 'error', 'scan_id', 'grade', 'score', 'start_time', 'state',
                           'tests_completed', 'tests_failed', 'tests_passed', 'tests_quantity')
        TEST_RESULT_VALID_KEYS = ('expectation', 'name', 'output', 'pass', 'result', 'score_modifier')

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
