from flask import make_response
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
