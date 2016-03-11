import sys

from flask import Flask
from os import environ

from httpobs.website import add_response_headers

app = Flask('http-observatory')


@app.route('/')
@add_response_headers()
def main() -> str:
    return 'Welcome to the HTTP Observatory!'


def __exit_with(msg: str) -> None:
    print(msg)
    sys.exit(1)

if __name__ == '__main__':
    if environ.get('HTTPOBS_ENVIRONMENT') == 'backend':
        from httpobs.website.backend import api
        port = 57002
    elif environ.get('HTTPOBS_ENVIRONMENT') == 'frontend':
        from httpobs.website.frontend import api
        port = 57001
    else:
        __exit_with('HTTPOBS_ENVIRONMENT not set. Exiting.')

    # Check to make sure we have all the needed environmental variables set
    if 'HTTPOBS_API_KEY' not in environ:
        __exit_with('HTTPOBS_API_KEY not set. Exiting.')
    elif environ.get('HTTPOBS_ENVIRONMENT') == 'frontend' and 'HTTPOBS_BACKEND_URL' not in environ:
        __exit_with('HTTPOBS_BACKEND_URL not set. Exiting.')

    # Enable debugging, if HTTPOBS_DEV is set
    debug = True if 'HTTPOBS_DEV' in environ else False

    app.register_blueprint(api)
    app.run(debug=debug, port=port)
