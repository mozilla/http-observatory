import sys

from flask import Flask
from os import environ

from httpobs.website import add_response_headers
from httpobs.website.common import common_api


def __exit_with(msg: str) -> None:
    print(msg)
    sys.exit(1)

# Register the application with flask
app = Flask('http-observatory')
if environ.get('HTTPOBS_ENVIRONMENT') == 'backend':
    print('Loading the HTTP Observatory Backend')
    from httpobs.website.backend import api
elif environ.get('HTTPOBS_ENVIRONMENT') == 'frontend':
    print('Loading the HTTP Observatory Frontend')
    from httpobs.website.frontend import api
else:
    __exit_with('HTTPOBS_ENVIRONMENT not set. Exiting.')
app.register_blueprint(api)
app.register_blueprint(common_api)

# Check to make sure we have all the needed environmental variables set
if 'HTTPOBS_API_KEY' not in environ:
    __exit_with('HTTPOBS_API_KEY not set. Exiting.')
elif environ.get('HTTPOBS_ENVIRONMENT') == 'frontend' and 'HTTPOBS_BACKEND_URL' not in environ:
    __exit_with('HTTPOBS_BACKEND_URL not set. Exiting.')


@app.route('/')
@add_response_headers()
def main() -> str:
    return 'Welcome to the HTTP Observatory!'


if __name__ == '__main__':
    port = 57001 if environ['HTTPOBS_ENVIRONMENT'] == 'frontend' else 57002

    # Enable debugging, if HTTPOBS_DEV is set
    debug = True if 'HTTPOBS_DEV' in environ else False

    app.run(debug=debug, port=port)
