import sys

from flask import Flask

from httpobs.conf import DEVELOPMENT_MODE, ENVIRONMENT, PORT
from httpobs.website import add_response_headers
from httpobs.website.common import common_api


def __exit_with(msg: str) -> None:
    print(msg)
    sys.exit(1)

# Register the application with flask
app = Flask('http-observatory')
if ENVIRONMENT == 'backend':
    print('Loading the HTTP Observatory Backend')
    from httpobs.website.backend import api
elif ENVIRONMENT == 'frontend':
    print('Loading the HTTP Observatory Frontend')
    from httpobs.website.frontend import api
app.register_blueprint(api)
app.register_blueprint(common_api)


@app.route('/')
@add_response_headers()
def main() -> str:
    return 'Welcome to the HTTP Observatory!'


if __name__ == '__main__':
    app.run(debug=DEVELOPMENT_MODE, port=PORT)
