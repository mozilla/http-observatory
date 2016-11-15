import sys

from flask import Flask

from httpobs.conf import DEVELOPMENT_MODE, API_PORT, API_PROPAGATE_EXCEPTIONS
from httpobs.website import add_response_headers
from httpobs.website.api import api
from httpobs.website.monitoring import monitoring_api


def __exit_with(msg: str) -> None:
    print(msg)
    sys.exit(1)


# Register the application with flask
app = Flask('http-observatory')
app.config['PROPAGATE_EXCEPTIONS'] = API_PROPAGATE_EXCEPTIONS
app.register_blueprint(api)
app.register_blueprint(monitoring_api)


@app.route('/')
@add_response_headers()
def main() -> str:
    return 'Welcome to the HTTP Observatory!'


if __name__ == '__main__':
    app.run(debug=DEVELOPMENT_MODE,
            port=API_PORT)
