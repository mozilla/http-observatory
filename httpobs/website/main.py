from flask import Flask
from os import environ

from httpobs.website import add_response_headers
from httpobs.website.backend import api

app = Flask('http-observatory')


@app.route('/')
@add_response_headers()
def main() -> str:
    return 'Welcome to the HTTP Observatory!'

if __name__ == '__main__':
    app.register_blueprint(api)

    if 'HTTPOBS_DEV' in environ:
        app.run(debug=True)
    else:
        app.run(debug=False)
