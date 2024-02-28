from flask import Flask

from httpobs.conf import API_PORT, API_PROPAGATE_EXCEPTIONS, DEVELOPMENT_MODE


def create_app():
    # Register the application with flask
    app = Flask('http-observatory')
    app.config['PROPAGATE_EXCEPTIONS'] = API_PROPAGATE_EXCEPTIONS

    from httpobs.website.api import api
    from httpobs.website.api_v2 import api_v2
    from httpobs.website.monitoring import monitoring_api

    app.register_blueprint(api)
    app.register_blueprint(api_v2, url_prefix="/api/v2")
    app.register_blueprint(monitoring_api)

    return app


def run():
    app = create_app()
    app.run(debug=DEVELOPMENT_MODE, port=API_PORT)


if __name__ == '__main__':
    run()

# make backwards compatible with uwsgi setup
# TODO: move into wsgi.py
app = create_app()
