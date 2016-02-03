from flask import Flask
from website.backend import api

app = Flask(__name__)


@app.route('/')
def main() -> str:
    return 'Welcome to the HTTP Observatory backend service!'

if __name__ == '__main__':
    app.register_blueprint(api)
    app.run(debug=True)
