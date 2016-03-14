from os import environ

import os.path
import sys


def __exit_without(envvar: str) -> str:
    value = environ.get(envvar)

    if not value:
        print('{0} not set. Exiting.'.format(envvar), file=sys.stderr)
        sys.exit(1)

    return value


DEVELOPMENT_MODE = True if environ.get('HTTPOBS_DEV', False) == 'true' else False

# Set the scanner cooldown speed
COOLDOWN = 15 if DEVELOPMENT_MODE else 300

API_KEY = __exit_without('HTTPOBS_API_KEY')
BROKER_URL = __exit_without('HTTPOBS_BROKER_URL')
DATABASE_DB = environ.get('HTTPOBS_DATABASE_DB', 'http_observatory')
DATABASE_HOST = environ.get('HTTPOBS_DATABASE_HOST', 'localhost')
DATABASE_PASSWORD = environ.get('HTTPOBS_DATABASE_PASS')
DATABASE_PORT = environ.get('HTTPOBS_DATABASE_PORT', 5432)
ENVIRONMENT = __exit_without('HTTPOBS_ENVIRONMENT')

if ENVIRONMENT == 'frontend':
    DATABASE_USER = 'httpobsapi'
    PORT = 57001
    BACKEND_API_URL = environ.get('HTTPOBS_BACKEND', 'http://localhost:' + str(PORT + 1))
elif ENVIRONMENT == 'backend':
    DATABASE_USER = 'httpobsscanner'
    PORT = 57002
    BACKEND_API_URL = 'http://localhost:' + str(PORT)
else:
    print('Invalid environment. Exiting.')
    sys.exit(1)

# Set some database provider specific parameters
__dirname = os.path.abspath(os.path.dirname(__file__))
if DATABASE_HOST.endswith('.rds.amazonaws.com'):
    DATABASE_CA_CERT = os.path.join(__dirname, 'amazon-rds.pem')
    DATABASE_SSL_MODE = 'verify-full'
else:
    DATABASE_CA_CERT = None
    DATABASE_SSL_MODE = 'prefer'
