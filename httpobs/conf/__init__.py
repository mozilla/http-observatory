from os import environ, cpu_count

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

API_KEY = environ.get('HTTPOBS_API_KEY')
API_URL = environ.get('HTTPOBS_API_URL',
                      'https://http.observatory.services.mozilla.com/api/v1')
BROKER_URL = __exit_without('HTTPOBS_BROKER_URL')
DATABASE_DB = environ.get('HTTPOBS_DATABASE_DB', 'http_observatory')
DATABASE_HOST = environ.get('HTTPOBS_DATABASE_HOST', 'localhost')
DATABASE_PASSWORD = __exit_without('HTTPOBS_DATABASE_PASS')
DATABASE_PORT = environ.get('HTTPOBS_DATABASE_PORT', 5432)
DATABASE_USER = __exit_without('HTTPOBS_DATABASE_USER')
WEBSITE_PORT = environ.get('HTTPOBS_WEBSITE_PORT', 57001)


# Set some database provider specific parameters
__dirname = os.path.abspath(os.path.dirname(__file__))
if DATABASE_HOST.endswith('.rds.amazonaws.com'):
    DATABASE_CA_CERT = os.path.join(__dirname, 'amazon-rds.pem')
    DATABASE_SSL_MODE = 'verify-full'
else:
    DATABASE_CA_CERT = None
    DATABASE_SSL_MODE = 'prefer'

# The scanner should back off once the system load average reaches a specific load factor
SCANNER_MAX_LOAD_RATIO = 3
SCANNER_MAX_LOAD = cpu_count() * SCANNER_MAX_LOAD_RATIO
SCANNER_BROKER_RECONNECTION_SLEEP_TIME = 15
SCANNER_CYCLE_SLEEP_TIME = .5  # half a second
SCANNER_DATABASE_RECONNECTION_SLEEP_TIME = 5
