from os import environ, cpu_count

import os.path
import sys


def __exit_without(envvar: str) -> str:
    value = environ.get(envvar)

    if not value:
        print('{0} not set. Exiting.'.format(envvar), file=sys.stderr)
        sys.exit(1)

    return value

# TODO: make this whole thing a configuration file

DEVELOPMENT_MODE = True if environ.get('HTTPOBS_DEV', False) == 'true' else False

# Set the scanner cooldown speed
COOLDOWN = 15 if DEVELOPMENT_MODE else 1200

API_KEY = environ.get('HTTPOBS_API_KEY')
API_URL = environ.get('HTTPOBS_API_URL',
                      'https://http.observatory.services.mozilla.com/api/v1')

# Broker configuration
BROKER_URL = __exit_without('HTTPOBS_BROKER_URL')

# Database configuration
DATABASE_DB = environ.get('HTTPOBS_DATABASE_DB', 'http_observatory')
DATABASE_HOST = environ.get('HTTPOBS_DATABASE_HOST', 'localhost')
DATABASE_PASSWORD = __exit_without('HTTPOBS_DATABASE_PASS')
DATABASE_PORT = environ.get('HTTPOBS_DATABASE_PORT', 5432)
DATABASE_USER = __exit_without('HTTPOBS_DATABASE_USER')

# Set some database provider specific parameters
__dirname = os.path.abspath(os.path.dirname(__file__))
if DATABASE_HOST.endswith('.rds.amazonaws.com'):
    DATABASE_CA_CERT = os.path.join(__dirname, 'amazon-rds.pem')
    DATABASE_SSL_MODE = 'verify-full'
else:
    DATABASE_CA_CERT = None
    DATABASE_SSL_MODE = 'prefer'

# Retriever parameters
RETRIEVER_CONNECT_TIMEOUT = 6.05
RETRIEVER_READ_TIMEOUT = 30
RETRIEVER_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0'

# The scanner should back off once the system load average reaches a specific load factor
SCANNER_BROKER_RECONNECTION_SLEEP_TIME = 15
SCANNER_CYCLE_SLEEP_TIME = .5  # half a second
SCANNER_DATABASE_RECONNECTION_SLEEP_TIME = 5
SCANNER_MAX_LOAD_RATIO = 3
SCANNER_MAX_LOAD = cpu_count() * SCANNER_MAX_LOAD_RATIO
SCANNER_MOZILLA_DOMAINS = ('mozilla', 'allizom', 'browserid', 'firefox', 'persona', 'taskcluster', 'webmaker')

WEBSITE_PORT = environ.get('HTTPOBS_WEBSITE_PORT', 57001)
