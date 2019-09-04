from os import environ, cpu_count

import configparser
import os.path
import sys


# Read in the default config file if /etc/httpobs.conf doesn't already exist
__dirname = os.path.abspath(os.path.dirname(__file__))
_config_parser = configparser.ConfigParser()
_config_parser.read_file(open(os.path.join(__dirname, 'httpobs.conf')))                  # default values
_config_parser.read(['/etc/httpobs.conf', os.path.expanduser('~/.httpobs.conf')])        # overridden values


# Return None if it's not in the config parser
def __conf(section, param, type=None, default=None):
    try:
        if type == str or type is None:
            return _config_parser.get(section, param)
        elif type == int:
            return _config_parser.getint(section, param)
        elif type == bool:
            return _config_parser.getboolean(section, param)
        elif type == float:
            return _config_parser.getfloat(section, param)
        else:
            return None
    except (KeyError, configparser.NoSectionError):
        return None
    except:
        if default:
            return default
        else:
            print('Error with key {0} in section {1}'.format(param, section))
            sys.exit(1)


DEVELOPMENT_MODE = True if environ.get('HTTPOBS_DEV') == 'yes' else False or __conf('global', 'development', bool)

# API configuration
API_ALLOW_VERBOSE_STATS_FROM_PUBLIC = (environ.get('HTTPOBS_ALLOW_VERBOSE_STATS_FROM_PUBLIC') == 'yes' or
                                       __conf('api', 'allow_verbose_stats_from_public', bool, True))
API_CACHED_RESULT_TIME = int(environ.get('HTTPOBS_API_CACHED_RESULT_TIME') or __conf('api', 'cached_result_time'))
API_COOLDOWN = int(environ.get('HTTPOBS_API_COOLDOWN') or __conf('api', 'cooldown', int))
API_PORT = int(environ.get('HTTPOBS_API_PORT') or __conf('api', 'port', int))
API_PROPAGATE_EXCEPTIONS = (True if environ.get('HTTPOBS_PROPAGATE_EXCEPTIONS') == 'yes' else False or
                            __conf('api', 'propagate_exceptions', bool))
API_URL = environ.get('HTTPOBS_API_URL') or __conf('api', 'url')

# Broker configuration
BROKER_URL = (environ.get('HTTPOBS_BROKER_URL') or __conf('scanner', 'broker'))

# Database configuration
DATABASE_DB = environ.get('HTTPOBS_DATABASE_DB') or __conf('database', 'database')
DATABASE_HOST = environ.get('HTTPOBS_DATABASE_HOST') or __conf('database', 'host')
DATABASE_PASSWORD = environ.get('HTTPOBS_DATABASE_PASS') or __conf('database', 'pass')
DATABASE_PORT = int(environ.get('HTTPOBS_DATABASE_PORT') or __conf('database', 'port', int))
DATABASE_USER = environ.get('HTTPOBS_DATABASE_USER') or __conf('database', 'user')

# Set some database provider specific parameters
if DATABASE_HOST.endswith('.rds.amazonaws.com'):
    DATABASE_CA_CERT = os.path.join(__dirname, 'amazon-rds.pem')
    DATABASE_SSL_MODE = 'verify-full'
else:
    DATABASE_CA_CERT = None
    DATABASE_SSL_MODE = 'prefer'

# Retriever parameters
RETRIEVER_CONNECT_TIMEOUT = float(environ.get('HTTPOBS_RETRIEVER_CONNECT_TIMEOUT') or
                                  __conf('retriever', 'connect_timeout'))
RETRIEVER_READ_TIMEOUT = float(environ.get('HTTPOBS_RETRIEVER_READ_TIMEOUT') or
                               __conf('retriever', 'read_timeout'))
RETRIEVER_USER_AGENT = environ.get('HTTPOBS_RETRIEVER_USER_AGENT') or __conf('retriever', 'user_agent')
RETRIEVER_CORS_ORIGIN = environ.get('HTTPOBS_RETRIEVER_CORS_ORIGIN') or __conf('retriever', 'cors_origin')

# Scanner configuration
SCANNER_ABORT_SCAN_TIME = int(environ.get('HTTPOBS_SCANNER_ABORT_SCAN_TIME') or
                              __conf('scanner', 'abort_scan_time'))
SCANNER_ALLOW_KICKSTART = (environ.get('HTTPOBS_SCANNER_ALLOW_KICKSTART') == 'yes' or
                           __conf('scanner', 'allow_kickstart', bool))
SCANNER_ALLOW_KICKSTART_NUM_ABORTED = int(environ.get('HTTPOBS_SCANNER_ALLOW_KICKSTART_NUM_ABORTED') or
                                          __conf('scanner', 'allow_kickstart_num_aborted'))
SCANNER_ALLOW_LOCALHOST = (environ.get('HTTPOBS_SCANNER_ALLOW_LOCALHOST') == 'yes' or
                           __conf('scanner', 'allow_localhost', bool))
SCANNER_BROKER_RECONNECTION_SLEEP_TIME = float(environ.get('HTTPOBS_SCANNER_BROKER_RECONNECTION_SLEEP_TIME') or
                                               __conf('scanner', 'broker_reconnection_sleep_time'))
SCANNER_CYCLE_SLEEP_TIME = float(environ.get('HTTPOBS_SCANNER_CYCLE_SLEEP_TIME') or
                                 __conf('scanner', 'cycle_sleep_time'))
SCANNER_DATABASE_RECONNECTION_SLEEP_TIME = float(environ.get('HTTPOBS_SCANNER_DATABASE_RECONNECTION_SLEEP_TIME') or
                                                 __conf('scanner', 'database_reconnection_sleep_time'))
SCANNER_MAINTENANCE_CYCLE_FREQUENCY = int(environ.get('HTTPOBS_MAINTENANCE_CYCLE_FREQUENCY') or
                                          __conf('scanner', 'maintenance_cycle_frequency'))
SCANNER_MATERIALIZED_VIEW_REFRESH_FREQUENCY = int(environ.get('HTTPOBS_SCANNER_MATERIALIZED_VIEW_REFRESH_FREQUENCY') or
                                                  __conf('scanner', 'materialized_view_refresh_frequency'))
SCANNER_MAX_CPU_UTILIZATION = int(environ.get('HTTPOBS_SCANNER_MAX_CPU_UTILIZATION') or
                                  __conf('scanner', 'max_cpu_utilization'))
SCANNER_MAX_LOAD_RATIO = int(environ.get('HTTPOBS_SCANNER_MAX_LOAD_RATIO_PER_CPU') or
                             __conf('scanner', 'max_load_ratio_per_cpu'))
SCANNER_MAX_LOAD = cpu_count() * SCANNER_MAX_LOAD_RATIO
SCANNER_MOZILLA_DOMAINS = [domain.strip() for domain in (environ.get('HTTPOBS_SCANNER_MOZILLA_DOMAINS') or
                                                         __conf('scanner', 'mozilla_domains')).split(',')]
SCANNER_PINNED_DOMAINS = [domain.strip() for domain in (environ.get('HTTPOBS_SCANNER_PINNED_DOMAINS') or
                                                        __conf('scanner', 'pinned_domains')).split(',')]
