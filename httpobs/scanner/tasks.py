from celery import Celery
from celery.exceptions import (
    SoftTimeLimitExceeded,
    TimeLimitExceeded,
    WorkerLostError,
    WorkerShutdown,
    WorkerTerminate)

from httpobs.conf import DEVELOPMENT_MODE
from httpobs.database import (insert_test_results,
                              select_site_headers,
                              update_scan_state)
from httpobs.scanner import celeryconfig, STATE_ABORTED, STATE_FAILED, STATE_RUNNING
from httpobs.scanner.analyzer import tests
from httpobs.scanner.retriever import retrieve_all
from httpobs.scanner.utils import sanitize_headers

import sys


# Create the scanner task queue
scanner = Celery()
scanner.config_from_object(celeryconfig)


@scanner.task()
def scan(hostname: str, site_id: int, scan_id: int):
    try:
        # Once celery kicks off the task, let's update the scan state from PENDING to RUNNING
        update_scan_state(scan_id, STATE_RUNNING)

        # Get the site's cookies and headers
        headers = select_site_headers(hostname)

        # Attempt to retrieve all the resources
        reqs = retrieve_all(hostname, cookies=headers['cookies'], headers=headers['headers'])

        # If we can't connect at all, let's abort the test
        if reqs['responses']['auto'] is None:
            update_scan_state(scan_id, STATE_FAILED, error='site down')

            return

        # Execute each test, replacing the underscores in the function name with dashes in the test name
        # TODO: Get overridden expectations
        insert_test_results(site_id,
                            scan_id,
                            [test(reqs) for test in tests],
                            sanitize_headers(reqs['responses']['auto'].headers),
                            reqs['responses']['auto'].status_code)

    # catch the celery timeout, which will almost certainly occur in retrieve_all()
    except SoftTimeLimitExceeded:
        update_scan_state(scan_id, STATE_ABORTED, error='site unresponsive')
    except (TimeLimitExceeded, WorkerLostError, WorkerShutdown, WorkerTerminate):
        raise
    # the database is down, oh no!
    except IOError:
        print('database down, aborting scan on {hostname}'.format(hostname=hostname), file=sys.stderr)
    except:
        # TODO: have more specific error messages
        e = sys.exc_info()[1]  # get the error message

        # If we are unsuccessful, close out the scan in the database
        update_scan_state(scan_id, STATE_FAILED, error=repr(e))

        # Print the exception to stderr if we're in dev
        if DEVELOPMENT_MODE:
            import traceback
            print('Error detected in scan for : ' + hostname)
            traceback.print_exc(file=sys.stderr)
