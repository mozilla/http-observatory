from httpobs.database import get_cursor, insert_test_result, update_scan_state
from httpobs.scanner import STATE_STARTED, STATE_FAILED
from httpobs.scanner.retriever import retrieve_all

from celery import Celery
from os import environ
from sys import exit

import httpobs.scanner.analyzer
import sys

# Set the Celery task queue
try:
    celery = Celery('httpobs.scanner.tasks', broker=environ['HTTPOBS_BROKER_URL'])
except KeyError:
    print('Cannot find environmental variable $HTTPOBS_DATABASE_URL. Exiting.')
    exit(1)


# TODO: get a callback to handle Celery errors
@celery.task(ignore_result=True)
def scan(hostname: str, site_id: int, scan_id: int):
    # Once celery kicks off the task, let's update the scan state from PENDING to STARTED
    update_scan_state(scan_id, STATE_STARTED)

    # Attempt to retrieve all the resources
    try:
        reqs = retrieve_all(hostname)
    except:
        # TODO: have more specific error messages
        e = sys.exc_info()[1]  # get the error message

        # If we are unsuccessful, close out the scan in the database
        update_scan_state(scan_id, STATE_FAILED, error=repr(e))

        return

    # Get all the tests
    tests = [f for _, f in httpobs.scanner.analyzer.__dict__.items() if callable(f)]

    for test in tests:
        # TODO: Get overridden expectation
        test_name = test.__name__.replace('_', '-')
        insert_test_result(site_id, scan_id, test_name, test(reqs))
