from celery import Celery

from httpobs.database import celeryconfig, update_scans_abort_broken_scans

import sys

# Create the database task queue
db = Celery()
db.config_from_object(celeryconfig)


@db.task()
def abort_broken_scans():
    try:
        # Clear out any broken scans older than 1800 seconds
        num = update_scans_abort_broken_scans(1800)

        if num > 0:
            print('INFO: Cleared {num} broken scan(s).'.format(file=sys.sterr, num=num))
    except IOError:
        print('WARNING: database down, aborting scan, err, aborter', file=sys.stderr)
    except:
        print('WARNING: scan aborter caught unknown exception', file=sys.stderr)
