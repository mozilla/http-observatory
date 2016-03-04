from celery import Celery

from httpobs.database import celeryconfig, update_scans_abort_broken_scans


# Create the database task queue
db = Celery()
db.config_from_object(celeryconfig)


@db.task()
def abort_broken_scans():
    # Clear out any broken scans older than 1800 seconds
    num = update_scans_abort_broken_scans(1800)

    if num > 0:
        print('Cleared {num} broken scan(s).'.format(num=num))
