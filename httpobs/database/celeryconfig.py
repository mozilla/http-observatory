from os import environ

# Set the Celery task queue
try:
    BROKER_URL = environ['HTTPOBS_BROKER_URL']

    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_IGNORE_RESULTS = True
    CELERY_REDIRECT_STDOUTS_LEVEL = 'WARNING'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TASK_SERIALIZER = 'json'

    CELERYD_TASK_SOFT_TIME_LIMIT = 300
    CELERYD_TASK_TIME_LIMIT = 600

    CELERYBEAT_SCHEDULE = {
        'abort-broken-scans': {
            'task': 'httpobs.database.tasks.abort_broken_scans',
            'schedule': 15,
        }
    }

except KeyError:
    print('Cannot find environmental variable $HTTPOBS_BROKER_URL. Exiting.')
    exit(1)
