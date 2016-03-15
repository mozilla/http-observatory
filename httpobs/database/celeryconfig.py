from httpobs.conf import BROKER_URL


# Set the Celery task queue
BROKER_URL = BROKER_URL

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
        'schedule': 1800,
    }
}
