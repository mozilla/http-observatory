from os import environ


# Set the Celery task queue
try:
    BROKER_URL = environ['HTTPOBS_BROKER_URL']

    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_DEFAULT_QUEUE = 'scanner'
    CELERY_REDIRECT_STDOUTS_LEVEL = 'WARNING'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_TASK_SERIALIZER = 'json'
except KeyError:
    print('Cannot find environmental variable $HTTPOBS_BROKER_URL. Exiting.')
    exit(1)
