from httpobs.conf import BROKER_URL as broker_url

# Set the Celery task queue
broker_url = broker_url

accept_content = ['json']
task_ignore_resultS = True
worker_redirect_stdouts_level = 'WARNING'
result_serializer = 'json'
task_serializer = 'json'

task_soft_time_limit = 751
task_time_limit = 1129
