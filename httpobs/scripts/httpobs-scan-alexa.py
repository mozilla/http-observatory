#!/usr/bin/env python3

from __future__ import print_function
from celery.task.control import inspect

import requests
import sys
import time


# TODO: Update to HTTPS once real site is live
HTTP_OBS_URL = 'http://http-observatory.services.mozilla.com:5000/api/v1'
ALEXA_FILE = sys.argv[1]

# Get the queue inspector
queue = inspect(timeout=15)

if __name__ == '__main__':
    start_time = time.time()

    with open(ALEXA_FILE, 'r') as alexafp:
        hosts = [host.strip().split(',')[1] if ',' in host else host.strip() for host in alexafp]

    while True:
        # Get the queue availability
        available = 512 - sum([len(queue) for queue in inspect().active()])
        print('Queue availability: {queue_avail}'.format(queue_avail=available))

        while available > 0:
            # Exit if there's nothing left
            if len(hosts) == 0:
                print('Elapsed time: {elapsed_time}'.format(elapsed_time=(time.time() - start_time)))
                exit(0)

            # Start up a new scan
            requests.post(HTTP_OBS_URL + '/analyze?host={host}'.format(host=hosts.pop()),  # start with the end sites
                          headers={'Content-Type': 'application/json'})
            available -= 1

        time.sleep(20)
