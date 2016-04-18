from os import getloadavg
from time import sleep
from urllib.parse import urlparse

from httpobs.conf import (BROKER_URL,
                          SCANNER_BROKER_RECONNECTION_SLEEP_TIME,
                          SCANNER_CYCLE_SLEEP_TIME,
                          SCANNER_DATABASE_RECONNECTION_SLEEP_TIME,
                          SCANNER_MAINTENANCE_CYCLE_FREQUENCY,
                          SCANNER_MAX_LOAD)
from httpobs.database import (periodic_maintenance,
                              update_scans_dequeue_scans)
from httpobs.scanner.tasks import scan

import redis
import sys


def main():
    dequeue_loop_count = 0

    # Parse the BROKER_URL
    broker_url = urlparse(BROKER_URL)

    if broker_url.scheme.lower() != 'redis':  # Currently the de-queuer only support redis
        print('Sorry, the scanner currently only supports redis.', file=sys.stderr)
        sys.exit(1)

    while True:
        try:
            # If the load is higher than SCANNER_MAX_LOAD, let's sleep a bit and see if things have calmed down a bit
            # If the load is 30 and the max load is 20, sleep 11 seconds. If the load is low, lets only sleep a little
            # bit.
            headroom = SCANNER_MAX_LOAD - int(getloadavg()[0])
            if headroom <= 0:
                sleep(abs(headroom))
                continue
        except:
            # I've noticed that on laptops that Docker has a tendency to kill the scanner when the laptop sleeps; this
            # is designed to catch that exception
            sleep(1)
            continue

        # Every so many scans, let's opportunistically clear out any PENDING scans that are older than 1800 seconds
        # Also update the grade_distribution table
        # If it fails, we don't care. Of course, nobody reads the comments, so I should say that *I* don't care.
        try:
            if dequeue_loop_count % SCANNER_MAINTENANCE_CYCLE_FREQUENCY == 0:
                dequeue_loop_count = 0
                num = periodic_maintenance()

            if num > 0:
                print('INFO: Cleared {num} broken scan(s).'.format(file=sys.stderr, num=num))
                num = 0
        except:
            pass
        finally:
            dequeue_loop_count += 1

        # Verify that the broker is still up; if it's down, let's sleep and try again later
        try:
            conn = redis.Connection(host=broker_url.hostname,
                                    port=broker_url.port or 6379,
                                    db=int(broker_url.path[1:]),
                                    password=broker_url.password)
            conn.connect()
            conn.can_read()
            conn.disconnect()
            del conn
        except:
            sleep(SCANNER_BROKER_RECONNECTION_SLEEP_TIME)
            continue

        # Get a list of sites that are pending
        try:
            sites_to_scan = update_scans_dequeue_scans(headroom)
        except IOError:
            sleep(SCANNER_DATABASE_RECONNECTION_SLEEP_TIME)
            continue

        try:
            if sites_to_scan:
                for site in sites_to_scan:
                    scan.delay(*site)
            else:  # If the queue was empty, lets sleep a little bit
                sleep(SCANNER_CYCLE_SLEEP_TIME)
        except:  # this shouldn't trigger, but we don't want a scan breakage to kill the scanner
            pass

if __name__ == '__main__':
    main()
