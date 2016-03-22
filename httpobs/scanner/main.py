from os import getloadavg
from time import sleep

from httpobs.conf import (SCANNER_MAX_LOAD,
                          SCANNER_BROKER_RECONNECTION_SLEEP_TIME,
                          SCANNER_CYCLE_SLEEP_TIME,
                          SCANNER_DATABASE_RECONNECTION_SLEEP_TIME,
                          BROKER_URL)
from httpobs.database import (update_scans_abort_broken_scans,
                              update_scans_dequeue_scans)
from httpobs.scanner.tasks import scan

import kombu
import sys


def main():
    dequeue_loop_count = 0

    while True:
        # If the load is higher than SCANNER_MAX_LOAD, let's sleep a bit and see if things have calmed down a bit
        # If the load is 30 and the max load is 20, sleep 11 seconds. If the load is low, lets only sleep a little bit.
        headroom = SCANNER_MAX_LOAD - int(getloadavg()[0])
        if headroom <= 0:
            sleep(abs(headroom))
            continue

        # Every 900 or so scans, let's opportunistically clear out any PENDING scans that are older than 1800 seconds
        # If it fails, we don't care. Of course, nobody reads the comments, so I should say that *I* don't care.
        try:
            if dequeue_loop_count % 900 == 0:
                num = update_scans_abort_broken_scans(1800)
                dequeue_loop_count = 0

            if num > 0:
                print('INFO: Cleared {num} broken scan(s).'.format(file=sys.stderr, num=num))
        except:
            pass
        finally:
            dequeue_loop_count += 1

        # Verify that the broker is still up; if it's down, let's sleep and try again later
        try:
            conn = kombu.Connection(BROKER_URL)
            conn.connect()
            conn.release()
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
