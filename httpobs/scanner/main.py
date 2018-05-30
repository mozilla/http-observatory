from random import randrange
from time import sleep
from urllib.parse import parse_qs, urlparse

from httpobs.conf import (BROKER_URL,
                          SCANNER_ALLOW_KICKSTART,
                          SCANNER_ALLOW_KICKSTART_NUM_ABORTED,
                          SCANNER_BROKER_RECONNECTION_SLEEP_TIME,
                          SCANNER_CYCLE_SLEEP_TIME,
                          SCANNER_DATABASE_RECONNECTION_SLEEP_TIME,
                          SCANNER_MAINTENANCE_CYCLE_FREQUENCY,
                          SCANNER_MATERIALIZED_VIEW_REFRESH_FREQUENCY,
                          SCANNER_MAX_CPU_UTILIZATION,
                          SCANNER_MAX_LOAD)
from httpobs.database import (periodic_maintenance,
                              refresh_materialized_views,
                              update_scans_dequeue_scans)
from httpobs.scanner.tasks import scan

import datetime
import psutil
import redis
import subprocess
import sys


def main():
    # Start each scanner at a random point in the range to spread out database maintenance
    dequeue_loop_count = randrange(0, SCANNER_MAINTENANCE_CYCLE_FREQUENCY)
    materialized_view_loop_count = randrange(0, SCANNER_MATERIALIZED_VIEW_REFRESH_FREQUENCY)

    # Parse the BROKER_URL
    broker_url = urlparse(BROKER_URL)

    if broker_url.scheme.lower() not in ('redis', 'redis+socket'):  # Currently the de-queuer only support redis
        print('Sorry, the scanner currently only supports redis.', file=sys.stderr)
        sys.exit(1)

    # Get the current CPU utilization and wait a second to begin the loop for the next reading
    psutil.cpu_percent()
    sleep(1)

    while True:
        try:
            # TODO: Document this madness and magic numbers, make it configurable
            # If max cpu is 90 and current CPU is 50, that gives us a headroom of 8 scans
            headroom = int((SCANNER_MAX_CPU_UTILIZATION - psutil.cpu_percent()) / 5)
            dequeue_quantity = min(headroom, SCANNER_MAX_LOAD)

            if headroom <= 0:
                # If the cycle sleep time is .5, sleep 2 seconds at a minimum, 10 seconds at a maximum
                sleep_time = min(max(abs(headroom), SCANNER_CYCLE_SLEEP_TIME * 4), 10)
                print('[{time}] WARNING: Load too high. Sleeping for {num} second(s).'.format(
                    time=str(datetime.datetime.now()).split('.')[0],
                    num=sleep_time),
                    file=sys.stderr)

                sleep(sleep_time)
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
                print('[{time}] INFO: Performing periodic maintenance.'.format(
                    time=str(datetime.datetime.now()).split('.')[0]),
                    file=sys.stderr)

                dequeue_loop_count = 0
                num = periodic_maintenance()

            if num > 0:
                print('[{time}] INFO: Cleared {num} broken scan(s).'.format(
                    time=str(datetime.datetime.now()).split('.')[0],
                    num=num),
                    file=sys.stderr)

            # Forcibly restart if things are going real bad, sleep for a bit to avoid flagging
            if num > SCANNER_ALLOW_KICKSTART_NUM_ABORTED and SCANNER_ALLOW_KICKSTART:
                sleep(10)
                try:
                    print('[{time}] ERROR: Celery appears to be hung. Attempting to kickstart the scanners.'.format(
                        time=str(datetime.datetime.now()).split('.')[0]),
                        file=sys.stderr)
                    subprocess.call(['pkill', '-u', 'httpobs'])
                except FileNotFoundError:
                    print('[{time}] ERROR: Tried to kickstart, but no pkill found.'.format(
                        time=str(datetime.datetime.now()).split('.')[0]),
                        file=sys.stderr)
                except:
                    print('[{time}] ERROR: Tried to kickstart, but failed for unknown reasons.'.format(
                        time=str(datetime.datetime.now()).split('.')[0]),
                        file=sys.stderr)
        except:
            pass
        finally:
            dequeue_loop_count += 1
            num = 0

        # Every so often we need to refresh the materialized views that the statistics depend on
        try:
            if materialized_view_loop_count % SCANNER_MATERIALIZED_VIEW_REFRESH_FREQUENCY == 0:
                print('[{time}] INFO: Refreshing materialized views.'.format(
                    time=str(datetime.datetime.now()).split('.')[0]),
                    file=sys.stderr)

                materialized_view_loop_count = 0
                refresh_materialized_views()

                print('[{time}] INFO: Materialized views refreshed.'.format(
                    time=str(datetime.datetime.now()).split('.')[0]),
                    file=sys.stderr)
        except:
            pass
        finally:
            materialized_view_loop_count += 1

        # Verify that the broker is still up; if it's down, let's sleep and try again later
        try:
            if broker_url.scheme.lower() == 'redis':
                conn = redis.Connection(host=broker_url.hostname,
                                        port=broker_url.port or 6379,
                                        db=int(broker_url.path[1:] if len(broker_url.path) > 0 else 0),
                                        password=broker_url.password)
            else:
                conn = redis.UnixDomainSocketConnection(path=broker_url.path,
                                                        db=int(parse_qs(broker_url.query).get(
                                                            'virtual_host', ['0'])
                                                            [0]))

            conn.connect()
            conn.can_read()
            conn.disconnect()
            del conn
        except:
            print('[{time}] ERROR: Unable to connect to to redis. Sleeping for {num} seconds.'.format(
                time=str(datetime.datetime.now()).split('.')[0],
                num=SCANNER_BROKER_RECONNECTION_SLEEP_TIME),
                file=sys.stderr
            )
            sleep(SCANNER_BROKER_RECONNECTION_SLEEP_TIME)
            continue

        # Get a list of sites that are pending
        try:
            sites_to_scan = update_scans_dequeue_scans(dequeue_quantity)
        except IOError:
            print('[{time}] ERROR: Unable to retrieve lists of sites to scan. Sleeping for {num} seconds.'.format(
                time=str(datetime.datetime.now()).split('.')[0],
                num=SCANNER_DATABASE_RECONNECTION_SLEEP_TIME),
                file=sys.stderr
            )
            sleep(SCANNER_DATABASE_RECONNECTION_SLEEP_TIME)
            continue

        try:
            if sites_to_scan:
                print('[{time}] INFO: Dequeuing {num} site(s): {sites}.'.format(
                    time=str(datetime.datetime.now()).split('.')[0],
                    num=len(sites_to_scan),
                    sites=', '.join([site[0] for site in sites_to_scan])),
                    file=sys.stderr
                )

                for site in sites_to_scan:
                    scan.delay(*site)

                # Always sleep at least some amount of time so that CPU utilization measurements can track
                sleep(SCANNER_CYCLE_SLEEP_TIME / 2)
            else:  # If the queue was empty, lets sleep a little bit
                sleep(SCANNER_CYCLE_SLEEP_TIME)
        except KeyboardInterrupt:
            print('Exiting scanner backend')
            sys.exit(1)
        except:  # this shouldn't trigger, but we don't want a scan breakage to kill the scanner
            print('[{time}] ERROR: Unknown celery error.'.format(
                time=str(datetime.datetime.now()).split('.')[0]),
                file=sys.stderr)


if __name__ == '__main__':
    main()
