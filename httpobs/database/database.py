from contextlib import contextmanager
from json import dumps
from types import SimpleNamespace
from os import getpid

from httpobs.conf import (API_CACHED_RESULT_TIME,
                          DATABASE_CA_CERT,
                          DATABASE_DB,
                          DATABASE_HOST,
                          DATABASE_PASSWORD,
                          DATABASE_PORT,
                          DATABASE_SSL_MODE,
                          DATABASE_USER,
                          SCANNER_ABORT_SCAN_TIME)
from httpobs.scanner import (ALGORITHM_VERSION,
                             STATE_ABORTED,
                             STATE_FAILED,
                             STATE_FINISHED,
                             STATE_PENDING,
                             STATE_STARTING)
from httpobs.scanner.analyzer import NUM_TESTS
from httpobs.scanner.grader import get_grade_and_likelihood_for_score, MINIMUM_SCORE_FOR_EXTRA_CREDIT

import psycopg2
import psycopg2.extras
import psycopg2.pool
import sys


class SimpleDatabaseConnection:
    def __init__(self):
        self._initialized_pid = getpid()
        self._connected = True
        self._connect()

    def _connect(self):
        try:
            self._conn = psycopg2.connect(database=DATABASE_DB,
                                          host=DATABASE_HOST,
                                          password=DATABASE_PASSWORD,
                                          port=DATABASE_PORT,
                                          sslmode=DATABASE_SSL_MODE,
                                          sslrootcert=DATABASE_CA_CERT,
                                          user=DATABASE_USER)

            if not self._connected:
                print('INFO: Connected to PostgreSQL', file=sys.stderr)
            self._connected = True

        except Exception as e:
            print(e, file=sys.stderr)
            self._conn = SimpleNamespace(closed=1)

            if self._connected:
                print('WARNING: Disconnected from PostgreSQL', file=sys.stderr)
            self._connected = False

    @property
    def conn(self):
        # TLS connections cannot be shared across workers; you'll get a decryption failed or bad mac error
        # What we will do is detect if we're running in a different PID and reconnect if so
        # TODO: use celery's worker init stuff instead?
        if self._initialized_pid != getpid():
            self.__init__()

        # If the connection is closed, try to reconnect and raise an IOError if it's unsuccessful
        if self._conn.closed:
            self._connect()

            if self._conn.closed:
                raise IOError

        return self._conn


# Create an initial database connection on startup
db = SimpleDatabaseConnection()


@contextmanager
def get_cursor():
    try:
        yield db.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            db.conn.commit()
        except:
            db.conn.rollback()
    except:
        raise IOError


# Print out a warning on startup if we can't connect to PostgreSQL
try:
    with get_cursor() as _:  # noqa
        pass
except IOError:
    print('WARNING: Unable to connect to PostgreSQL.', file=sys.stderr)


def insert_scan(site_id: int, hidden: bool = False) -> dict:
    with get_cursor() as cur:
        cur.execute("""INSERT INTO scans (site_id, state, start_time, algorithm_version, tests_quantity, hidden)
                         VALUES (%s, %s, NOW(), %s, %s, %s)
                         RETURNING *""",
                    (site_id, STATE_PENDING, ALGORITHM_VERSION, NUM_TESTS, hidden))

        return dict(cur.fetchone())


def insert_scan_grade(scan_id, scan_grade, scan_score) -> dict:
    with get_cursor() as cur:
        cur.execute("""UPDATE scans
                         SET (grade, score) =
                         (%s, %s)
                         WHERE id = %s
                         RETURNING *""",
                    (scan_grade, scan_score, scan_id))

        return dict(cur.fetchone())


# TODO: Separate out some of this logic so it doesn't need to be duplicated in local.scan()
def insert_test_results(site_id: int,
                        scan_id: int,
                        tests: list,
                        response_headers: dict,
                        status_code: int = None) -> dict:
    with get_cursor() as cur:
        tests_failed = tests_passed = 0
        score_with_extra_credit = uncurved_score = 100

        for test in tests:
            name = test.pop('name')
            expectation = test.pop('expectation')
            passed = test.pop('pass')
            result = test.pop('result')
            score_modifier = test.pop('score_modifier')

            # Keep track of how many tests passed or failed
            if passed:
                tests_passed += 1
            else:
                tests_failed += 1

            # And keep track of the score
            score_with_extra_credit += score_modifier
            if score_modifier < 0:
                uncurved_score += score_modifier

            # Insert test result to the database
            cur.execute("""INSERT INTO tests (site_id, scan_id, name, expectation, result, pass, output, score_modifier)
                             VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                        (site_id, scan_id, name, expectation, result, passed, dumps(test), score_modifier))

        # Only record the full score if the uncurved score already receives an A
        score = score_with_extra_credit if uncurved_score >= MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved_score

        # Now we need to update the scans table
        score, grade, likelihood_indicator = get_grade_and_likelihood_for_score(score)

        # Update the scans table
        cur.execute("""UPDATE scans
                         SET (end_time, tests_failed, tests_passed, grade, score, likelihood_indicator,
                         state, response_headers, status_code) =
                         (NOW(), %s, %s, %s, %s, %s, %s, %s, %s)
                         WHERE id = %s
                         RETURNING *""",
                    (tests_failed, tests_passed, grade, score, likelihood_indicator, STATE_FINISHED,
                        dumps(response_headers), status_code, scan_id))

        row = dict(cur.fetchone())

    return row


def periodic_maintenance() -> int:
    """
    Update all scans that are stuck. The hard time limit for celery is 1129, so if something isn't aborted, finished,
    or failed, we should just mark it as aborted.
    :return: the number of scans that were closed out
    """
    with get_cursor() as cur:
        # Mark all scans that have been sitting unfinished for at least SCANNER_ABORT_SCAN_TIME as ABORTED
        cur.execute("""UPDATE scans
                         SET (state, end_time) = (%s, NOW())
                         WHERE state != %s
                           AND state != %s
                           AND state != %s
                           AND start_time < NOW() - INTERVAL '%s seconds';""",
                    (STATE_ABORTED, STATE_ABORTED, STATE_FAILED, STATE_FINISHED, SCANNER_ABORT_SCAN_TIME))

    return cur.rowcount


def refresh_materialized_views() -> None:
    """
    Refresh every view in the database as used for grade statistics
    :return: None
    """
    with get_cursor() as cur:
        # Update the various materialized views
        cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY latest_scans;")
        cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY earliest_scans;")
        cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY grade_distribution;")
        cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY grade_distribution_all_scans;")
        cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY scan_score_difference_distribution;")
        cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY scan_score_difference_distribution_summation;")

    return None


def select_star_from(table: str) -> dict:
    # Select all the rows in a given table. Note that this is specifically not parameterized.
    with get_cursor() as cur:
        cur.execute('SELECT * FROM {table}'.format(table=table))

        return dict(cur.fetchall())


def select_scan_host_history(site_id: int) -> list:
    # Get all of the site's historic scans
    with get_cursor() as cur:
        cur.execute("""SELECT id, grade, score, end_time FROM scans
                         WHERE site_id = %s
                         AND state = %s
                         ORDER BY end_time ASC;""",
                    (site_id, STATE_FINISHED))

    if cur.rowcount > 0:
        return([
            {
                'scan_id': row['id'],
                'grade': row['grade'],
                'score': row['score'],
                'end_time': row['end_time'],
                'end_time_unix_timestamp': int(row['end_time'].timestamp())
            } for row in cur.fetchall()])
    else:
        return []


def select_scan_scanner_statistics(verbose: bool = False) -> dict:
    # Get all the scanner statistics while minimizing the number of cursors needed
    with get_cursor() as cur:
        # Get the grade distribution across all scans (periodically refreshed)
        cur.execute('SELECT * FROM grade_distribution;')
        grade_distribution = dict(cur.fetchall())

        # Get the grade distribution across all scans (periodically refreshed)
        cur.execute('SELECT * FROM grade_distribution_all_scans;')
        grade_distribution_all_scans = dict(cur.fetchall())

        # And the summation of grade differences
        cur.execute('SELECT * FROM scan_score_difference_distribution_summation;')
        scan_score_difference_distribution_summation = dict(cur.fetchall())

        # And the total number of scans
        cur.execute("""SELECT id, start_time FROM scans ORDER BY id DESC LIMIT 1;""")
        most_recent_scan = list(cur.fetchall())

        # Stats we only need if verbose is true, as these take a while to collect
        if verbose:
            # Get the scanner stats
            cur.execute('SELECT state, COUNT(*) as quantity FROM scans GROUP BY state;')
            states = dict(cur.fetchall())

            # Get the recent scan count
            cur.execute("""SELECT DATE_TRUNC('hour', end_time) AS hour, COUNT(*) as num_scans
                             FROM scans
                             WHERE (end_time < DATE_TRUNC('hour', NOW()))
                               AND (end_time >= DATE_TRUNC('hour', NOW()) - INTERVAL '24 hours')
                             GROUP BY hour
                             ORDER BY hour DESC;""",
                        (STATE_FINISHED,))
            recent_scans = dict(cur.fetchall()).items()
        else:
            recent_scans = {}
            states = {}

    return {
        'grade_distribution': grade_distribution,
        'grade_distribution_all_scans': grade_distribution_all_scans,
        'most_recent_scan_datetime': most_recent_scan[0][1],
        'recent_scans': recent_scans,
        'scan_count': most_recent_scan[0][0],
        'scan_score_difference_distribution_summation': scan_score_difference_distribution_summation,
        'states': states,
    }


def select_scan_recent_finished_scans(num_scans=10, min_score=0, max_score=100) -> dict:
    # Used for /api/v1/getRecentScans
    # Fix from: https://gist.github.com/april/61efa9ff197828bf5ab13e5a00be9138
    with get_cursor() as cur:
        cur.execute("""SELECT sites.domain, s2.grade
                         FROM
                           (SELECT DISTINCT ON (s1.site_id) s1.site_id, s1.grade, s1.end_time
                              FROM
                                (SELECT site_id, grade, end_time
                                  FROM scans
                                    WHERE state = %s
                                    AND NOT hidden
                                    AND score >= %s
                                    AND score <= %s
                                    ORDER BY end_time
                                    DESC LIMIT %s) s1
                                  ORDER BY s1.site_id, s1.end_time DESC) s2
                                  INNER JOIN sites ON (sites.id = s2.site_id)
                                ORDER BY s2.end_time DESC LIMIT %s;""",
                    (STATE_FINISHED, min_score, max_score, num_scans * 2, num_scans))

        return dict(cur.fetchall())


def select_scan_recent_scan(site_id: int, recent_in_seconds=API_CACHED_RESULT_TIME) -> dict:
    with get_cursor() as cur:
        cur.execute("""SELECT * FROM scans
                         WHERE site_id = %s
                         AND start_time >= NOW() - INTERVAL '%s seconds'
                         ORDER BY start_time DESC
                         LIMIT 1""",
                    (site_id, recent_in_seconds))

        if cur.rowcount > 0:
            return dict(cur.fetchone())

    return {}


def select_site_headers(hostname: str) -> dict:
    # Return the site's headers
    with get_cursor() as cur:
        cur.execute("""SELECT public_headers, private_headers, cookies FROM sites
                         WHERE domain = %s
                         ORDER BY creation_time DESC
                         LIMIT 1""",
                    (hostname,))

        # If it has headers, merge the public and private headers together
        if cur.rowcount > 0:
            row = cur.fetchone()

            headers = {} if row.get('public_headers') is None else row.get('public_headers')
            private_headers = {} if row.get('private_headers') is None else row.get('private_headers')
            headers.update(private_headers)

            return {
                'cookies': {} if row.get('cookies') is None else row.get('cookies'),
                'headers': headers
            }
        else:
            return {}


def select_site_id(hostname: str) -> int:
    # See if the site exists already
    with get_cursor() as cur:
        cur.execute("""SELECT id FROM sites
                         WHERE domain = %s
                         ORDER BY creation_time DESC
                         LIMIT 1""",
                    (hostname,))

        if cur.rowcount > 0:
            return cur.fetchone()['id']

    # If not, let's create the site
    with get_cursor() as cur:
        cur.execute("""INSERT INTO sites (domain, creation_time)
                         VALUES (%s, NOW())
                         RETURNING id""", (hostname,))

        return cur.fetchone()['id']


def select_test_results(scan_id: int) -> dict:
    tests = {}

    with get_cursor() as cur:
        cur.execute("SELECT * FROM tests WHERE scan_id = %s", (scan_id,))

        # Grab every test and stuff it into the tests dictionary
        if cur.rowcount > 1:
            for test in cur:
                tests[test['name']] = dict(test)

    return tests


def update_scan_state(scan_id, state: str, error=None) -> dict:
    if error:
        with get_cursor() as cur:
            cur.execute("""UPDATE scans
                             SET (state, end_time, error) = (%s, NOW(), %s)
                             WHERE id = %s
                             RETURNING *""",
                        (state, error, scan_id))

            row = dict(cur.fetchone())

    else:
        with get_cursor() as cur:
            cur.execute("""UPDATE scans
                             SET state = %s
                             WHERE id = %s
                             RETURNING *""",
                        (state, scan_id))

            row = dict(cur.fetchone())

    return row


def update_scans_dequeue_scans(num_to_dequeue: int = 0) -> dict:
    with get_cursor() as cur:
        cur.execute("""UPDATE scans
                         SET state = %s
                         FROM (
                           SELECT sites.domain, scans.site_id, scans.id AS scan_id, scans.state
                             FROM scans
                             INNER JOIN sites ON scans.site_id = sites.id
                             WHERE state = %s
                             LIMIT %s
                             FOR UPDATE) sub
                         WHERE scans.id = sub.scan_id
                         RETURNING sub.domain, sub.site_id, sub.scan_id""",
                    (STATE_STARTING, STATE_PENDING, num_to_dequeue))

        return cur.fetchall()
