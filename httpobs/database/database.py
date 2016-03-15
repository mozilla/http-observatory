from contextlib import contextmanager
from json import dumps

from httpobs.conf import (DATABASE_CA_CERT,
                          DATABASE_DB,
                          DATABASE_HOST,
                          DATABASE_PASSWORD,
                          DATABASE_PORT,
                          DATABASE_SSL_MODE,
                          DATABASE_USER)
from httpobs.scanner import STATE_ABORTED, STATE_FAILED, STATE_FINISHED, STATE_PENDING
from httpobs.scanner.analyzer import NUM_TESTS
from httpobs.scanner.grader import get_grade_for_score

import psycopg2
import psycopg2.extras
import psycopg2.pool
import sys


# TODO: Try to fix connection pooling someday, ugh
# Create a psycopg2 connection pool
# try:
#     pool = psycopg2.pool.ThreadedConnectionPool(1, 224, environ['HTTPOBS_DATABASE_URL'])
# except KeyError:
#     print('Cannot find environmental variable $HTTPOBS_DATABASE_URL. Exiting.')
#     exit(1)
# except psycopg2.OperationalError:
#     print('Cannot connect to PostgreSQL. Exiting.')
#     exit(1)
#
# @contextmanager
# def get_cursor():
#     conn = pool.getconn()
#
#     try:
#         yield conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
#         conn.commit()
#     except:
#         conn.rollback()
#     finally:
#         pool.putconn(conn)

@contextmanager
def get_cursor():
    try:
        conn = psycopg2.connect(database=DATABASE_DB,
                                host=DATABASE_HOST,
                                password=DATABASE_PASSWORD,
                                port=DATABASE_PORT,
                                sslmode=DATABASE_SSL_MODE,
                                sslrootcert=DATABASE_CA_CERT,
                                user=DATABASE_USER)

        try:
            yield conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            conn.commit()
        except:
            conn.rollback()
    except:
        raise IOError


# Print out a warning on startup if we can't connect to PostgreSQL
try:
    with get_cursor() as _:  # noqa
        pass
except IOError:
    print('WARNING: Unable to connect to PostgreSQL.', file=sys.stderr)
    raise


def insert_scan(site_id: int, hidden: bool = False) -> dict:
    with get_cursor() as cur:
        cur.execute("""INSERT INTO scans (site_id, state, start_time, tests_quantity, hidden)
                         VALUES (%s, %s, NOW(), %s, %s)
                         RETURNING *""",
                    (site_id, STATE_PENDING, NUM_TESTS, hidden))

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


def insert_test_results(site_id: int, scan_id: int, tests: list) -> dict:
    with get_cursor() as cur:
        tests_failed = tests_passed = 0
        score = 100

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
            score += score_modifier

            # Insert test result to the database
            cur.execute("""INSERT INTO tests (site_id, scan_id, name, expectation, result, pass, output, score_modifier)
                             VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                        (site_id, scan_id, name, expectation, result, passed, dumps(test), score_modifier))

        # Now we need to update the scans table
        score, grade = get_grade_for_score(score)

        # Update the scans table
        cur.execute("""UPDATE scans
                         SET (end_time, tests_failed, tests_passed, grade, score, state) =
                         (NOW(), %s, %s, %s, %s, %s)
                         WHERE id = %s
                         RETURNING *""",
                    (tests_failed, tests_passed, grade, score, STATE_FINISHED, scan_id))

        row = dict(cur.fetchone())

    return row


def select_scan_grade_totals() -> dict:
    with get_cursor() as cur:
        cur.execute("""SELECT totals.grade, COUNT(*) AS quantity
                         FROM
                           (SELECT site_id, grade, MAX(end_time) AS et
                              FROM scans
                              WHERE state = %s
                              GROUP BY site_id, grade) totals
                         GROUP BY totals.grade""",
                    (STATE_FINISHED,))

        return dict(cur.fetchall())


def select_scan_scanner_stats() -> dict:
    with get_cursor() as cur:
        cur.execute('SELECT state, COUNT(*) as quantity FROM scans GROUP BY state;')

        return dict(cur.fetchall())


def select_scan_recent_finished_scans(num_scans=10, min_score=0, max_score=100) -> dict:
    with get_cursor() as cur:
        cur.execute("""SELECT sites.domain, scans.grade
                         FROM
                           (SELECT site_id, grade, MAX(end_time) AS et
                             FROM scans
                             WHERE state = 'FINISHED'
                             AND score >= %s
                             AND score <= %s
                             AND hidden = FALSE
                             GROUP BY site_id, grade
                             ORDER BY et DESC
                             LIMIT %s) scans
                         INNER JOIN sites
                           ON (sites.id = scans.site_id)""",
                    (min_score, max_score, num_scans))

        return dict(cur.fetchall())


def select_scan_recent_scan(site_id: int, recent_in_seconds=86400) -> dict:
    with get_cursor() as cur:
        cur.execute("""SELECT * FROM scans
                         WHERE site_id = (%s)
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
        cur.execute("""SELECT public_headers, private_headers FROM sites
                         WHERE domain=(%s)
                         ORDER BY creation_time DESC
                         LIMIT 1""",
                    (hostname,))

        # If it has headers, merge the public and private headers together
        if cur.rowcount > 0:
            row = cur.fetchone()

            headers = {} if row.get('public_headers') is None else row.get('public_headers')
            private_headers = {} if row.get('private_headers') is None else row.get('private_headers')
            headers.update(private_headers)

            return headers
        else:
            return {}


def select_site_id(hostname: str) -> int:
    # See if the site exists already
    with get_cursor() as cur:
        cur.execute("""SELECT id FROM sites
                         WHERE domain=(%s)
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
                             SET (state) = (%s)
                             WHERE id = %s
                             RETURNING *""",
                        (state, scan_id))

            row = dict(cur.fetchone())

    return row


def update_scans_abort_broken_scans(num_seconds=1800) -> int:
    """
    Update all scans that are stuck. The hard time limit for celery is 1129, so if something isn't aborted, finished,
    or failed, we should just mark it as aborted.
    :return: the number of scans that were closed out
    """
    with get_cursor() as cur:
        cur.execute("""UPDATE scans
                         SET (state, end_time) = (%s, NOW())
                         WHERE state != %s
                           AND state != %s
                           AND state != %s
                           AND start_time < NOW() - INTERVAL '%s seconds';""",
                    (STATE_ABORTED, STATE_ABORTED, STATE_FAILED, STATE_FINISHED, num_seconds))

        return cur.rowcount
