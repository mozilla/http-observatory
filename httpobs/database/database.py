from contextlib import contextmanager
from json import dumps
from os import environ
from sys import exit

from httpobs.scanner import NUM_TESTS, STATE_FINISHED, STATE_PENDING, STATE_RUNNING, STATE_STARTED
from httpobs.scanner.grader import grade

import psycopg2
import psycopg2.extras
import psycopg2.pool


# Create a psycopg2 connection pool
try:
    pool = psycopg2.pool.SimpleConnectionPool(1, 224, environ['HTTPOBS_DATABASE_URL'])
except KeyError:
    print('Cannot find environmental variable $HTTPOBS_DATABASE_URL. Exiting.')
    exit(1)


@contextmanager
def get_cursor():
    conn = pool.getconn()

    try:
        yield conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        conn.commit()
    finally:
        pool.putconn(conn)


def insert_scan(site_id) -> psycopg2.extras.DictRow:
    with get_cursor() as cur:
        cur.execute("""INSERT INTO scans (site_id, state, start_time, tests_quantity)
                         VALUES (%s, %s, NOW(), %s)
                         RETURNING *""",
                    (site_id, STATE_PENDING, NUM_TESTS))

    return cur.fetchone()


def insert_scan_grade(scan_id, scan_grade, scan_score) -> psycopg2.extras.DictRow:
    with get_cursor() as cur:
        cur.execute("""UPDATE scans
                         SET (grade, score) =
                         (%s, %s)
                         WHERE id = %s
                         RETURNING *""",
                    (scan_grade, scan_score, scan_id))

    return cur.fetchone()


def insert_test_result(site_id: int, scan_id: int, name: str, output: dict) -> psycopg2.extras.DictRow:
    with get_cursor() as cur:
        # Pull the expectation, result, and pass result from the output
        expectation = output.pop('expectation')
        passed = output.pop('pass')
        result = output.pop('result')
        score_modifier = output.pop('score_modifier')

        # First, let's get the scan from the scans table
        cur.execute("""SELECT tests_completed, tests_passed, tests_failed, tests_quantity, state FROM scans
                         WHERE id=%s""", (scan_id,))

        row = cur.fetchone()

        # Increment the number of tests completed
        tests_completed = row['tests_completed'] + 1
        end_time = 'NULL'

        # Set the proper state
        state = row['state']
        if state == STATE_STARTED:
            state = STATE_RUNNING
        elif tests_completed == row['tests_quantity']:
            state = STATE_FINISHED
            end_time = 'NOW()'

        # Increment the tests passed/failed column
        tests_passed = row['tests_passed'] + 1 if passed in (True, None) else row['tests_passed']
        tests_failed = row['tests_failed'] + 1 if passed is False else row['tests_failed']

        # Update the scans table
        cur.execute("""UPDATE scans
                         SET (end_time, tests_completed, tests_failed, tests_passed, state) =
                         ({0}, %s, %s, %s, %s)
                         WHERE id = %s""".format(end_time),
                    (tests_completed, tests_failed, tests_passed, state, scan_id))

        # Add the test result to the database
        cur.execute("""INSERT INTO tests (site_id, scan_id, name, expectation, result, pass, output, score_modifier)
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                         RETURNING *""",
                    (site_id, scan_id, name, expectation, result, passed, dumps(output), score_modifier))

    # If the state was finished, let's trigger a grading call
    if state == STATE_FINISHED:
        grade(scan_id)

    return cur.fetchone()


# TODO: Only look for successful scans?
def select_scan_recent_scan(site_id: int) -> psycopg2.extras.DictRow:
    with get_cursor() as cur:
        cur.execute("""SELECT * FROM scans
                         WHERE start_time >= NOW() - INTERVAL '1 day'
                         AND site_id = '%s'
                         ORDER BY start_time DESC
                         LIMIT 1""",
                    (site_id,))

        if cur.rowcount > 0:
            return cur.fetchone()

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


def update_scan_state(scan_id, state: str, error=None) -> psycopg2.extras.DictRow:
    if error:
        with get_cursor() as cur:
            cur.execute("""UPDATE scans
                             SET (state, end_time, error) = (%s, NOW(), %s)
                             WHERE id = %s
                             RETURNING *""",
                        (state, error, scan_id))

    else:
        with get_cursor() as cur:
            cur.execute("""UPDATE scans
                             SET (state) = (%s)
                             WHERE id = %s
                             RETURNING *""",
                        (state, scan_id))

    return cur.fetchone()
