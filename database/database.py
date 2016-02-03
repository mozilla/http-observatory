from contextlib import contextmanager
from json import dumps

from scanner import STATE_FINISHED, STATE_RUNNING, STATE_STARTED

import psycopg2
import psycopg2.extras
import psycopg2.pool

import scanner.analyzer

# Create a psycopg2 connection pool
# TODO: pull credentials from environmental variable
pool = psycopg2.pool.SimpleConnectionPool(1, 32, database='http_observatory')


@contextmanager
def get_cursor():
    conn = pool.getconn()

    try:
        yield conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        conn.commit()
    finally:
        pool.putconn(conn)


def insert_scan_grade(scan_id, grade):
    with get_cursor() as cur:
        cur.execute("""UPDATE scans
                         SET (grade, grade_reasons) =
                         (%s, %s)
                         WHERE id = %s
                         RETURNING *""",
                    (grade['grade'], dumps(grade['grade_reasons']), scan_id))

    return cur.fetchone()


def insert_scan(site_id) -> psycopg2.extras.DictRow:
    with get_cursor() as cur:
        cur.execute("""INSERT INTO scans (site_id, state, start_time, tests_quantity)
                         VALUES (%s, %s, NOW(), %s)
                         RETURNING *""",
                    (site_id, STATE_STARTED, len(scanner.analyzer.__all__)))

    return cur.fetchone()


def insert_test_result(site_id: int, scan_id: int, name: str, output: dict) -> psycopg2.extras.DictRow:
    expectation = output.pop('expectation')

    with get_cursor() as cur:
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
        tests_passed = row['tests_passed'] + 1 if output['pass'] == True else row['tests_passed']
        tests_failed = row['tests_failed'] + 1 if output['pass'] == False else row['tests_failed']

        # Update the scans table
        cur.execute("""UPDATE scans
                         SET (end_time, tests_completed, tests_failed, tests_passed, state) =
                         ({0}, %s, %s, %s, %s)
                         WHERE id = %s""".format(end_time),
                    (tests_completed, tests_failed, tests_passed, state, scan_id))

        # Add the test result to the database
        cur.execute("""INSERT INTO tests (site_id, scan_id, name, expectation, output)
                         VALUES (%s, %s, %s, %s, %s)
                         RETURNING *""",
                    (site_id, scan_id, name, expectation, dumps(output, indent=4, sort_keys=True)))

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
                expectation = test['expectation']
                passed = test['output'].pop('pass')
                result = test['output'].pop('result')

                tests[test['name']] = {
                    'expectation': expectation,
                    'output': test['output'],
                    'passed': passed,
                    'result': result,
                }

    return tests
