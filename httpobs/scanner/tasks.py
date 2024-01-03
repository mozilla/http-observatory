import sys

from httpobs.conf import DEVELOPMENT_MODE
from httpobs.database import insert_test_results, select_site_headers, update_scan_state
from httpobs.scanner import STATE_FAILED, STATE_RUNNING
from httpobs.scanner.analyzer import NUM_TESTS, tests
from httpobs.scanner.grader import MINIMUM_SCORE_FOR_EXTRA_CREDIT, get_grade_and_likelihood_for_score
from httpobs.scanner.retriever import retrieve_all
from httpobs.scanner.utils import sanitize_headers


def scan(hostname: str, site_id: int, scan_id: int):
    try:
        # Once celery kicks off the task, let's update the scan state from PENDING to RUNNING
        update_scan_state(scan_id, STATE_RUNNING)

        # Get the site's cookies and headers
        headers = select_site_headers(hostname)

        # Attempt to retrieve all the resources
        reqs = retrieve_all(hostname, cookies=headers['cookies'], headers=headers['headers'])

        # If we can't connect at all, let's abort the test
        if reqs['responses']['auto'] is None:
            update_scan_state(scan_id, STATE_FAILED, error='site down')

            return

        results = [test(reqs) for test in tests]
        response_headers = sanitize_headers(reqs["responses"]["auto"].headers)
        status_code = reqs["responses"]["auto"].status_code

        tests_passed = 0
        score_with_extra_credit = uncurved_score = 100

        for result in results:
            passed = result.get("pass")
            score_modifier = result.get("score_modifier")

            # Keep track of how many tests passed or failed
            if passed:
                tests_passed += 1

            # And keep track of the score
            score_with_extra_credit += score_modifier
            if score_modifier < 0:
                uncurved_score += score_modifier

        # Only record the full score if the uncurved score already receives an A
        score = score_with_extra_credit if uncurved_score >= MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved_score

        # Now we need to update the scans table
        score, grade, likelihood_indicator = get_grade_and_likelihood_for_score(score)

        return insert_test_results(
            site_id,
            scan_id,
            {
                "scan": {
                    "grade": grade,
                    "likelihood_indicator": likelihood_indicator,
                    "response_headers": response_headers,
                    "score": score,
                    "tests_failed": NUM_TESTS - tests_passed,
                    "tests_passed": tests_passed,
                    "tests_quantity": NUM_TESTS,
                    "status_code": status_code,
                },
                "tests": results,
            },
        )

    # the database is down, oh no!
    except IOError:
        print('database down, aborting scan on {hostname}'.format(hostname=hostname), file=sys.stderr)
    except:
        # TODO: have more specific error messages
        e = sys.exc_info()[1]  # get the error message

        # If we are unsuccessful, close out the scan in the database
        update_scan_state(scan_id, STATE_FAILED, error=repr(e))

        # Print the exception to stderr if we're in dev
        if DEVELOPMENT_MODE:
            import traceback

            print('Error detected in scan for : ' + hostname)
            traceback.print_exc(file=sys.stderr)
