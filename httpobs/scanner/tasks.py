from httpobs.scanner.analyzer import NUM_TESTS, tests
from httpobs.scanner.grader import MINIMUM_SCORE_FOR_EXTRA_CREDIT, get_grade_and_likelihood_for_score
from httpobs.scanner.retriever import retrieve_all
from httpobs.scanner.utils import sanitize_headers


def scan(hostname: str, site_id: int, scan_id: int, headers: dict):
    # Attempt to retrieve all the resources
    reqs = retrieve_all(hostname, cookies=headers['cookies'], headers=headers['headers'])

    # If we can't connect at all, let's abort the test
    if reqs['responses']['auto'] is None:
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

    return {
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
    }
