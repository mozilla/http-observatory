import sys
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

import httpobs.database as database
import httpobs.scanner as scanner
from httpobs import STATE_FAILED
from httpobs.conf import API_COOLDOWN, DEVELOPMENT_MODE
from httpobs.scanner.grader import get_score_description
from httpobs.website import add_response_headers
from httpobs.website.utils import valid_hostname

api_v2 = Blueprint("api_v2", __name__)


@api_v2.route("/analyze", methods=["GET", "OPTIONS", "POST"])
@add_response_headers(cors=True)
def api_post_scan_hostname():
    status_code = 200
    scan = {}
    tests = {}

    host = request.args.get("host", "").lower().strip()
    try:
        site_id = database.select_site_id(host, create=False)
    except IOError:
        return {
            "error": "database-down",
            "text": "Unable to connect to database",
        }, 503

    if site_id is not None:
        hostname = host
    else:
        ip = True if valid_hostname(host) is None else False
        if ip:
            return {
                "error": "invalid-hostname-ip",
                "text": "Cannot scan IP addresses",
            }, 400

        hostname = valid_hostname(host) or (
            valid_hostname("www." + host) if host else False
        )  # prepend www. if necessary
        if not hostname:
            return {
                "error": "invalid-hostname",
                "text": f"{host} is an invalid hostname",
            }, 400

    site_id: int = database.select_site_id(host, create=True)
    scan = database.select_scan_most_recent_scan(site_id)

    if scan and request.method == "POST":
        time_since_scan = datetime.now() - scan["end_time"]
        if time_since_scan < timedelta(seconds=API_COOLDOWN):
            status_code = 429  # keep going, we'll respond with the most recent scan
        else:
            scan = None  # clear the scan, and we'll do another

    if scan:
        scan_id = scan["id"]

        tests = database.select_test_results(scan_id)
        for name, test in tests.items():
            del test["id"]
            del test["scan_id"]
            del test["site_id"]
            del test["name"]
            test["score_description"] = get_score_description(test["result"])
            tests[name] = {**test.pop("output"), **test}

    else:
        # no scan means we're a POST which hasn't been rate limited
        # or we're a GET for a host which has no scans in the db
        # either way, we need to perform a scan

        hidden = request.form.get("hidden", "false") == "true"

        scan = database.insert_scan(site_id, hidden=hidden)
        scan_id = scan["id"]

        # Get the site's cookies and headers
        # TODO: add API to insert these into the db
        # headers = database.select_site_headers(hostname)

        try:
            result = scanner.scan(hostname)

            if "error" in result:
                scan = database.update_scan_state(scan_id, STATE_FAILED, error=result["error"])
            else:
                scan = database.insert_test_results(
                    site_id,
                    scan_id,
                    result,
                )
                tests = result["tests"]
        except:
            # If we are unsuccessful, close out the scan in the database
            scan = database.update_scan_state(scan_id, STATE_FAILED)

            # Print the exception to stderr if we're in dev
            if DEVELOPMENT_MODE:
                import traceback

                print("Error detected in scan for: " + hostname)
                traceback.print_exc(file=sys.stderr)

    scan["start_time"] = scan["start_time"].isoformat()
    scan["end_time"] = scan["end_time"].isoformat()

    history = database.select_scan_host_history(site_id)

    # Prune for when the score doesn't change; thanks to chuck for the elegant list comprehension
    history = [
        {
            "end_time": v["end_time"].isoformat(),
            "grade": v["grade"],
            "id": v["scan_id"],
            "score": v["score"],
        }
        for k, v in enumerate(history)
        if history[k].get('score') is not history[k - 1].get('score') or k == 0
    ]

    return (
        jsonify(
            {
                "scan": scan,
                "tests": tests,
                "history": history,
            }
        ),
        status_code,
    )
