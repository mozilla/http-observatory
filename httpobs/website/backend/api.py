from httpobs.scanner.grader import get_score_description, GRADES
from httpobs.scanner.tasks import scan
from httpobs.scanner.utils import valid_hostname
from httpobs.website import add_response_headers, sanitized_api_response

from flask import Blueprint, jsonify, request
from os import environ

import httpobs.database as database

api = Blueprint('api', __name__)


COOLDOWN = 15 if 'HTTPOBS_DEV' in environ else 300


# TODO: Implement API to write public and private headers to the database

@api.route('/api/v1/analyze', methods=['GET', 'OPTIONS', 'POST'])
@add_response_headers(cors=True)
@sanitized_api_response
def api_post_scan_hostname():
    # TODO: Allow people to accidentally use https://mozilla.org and convert to mozilla.org

    # Get the hostname
    hostname = request.args.get('host', '').lower()

    # Fail if it's not a valid hostname (not in DNS, not a real hostname, etc.)
    hostname = valid_hostname(hostname) or valid_hostname('www.' + hostname)  # prepend www. if necessary
    if not hostname:
        return {'error': '{hostname} is an invalid hostname'.format(hostname=request.args.get('host', ''))}

    # Get the site's id number
    try:
        site_id = database.select_site_id(hostname)
    except IOError:
        return {'error': 'Unable to connect to database'}

    # Next, let's see if there's a recent scan; if there was a recent scan, let's just return it
    # Setting rescan shortens what "recent" means
    rescan = True if request.form.get('rescan', 'false') == 'true' else False
    if rescan:
        row = database.select_scan_recent_scan(site_id, COOLDOWN)
    else:
        row = database.select_scan_recent_scan(site_id)

    # Otherwise, let's start up a scan
    if not row:
        hidden = True if request.form.get('hidden', 'false') == 'true' else False

        # Begin the dispatch process if it was a POST
        if request.method == 'POST':
            row = database.insert_scan(site_id, hidden=hidden)
            scan_id = row['id']
            scan.delay(hostname, site_id, scan_id)
        else:
            return {'error': 'recent-scan-not-found'}

    # If there was a rescan attempt and it returned a row, it's because the rescan was done within the cooldown window
    elif rescan and request.method == 'POST':
        return {'error': 'rescan-attempt-too-soon'}

    # Return the scan row
    return row


@api.route('/api/v1/getGradeTotals', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_grade_totals():
    totals = database.select_scan_grade_totals()

    # If a grade isn't in the database, return it with quantity 0
    totals = {grade: totals.get(grade, 0) for grade in GRADES}

    return jsonify(totals)


@api.route('/api/v1/getRecentScans', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_recent_scans():
    try:
        # Get the min and max scores, if they're there
        min_score = int(request.args.get('min-score', 0))
        max_score = int(request.args.get('max-score', 1000))

        min_score = max(0, min_score)
        max_score = min(1000, max_score)
    except ValueError:
        return {'error': 'invalid-parameters'}

    return jsonify(database.select_scan_recent_finished_scans(min_score=min_score, max_score=max_score))


@api.route('/api/v1/getScannerStats', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_scanner_stats():
    return jsonify(database.select_scan_scanner_stats())


@api.route('/api/v1/getScanResults', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
@sanitized_api_response
def api_get_scan_results():
    scan_id = request.args.get('scan')

    if not scan_id:
        return {'error': 'scan-not-found'}

    # Get all the test results for the given scan id
    tests = dict(database.select_test_results(scan_id))

    # For each test, get the test score description and add that in
    for test in tests:
        tests[test]['score_description'] = get_score_description(tests[test]['result'])

    return tests
