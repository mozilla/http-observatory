from httpobs.conf import API_COOLDOWN
from httpobs.scanner.grader import get_score_description, GRADES
from httpobs.scanner.utils import valid_hostname
from httpobs.website import add_response_headers, sanitized_api_response

from flask import Blueprint, jsonify, make_response, request

import httpobs.database as database
import os.path


api = Blueprint('api', __name__)


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
        row = database.select_scan_recent_scan(site_id, API_COOLDOWN)
    else:
        row = database.select_scan_recent_scan(site_id)

    # Otherwise, let's queue up the scan
    if not row:
        hidden = request.form.get('hidden', 'false')

        # Begin the dispatch process if it was a POST
        if request.method == 'POST':
            row = database.insert_scan(site_id, hidden=hidden)
        else:
            return {'error': 'recent-scan-not-found'}

    # If there was a rescan attempt and it returned a row, it's because the rescan was done within the cooldown window
    elif rescan and request.method == 'POST':
        return {'error': 'rescan-attempt-too-soon'}

    # Return the scan row
    return row


# TODO: Deprecate this and replace with __stats__ once website is updated
@api.route('/api/v1/getGradeDistribution', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_grade_totals():
    totals = database.select_star_from('grade_distribution')

    # If a grade isn't in the database, return it with quantity 0
    totals = {grade: totals.get(grade, 0) for grade in GRADES}

    return jsonify(totals)


@api.route('/api/v1/getHostHistory', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_host_history():
    # Get the hostname
    hostname = request.args.get('host', '').lower()

    # Fail if it's not a valid hostname (not in DNS, not a real hostname, etc.)
    hostname = valid_hostname(hostname) or valid_hostname('www.' + hostname)  # prepend www. if necessary
    if not hostname:
        return jsonify({'error': '{hostname} is an invalid hostname'.format(hostname=request.args.get('host', ''))})

    # Get the site's id number
    try:
        site_id = database.select_site_id(hostname)
    except IOError:
        return jsonify({'error': 'Unable to connect to database'})

    # Get the host history
    history = database.select_scan_host_history(site_id)

    # Gracefully handle when there's no history
    if not history:
        return jsonify({'error': 'No history found'})

    # Prune for when the score doesn't change; thanks to chuck for the elegant list comprehension
    pruned_history = [v for k, v in enumerate(history) if history[k].get('score') is not history[k-1].get('score')
                      or k is 0]

    # Return the host history
    return jsonify(pruned_history)


@api.route('/api/v1/getRecentScans', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_recent_scans():
    try:
        # Get the min and max scores, if they're there
        min_score = int(request.args.get('min', 0))
        max_score = int(request.args.get('max', 1000))
        num_scans = int(request.args.get('num', 10))

        min_score = max(0, min_score)
        max_score = min(1000, max_score)
        num_scans = min(25, num_scans)
    except ValueError:
        return {'error': 'invalid-parameters'}

    return jsonify(database.select_scan_recent_finished_scans(num_scans=num_scans,
                                                              min_score=min_score,
                                                              max_score=max_score))


# TODO: Deprecate
@api.route('/api/v1/getScannerStates', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_scanner_states():
    return jsonify(database.select_scan_scanner_statistics()['states'])


@api.route('/api/v1/__stats__', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
def api_get_scanner_stats():
    verbose = True if request.args.get('verbose', '').lower() == 'true' else False

    # Get the scanner statistics from the backend database, defaulting to the quick stats only
    stats = database.select_scan_scanner_statistics(verbose)

    # If a grade isn't in the database, return it with quantity 0
    grade_distribution = {grade: stats['grade_distribution'].get(grade, 0) for grade in GRADES}

    # Get the number of grade improvements
    grade_improvements_all = stats['scan_score_difference_distribution_summation']

    # Make sure we only list the ones that are improvements, with a maximum of 5 letter grades
    grade_improvements = {k: 0 for k in range(0, 6)}
    for k, v in grade_improvements_all.items():
        grade_improvements[min(5, max(0, int(k / 20)))] += v

    return jsonify({
        'gradeDistribution': grade_distribution,
        'gradeImprovements': grade_improvements,
        'misc': {
            'numHoursWithoutScansInLast24Hours': 24 - len(stats['recent_scans']) if verbose else -1,
            'numImprovedSites': sum([v for k, v in grade_improvements_all.items() if k > 0]),
            'numScans': stats['scan_count'],
            'numSuccessfulScans': sum(grade_distribution.values()),
            'numUniqueSites': sum(grade_improvements_all.values())
        },
        'recentScans': stats['recent_scans'],
        'states': stats['states'],
    })


@api.route('/api/v1/getScanResults', methods=['GET', 'OPTIONS'])
@add_response_headers(cors=True)
@sanitized_api_response
def api_get_scan_results():
    scan_id = request.args.get('scan')

    if not scan_id:
        return {'error': 'scan-not-found'}

    # Check for invalid scan_id numbers
    try:
        scan_id = int(scan_id)

        # <3 :atoll
        if scan_id < 1 or scan_id > 2147483646:  # the first rule of autoincrement club
            raise ValueError
    except ValueError:
        return {'error': 'invalid-scan-id'}

    # Get all the test results for the given scan id
    tests = dict(database.select_test_results(scan_id))

    # For each test, get the test score description and add that in
    for test in tests:
        tests[test]['score_description'] = get_score_description(tests[test]['result'])

    return tests


@api.route('/contribute.json', methods=['GET'])
@add_response_headers()
def contribute_json():
    __dirname = os.path.abspath(os.path.dirname(__file__))
    __filename = os.path.join(__dirname, '..', 'docs', 'contribute.json')

    # Return the included contribute.json file
    try:
        with open(__filename, 'r') as f:
            resp = make_response(f.read())
            resp.mimetype = 'application/json'
            return resp
    except:
        return jsonify({'error': 'no-contribute-json'})
