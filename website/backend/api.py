from scanner import STATE_FINISHED
from scanner.grader import grade
from scanner.tasks import scan
from website import add_response_headers

from flask import Blueprint, abort, jsonify

import database

api = Blueprint('api', __name__)

# TODO Implement GET, which just returns scan status?
# @api.route('/api/v1/scan/<hostname>', methods=['GET'])
# def get_scan_hostname(hostname):
#     abort(403)


@api.route('/api/v1/scan/<hostname>', methods=['GET', 'POST'])
@add_response_headers()
def api_post_scan_hostname(hostname: str):
    hostname = hostname.lower()

    # Get the site's id number
    site_id = database.select_site_id(hostname)

    # Next, let's see if there's a recent scan
    recent_scan_row = database.select_scan_recent_scan(site_id)

    # If there was a recent scan, just return it
    if recent_scan_row:
        if recent_scan_row['state'] == STATE_FINISHED and recent_scan_row['grade'] is None:
            recent_scan_row = grade(recent_scan_row['id'])

        # TODO: clean this up
        return jsonify(recent_scan_row)

    # Otherwise, let's start up a scan
    else:
        row = database.insert_scan(site_id)
        scan_id = row['id']

    # Begin the dispatch process
    scan(hostname, site_id, scan_id)

    # And return the scan data
    # TODO: clean this up
    return jsonify(row)


@api.route('/api/v1/results/<scan_id>', methods=['GET'])
@add_response_headers()
def api_get_test_results(scan_id: int):
    try:
        scan_id = int(scan_id)
    except ValueError:
        abort(403)

    # Get all the test results for the given scan id and return it
    return jsonify(database.select_test_results(scan_id))
