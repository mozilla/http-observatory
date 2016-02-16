from httpobs.scanner.tasks import scan
from httpobs.scanner.utils import valid_hostname
from httpobs.website import add_response_headers, sanitized_api_response

from flask import Blueprint, abort, jsonify

import httpobs.database as database

api = Blueprint('api', __name__)

# TODO: Implement GET, which just returns scan status?
# @api.route('/api/v1/scan/<hostname>', methods=['GET'])
# def get_scan_hostname(hostname):
#     abort(403)


# TODO: Implement API to write public and private headers to the database

@api.route('/api/v1/scan/<hostname>', methods=['GET', 'POST'])
@add_response_headers()
@sanitized_api_response
def api_post_scan_hostname(hostname: str):
    hostname = hostname.lower()

    # Fail if it's not a valid hostname (not in DNS, not a real hostname, etc.)  # TODO: move to frontend?
    if not valid_hostname(hostname):
        return {'error': 'invalid-hostname'}

    # Get the site's id number
    site_id = database.select_site_id(hostname)

    # Next, let's see if there's a recent scan; if there was a recent scan, let's just return it
    row = database.select_scan_recent_scan(site_id)

    # TODO: allow something to force a rescan

    # Otherwise, let's start up a scan
    if not row:
        row = database.insert_scan(site_id)
        scan_id = row['id']

        # Begin the dispatch process
        scan.delay(hostname, site_id, scan_id)

    # Return the scan row
    return row


@api.route('/api/v1/result/<scan_id>', methods=['GET'])
@add_response_headers()
@sanitized_api_response
def api_get_test_results(scan_id: int):
    try:
        scan_id = int(scan_id)
    except ValueError:
        abort(403)

    # Get all the test results for the given scan id and return it
    return database.select_test_results(scan_id)
