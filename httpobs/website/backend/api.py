from httpobs.conf import API_KEY, COOLDOWN
from httpobs.scanner.tasks import scan
from httpobs.website import add_response_headers

from flask import abort, jsonify, Blueprint, request

import httpobs.database as database

api = Blueprint('api', __name__)


@api.route('/api/v1/analyze', methods=['POST'])
@add_response_headers()
def api_post_scan_hostname():
    # Abort if the API keys don't match
    if request.form.get('apikey', 'notatrueapikey') != API_KEY:
        abort(403)

    # Get the hostname, whether the scan is hidden, site_id, and scan_id
    try:
        hostname = request.args['host']
        hidden = False if request.form['hidden'] == 'false' else True
        site_id = request.form['site_id']
    except KeyError:
        return {'error': 'scan-missing-parameters'}

    # Sanity check to see that there are no scans pending; it's not a huge issue if we end up with duplicate
    # scans, but it's better not
    row = database.select_scan_recent_scan(site_id, COOLDOWN)

    # Start up the scan
    if not row:
        try:
            row = database.insert_scan(site_id, hidden=hidden)
            scan_id = row['id']
            scan.delay(hostname, site_id, scan_id)
        except IOError:
            return {'error': 'scanner-down-try-again-soon'}

    # Return the scan row
    return jsonify(row)
