from flask import abort, Blueprint, jsonify

from httpobs import SOURCE_URL, VERSION
from httpobs.database import get_cursor


monitoring_api = Blueprint('monitoring-api', __name__)


@monitoring_api.route('/__heartbeat__')
def heartbeat():
    # TODO: check celery status
    try:
        # Check the database
        with get_cursor() as _:  # noqa
            pass
    except:
        abort(500)

    return jsonify({'database': 'OK'})


@monitoring_api.route('/__lbheartbeat__')
def lbheartbeat():
    return ''


@monitoring_api.route('/__version__')
def version():
    return jsonify({'source': SOURCE_URL,
                    'version': VERSION})
