from flask import abort, Blueprint, jsonify

from httpobs import SOURCE_URL, VERSION
from httpobs.database import get_cursor


common_api = Blueprint('common-api', __name__)


@common_api.route('/__heartbeat__')
def heartbeat():
    # TODO: check celery status
    try:
        with get_cursor() as _:  # noqa
            return ''
    except IOError:
        abort(500)


@common_api.route('/__lbheartbeat__')
def lbheartbeat():
    return ''


@common_api.route('/__version__')
def version():
    return jsonify({'source': SOURCE_URL,
                    'version': VERSION})
