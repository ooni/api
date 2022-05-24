from datetime import datetime
from flask.json import jsonify
from flask import Response, make_response

ISO_TIMESTAMP_SHORT = "%Y%m%dT%H%M%SZ"
OONI_EPOCH = datetime(2012, 12, 5)

INTERVAL_UNITS = dict(s=1, m=60, h=3600, d=86400)


def cachedjson(interval: str, *a, **kw):
    """Jsonify and add cache expiration"""
    resp = jsonify(*a, **kw)
    unit = interval[-1]
    value = int(interval[:-1])
    resp.cache_control.max_age = value * INTERVAL_UNITS[unit]
    return resp


def nocachejson(*a, **kw):
    """Jsonify and explicitely prevent caching"""
    resp = jsonify(*a, **kw)
    resp.cache_control.max_age = 0
    resp.cache_control.no_cache = True
    return resp


def jer(error_id, tpl, *a, **kw) -> Response:
    """Error handler with localization support
    Return error_id, error_msg human friendly msg and errdata dict
    Set Cache-Control: No-Cache
    Set HTTP error code from the first optional argument or default to 400
    """
    # The function definition is parsed by ../scan_error_handlers.py
    if error_id == "":
        error_id = tpl.title().replace(" ", "")
    if a:
        http_code = a[0]
    else:
        http_code = 400
    msg = tpl.format(kw)
    d = dict(error=error_id, error_msg=msg, errdata=kw)
    resp = make_response(jsonify(d), http_code)
    resp.cache_control.no_cache = True
    return resp
