"""
OONI Probe Services API
"""

from base64 import b64encode
from datetime import datetime
from os import urandom
from typing import List

from flask import Blueprint, current_app, request, make_response
from flask.json import jsonify
import jwt  # debdeps: python3-jwt

probe_services_blueprint = Blueprint("ps_api", "probe_services")


@probe_services_blueprint.route("/api/v1/collectors")
def list_collectors():
    """Probe Services: list collectors
    ---
    responses:
      '200':
        description: List available collectors
    """
    j = [
        {"address": "httpo://jehhrikjjqrlpufu.onion", "type": "onion"},
        {"address": "https://ams-ps2.ooni.nu:443", "type": "https"},
        {
            "address": "https://dkyhjv0wpi2dk.cloudfront.net",
            "front": "dkyhjv0wpi2dk.cloudfront.net",
            "type": "cloudfront",
        },
        {"address": "httpo://hcn5nqahdkds6cjv.onion", "type": "onion"},
        {"address": "https://mia-ps2.ooni.nu:443", "type": "https"},
        {
            "address": "https://dkyhjv0wpi2dk.cloudfront.net",
            "front": "dkyhjv0wpi2dk.cloudfront.net",
            "type": "cloudfront",
        },
    ]
    return jsonify(j)


@probe_services_blueprint.route("/api/v1/login", methods=["POST"])
def login_post():
    """Probe Services: login
    ---
    parameters:
      - in: body
        name: auth data
        description: Username and password
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      '200':
        description: Auth object
        content:
          application/json:
            schema:
              type: object
              properties:
                token:
                  type: string
                  description: Token
                expire:
                  type: string
                  description: Expiration time
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/api/v1/register", methods=["POST"])
def register():
    """Probe Services: Register
    ---
    parameters:
      - in: body
        name: register data
        description: Registration data
        required: true
        schema:
          type: object
          properties:
            password:
              type: string
            platform:
              type: string
            probe_asn:
              type: string
            probe_cc:
              type: string
            software_name:
              type: string
            software_version:
              type: string
            supported_tests:
              type: array
              items:
                type: string
    responses:
      '200':
        description: Registration confirmation
        content:
          application/json:
            schema:
              type: object
              properties:
                token:
                  description: client_id
                  type: string
    """
    log = current_app.logger
    if not request.is_json:
        return jsonify({"msg": "error: JSON expected!"})

    return jsonify({"client_id": "BOGUS_CLIENT_ID"})  # FIXME


# UNUSED
# @probe_services_blueprint.route("/api/v1/update/<clientID>", methods=["PUT"])
# def api_update(clientID):
#     """Probe Services
#     ---
#     responses:
#       '200':
#         description: TODO
#     """
#     return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/api/v1/test-helpers")
def list_test_helpers():
    """Probe Services: List collectors
    ---
    responses:
      '200':
        description: List test helpers
    """
    j = {
        "dns": [
            {"address": "37.218.241.93:57004", "type": "legacy"},
            {"address": "37.218.241.93:57004", "type": "legacy"},
        ],
        "http-return-json-headers": [
            {"address": "http://37.218.241.94:80", "type": "legacy"},
            {"address": "http://37.218.241.94:80", "type": "legacy"},
        ],
        "ssl": [
            {"address": "https://37.218.241.93", "type": "legacy"},
            {"address": "https://37.218.241.93", "type": "legacy"},
        ],
        "tcp-echo": [
            {"address": "37.218.241.93", "type": "legacy"},
            {"address": "37.218.241.93", "type": "legacy"},
        ],
        "traceroute": [
            {"address": "37.218.241.93", "type": "legacy"},
            {"address": "37.218.241.93", "type": "legacy"},
        ],
        "web-connectivity": [
            {"address": "httpo://o7mcp5y4ibyjkcgs.onion", "type": "legacy"},
            {"address": "https://wcth.ooni.io", "type": "https"},
            {
                "address": "https://d33d1gs9kpq1c5.cloudfront.net",
                "front": "d33d1gs9kpq1c5.cloudfront.net",
                "type": "cloudfront",
            },
            {"address": "httpo://y3zq5fwelrzkkv3s.onion", "type": "legacy"},
            {"address": "https://wcth.ooni.io", "type": "https"},
            {
                "address": "https://d33d1gs9kpq1c5.cloudfront.net",
                "front": "d33d1gs9kpq1c5.cloudfront.net",
                "type": "cloudfront",
            },
        ],
    }
    return jsonify(j)


@probe_services_blueprint.route("/api/v1/test-list/psiphon-config")
def serve_psiphon_config():
    """Probe Services: Psiphon data
    TODO
    ---
    responses:
      '200':
        description: TODO
    """
    decoded = jwt.decode(encoded, key, algorithms="HS256")
    return jsonify({"msg": "not implemented"})  # TODO


## TODO
@probe_services_blueprint.route("/api/v1/test-list/tor-targets")
def serve_tor_targets():
    """Probe Services: Tor targets
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/api/private/v1/wcth")
def forward_to_old_test_helper():
    """Probe Services: TODO
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/bouncer/net-tests")
def bouncer_net_tests():
    """Probe Services: TODO
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


def error(msg, code=400):
    return make_response(dict(error=msg), code=code)


@probe_services_blueprint.route("/report", methods=["POST"])
def open_report():
    """Probe Services: Open report
    ---
    parameters:
      - in: body
        name: open report data
        required: true
        schema:
          type: object
          properties:
            data_format_version:
              type: string
            format:
              type: string
            probe_asn:
              type: string
            probe_cc:
              type: string
            software_name:
              type: string
            software_version:
              type: string
            test_name:
              type: string
            test_start_time:
              type: string
            test_version:
              type: string
    responses:
      '200':
        description: Open report confirmation
        content:
          application/json:
            schema:
              type: object
              properties:
                backend_version:
                  type: string
                report_id:
                  type: string
                supported_formats:
                  type: array
                  items:
                    type: string
    responses:
      '200':
        description: Open a report
    """
    log = current_app.logger
    if not request.is_json:
        return error("JSON expected")

    log.info("Open report %r", request.json)
    asn = request.json.get("probe_asn", "AS0")
    if len(asn) > 8 or len(asn) < 3 or not asn.startswith("AS"):
        asn = "AS0"
    cc = request.json.get("probe_cc", "ZZ").upper()
    if len(cc) != 2:
        cc = "ZZ"
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    cid = "1" # collector id TODO read from conf
    rand = b64encode(urandom(12), b'oo').decode()
    rid = f"{ts}_{asn}_n{cid}{cc}{rand}"
    return jsonify(
        backend_version="1.3.5", supported_formats=["yaml", "json"], report_id=rid
    )


@probe_services_blueprint.route("/report/<report_id>", methods=["POST"])
def receive_measurement(report_id):
    """Probe Services: Submit measurement
    ---
    responses:
      '200':
        description: Acknowledge
    """
    log = current_app.logger
    if not request.is_json:
        return error("JSON expected")

    r = request.json
    if "format" not in r or "content" not in r:
        return error("Incorrect format")

    # TODO: save to disk and forward to fastpath
    # TODO return jsonify(measurement_id = mid)
    return jsonify()


@probe_services_blueprint.route("/report/<report_id>/close", methods=["POST"])
def close_report(report_id):
    """Probe Services: Close report
    ---
    responses:
      '200':
        description: Close a report
    """
    if not request.is_json:
        return error("JSON expected")

    return jsonify()
