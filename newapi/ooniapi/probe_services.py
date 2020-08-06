"""
OONI Probe Services API
"""

from typing import List
import random
import time

from flask import Blueprint, current_app, request
from flask.json import jsonify
import jwt  # debdeps: python3-jwt

probe_services_blueprint = Blueprint("ps_api", "probe_services")


@probe_services_blueprint.route("/api/v1/collectors")
def list_collectors():
    """List collectors
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
    """Login - used by probes
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
    """Register - used by probes
    ---
    parameters:
      - in: body
        name: register data
        description: Registration data
        required: true
        schema:
          type: object
          properties:
            ProbeCC:
              type: string
            ProbeASN:
              type: string
            Platform:
              type: string
            SoftwareName:
              type: string
            SoftwareVersion:
              type: string
            SupportedTests:
              type: array
              items:
                type: string
            NetworkType:
              type: string
            AvailableBandwidth:
              type: string
            Language:
              type: string
            Token:
              type: string
            Password:
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
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/api/v1/update/<clientID>", methods=["PUT"])
def api_update(clientID):
    """
    TODO
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/api/v1/test-helpers")
def list_test_helpers():
    """#f:1 pe bouncer
    List collectors
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


# key = 'secret'
# encoded = jwt.encode({'some': 'payload'}, key, algorithm='HS256')
#'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg'
# decoded = jwt.decode(encoded, key, algorithms='HS256')
# {'some': 'payload'}
##>>jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'})


@probe_services_blueprint.route("/api/v1/test-list/psiphon-config")
def serve_psiphon_config():
    """
    TODO
    ---
    responses:
      '200':
        description: TODO
    """
    decoded = jwt.decode(encoded, key, algorithms="HS256")
    return jsonify({"msg": "not implemented"})  # TODO


#
## TODO
## JWT required
@probe_services_blueprint.route("/api/v1/test-list/tor-targets")
def serve_tor_targets():
    """
    TODO
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/api/private/v1/wcth")
def forward_to_old_test_helper():
    """
    TODO
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/bouncer/net-tests")
def bouncer_net_tests():
    """
    TODO
    ---
    responses:
      '200':
        description: TODO
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/report", methods=["POST"])
def open_report():
    """
    Open report
    ---
    responses:
      '200':
        description: Open a report
    """
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/report/<reportID>")
def receive_measurement(report_id):
    """
    Submit measurement
    ---
    responses:
      '200':
        description: Acknowledge
    """
    # TODO: forward to fastpath
    return jsonify({"msg": "not implemented"})  # TODO


@probe_services_blueprint.route("/report/<reportID>/close", methods=["POST"])
def close_report(report_id):
    """
    Close report
    ---
    responses:
      '200':
        description: Close a report
    """
    return jsonify({"msg": "not implemented"})  # TODO
