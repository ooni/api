from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import datetime
import os

from flask import Flask, json

# from flask_misaka import Misaka
# from flask_cors import CORS
from ooniapi.rate_limit_quotas import FlaskLimiter

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import ignore_logger

from flasgger import Swagger

from decimal import Decimal
from ooniapi.database import init_db

APP_DIR = os.path.dirname(__file__)


class FlaskJSONEncoder(json.JSONEncoder):
    # Special JSON encoder that handles dates
    def default(self, o):
        if isinstance(o, datetime.datetime):
            if o.tzinfo:
                # eg: '2015-09-25T23:14:42.588601+00:00'
                return o.isoformat("T")
            else:
                # No timezone present - assume UTC.
                # eg: '2015-09-25T23:14:42.588601Z'
                return o.isoformat("T") + "Z"

        if isinstance(o, datetime.date):
            return o.isoformat()

        if isinstance(o, Decimal):
            return float(o)

        if isinstance(o, set):
            return list(o)

        return json.JSONEncoder.default(self, o)


def init_app(app, testmode=False):
    # We load configurations first from the config file (where some options
    # are overridable via environment variables) or from the config file
    # pointed to by the MEASUREMENTS_CONFIG environment variable.
    # The later overrides the former.
    app.config.from_object("ooniapi.config")
    app.config.from_envvar("MEASUREMENTS_CONFIG", silent=True)

    # Prevent messy duplicate logs during testing
    if not testmode:
        app.logger.addHandler(logging.StreamHandler())

    stage = app.config["APP_ENV"]
    if stage == "production":
        app.logger.setLevel(logging.INFO)
    elif stage == "development":
        app.logger.setLevel(logging.DEBUG)
        # Set the jinja templates to reload when in development
        app.jinja_env.auto_reload = True
        app.config["TEMPLATES_AUTO_RELOAD"] = True
        app.config["DEBUG"] = True
    elif stage not in ("testing", "staging",):  # known envs according to Readme.md
        raise RuntimeError("Unexpected APP_ENV", stage)

    if app.config["APP_ENV"] == "production":
        sentry_sdk.init(
            dsn="https://dcb077b34ac140d58a7c37609cea0cf9@sentry.io/1367288",
            integrations=[FlaskIntegration()],
        )
        # TODO Temporary workaround to ignore flask-limiter logs due to:
        # https://github.com/ooni/api/issues/145 &
        # https://github.com/alisaifee/flask-limiter/issues/186
        ignore_logger("flask-limiter")

    # md = Misaka(fenced_code=True)
    # md.init_app(app)

    # CORS(app, resources={r"/api/*": {"origins": "*"}})


def check_config(config):
    pass


def create_app(*args, testmode=False, **kw):
    from ooniapi import views

    app = Flask(__name__)
    app.json_encoder = FlaskJSONEncoder

    # Order matters
    init_app(app, testmode=testmode)
    check_config(app.config)

    # Setup Database connector
    init_db(app)

    # Setup rate limiting
    # NOTE: the limits apply per-process. The number of processes is set in:
    # https://github.com/ooni/sysadmin/blob/master/ansible/roles/ooni-measurements/tasks/main.yml
    limits = dict(
        ipaddr_per_month=6000,
        token_per_month=6000,
        ipaddr_per_week=2000,
        token_per_week=2000,
        ipaddr_per_day=400,
        token_per_day=500,
    )
    # Whitelist Prometheus and AMS Explorer
    # TODO: move addrs to an external config file /etc/ooniapi.conf ?
    whitelist = ["37.218.245.43", "37.218.242.149"]
    app.limiter = FlaskLimiter(limits=limits, app=app, whitelisted_ipaddrs=whitelist)

    Swagger(app, parse=True)

    # FIXME
    views.register(app)

    # why is it `teardown_appcontext` and not `teardown_request` ?...
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        app.db_session.remove()

    @app.route("/health")
    def health():
        return "UP"
        # option httpchk GET /check
        # http-check expect string success

    return app
