from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
#import pathlib
#import traceback

#import werkzeug
from flask import Response, current_app, render_template

# from connexion import ProblemException, FlaskApi, Resolver, problem

from ooniapi.private import api_private_blueprint
from ooniapi.measurements import api_msm_blueprint
from ooniapi.pages import pages_blueprint, api_docs_blueprint
from ooniapi.probe_services import probe_services_blueprint
from ooniapi.prio import prio_bp

HERE = os.path.abspath(os.path.dirname(__file__))


#def render_problem_exception(exception):
#    response = exception.to_problem()
#    return FlaskApi.get_response(response)


# def render_generic_exception(exception):
#    if not isinstance(exception, werkzeug.exceptions.HTTPException):
#        exc_name = "{}.{}".format(type(exception).__module__, type(exception).__name__)
#        exc_desc = str(exception)
#        if hasattr(exception, "__traceback__"):
#            current_app.logger.error(
#                "".join(traceback.format_tb(exception.__traceback__))
#            )
#        current_app.logger.error(
#            "Unhandled error occurred, {}: {}".format(exc_name, exc_desc)
#        )
#        exception = werkzeug.exceptions.InternalServerError(
#            description="An unhandled application error occurred: {}".format(exc_name)
#        )
#
#    response = problem(
#        title=exception.name, detail=exception.description, status=exception.code
#    )
#    return FlaskApi.get_response(response)


def page_not_found(e):
    return render_template("404.html"), 404


def bad_request(e):
    return render_template("400.html", exception=e), 400

def register(app):
    #app.register_blueprint(api_docs_blueprint, url_prefix="/api")

    # Measurements API:
    app.register_blueprint(api_msm_blueprint, url_prefix="/api")
    #app.register_blueprint(connexion_api.blueprint)

    # Private API
    app.register_blueprint(api_private_blueprint, url_prefix="/api/_")

    # The index is here:
    app.register_blueprint(pages_blueprint, url_prefix="")

    # Probe services
    app.register_blueprint(probe_services_blueprint, url_prefix="")
    app.register_blueprint(prio_bp, url_prefix="")

    #app.register_error_handler(ProblemException, render_problem_exception)
    #app.register_error_handler(Exception, render_generic_exception)

    app.errorhandler(404)(page_not_found)
    app.errorhandler(400)(bad_request)
