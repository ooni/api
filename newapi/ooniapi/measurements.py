"""
Measurements API
The routes are mounted under /api
"""

from csv import DictWriter
from datetime import datetime, timedelta
from dateutil.parser import parse as parse_date
from io import StringIO
import http.client
import json
import math
import re
import time

import requests
import lz4framed

from flask import current_app, request, make_response, abort
from flask.json import jsonify
from werkzeug.exceptions import HTTPException, BadRequest

from sqlalchemy import func, and_, false, text, select, sql, column
from sqlalchemy.sql import literal_column
from sqlalchemy import String, cast
from sqlalchemy.exc import OperationalError
from psycopg2.extensions import QueryCanceledError

from urllib.parse import urljoin, urlencode

from ooniapi import __version__
from ooniapi.config import REPORT_INDEX_OFFSET, REQID_HDR, request_id

from flask import Blueprint

api_msm_blueprint = Blueprint("msm_api", "measurements")

FASTPATH_MSM_ID_PREFIX = "temp-fid-"
FASTPATH_SERVER = "fastpath.ooni.nu"
FASTPATH_PORT = 8000


class QueryTimeoutError(HTTPException):
    code = 504
    description = "The database query timed out.\nTry changing the query parameters."


def get_version():
    return jsonify({"version": __version__})


@api_msm_blueprint.route("/v1/files")
def list_files():
    """List files
    ---
    parameters:
      - name: probe_cc
        in: query
        type: string
        description: The two letter country code
      - name: probe_asn
        in: query
        type: string
        description: the Autonomous system number in the format "ASXXX"
      - name: test_name
        in: query
        type: string
        description: The name of the test
      - name: since
        in: query
        type: string
        description: >-
          The start date of when measurements were run (ex.
          "2016-10-20T10:30:00")
      - name: until
        in: query
        type: string
        description: >-
          The end date of when measurement were run (ex.
          "2016-10-20T10:30:00")
      - name: since_index
        in: query
        type: string
        description: Return results only strictly greater than the provided index
      - name: order_by
        in: query
        type: string
        description: |-
          by which key the results should be ordered by (default: `test_start_time`)
        enum:
          - test_start_time
          - probe_cc
          - report_id
          - probe_asn
          - test_name
          # These are all equivalent
          - index
          - idx
          - report_no
      - name: order
        in: query
        type: string
        description: |-
          If the order should be ascending or descending (one of: `asc` or `desc`)
        enum:
          - asc
          - desc
          - ASC
          - DESC
      - name: offset
        in: query
        type: integer
        description: 'Offset into the result set (default: 0)'
      - name: limit
        in: query
        type: integer
        description: 'Number of records to return (default: 100)'
    responses:
      '200':
        description: List of files that match the requested criteria with pagination
        schema:
          $ref: "#/definitions/FileList"

      default:
        description: Default response
    """
    param = request.args.get
    probe_asn = param("probe_asn")
    probe_cc = param("probe_cc")
    test_name = param("test_name")
    since = param("since")
    until = param("until")
    since_index = param("since_index")
    order_by = param("order_by", "index")
    order = param("order", "desc")
    offset = int(param("offset", 0))
    limit = int(param("limit", 100))
    log = current_app.logger

    if probe_asn is not None:
        if probe_asn.startswith("AS"):
            probe_asn = probe_asn[2:]
        probe_asn = int(probe_asn)

    try:
        if since is not None:
            since = parse_date(since)
    except ValueError:
        raise BadRequest("Invalid since")

    try:
        if until is not None:
            until = parse_date(until)
    except ValueError:
        raise BadRequest("Invalid until")

    if since_index is not None:
        since_index = int(since_index)
        report_no = max(0, since_index - REPORT_INDEX_OFFSET)

    if order_by in ("index", "idx"):
        order_by = "report_no"

    cols = [
        literal_column("textname"),
        literal_column("test_start_time"),
        literal_column("probe_cc"),
        literal_column("probe_asn"),
        literal_column("report_no"),
        literal_column("test_name"),
    ]
    where = []
    query_params = {}

    # XXX maybe all of this can go into some sort of function.
    if probe_cc:
        where.append(sql.text("probe_cc = :probe_cc"))
        query_params["probe_cc"] = probe_cc

    if probe_asn:
        where.append(sql.text("probe_asn = :probe_asn"))
        query_params["probe_asn"] = probe_asn

    if test_name:
        where.append(sql.text("test_name = :test_name"))
        query_params["test_name"] = test_name

    if since:
        where.append(sql.text("test_start_time > :since"))
        query_params["since"] = since

    if until:
        where.append(sql.text("test_start_time <= :until"))
        query_params["until"] = until

    if since_index:
        where.append(sql.text("report_no > :report_no"))
        query_params["report_no"] = report_no

    query = select(cols).where(and_(*where)).select_from("report")
    count = -1
    pages = -1
    current_page = math.ceil(offset / limit) + 1

    query = query.order_by(text("{} {}".format(order_by, order)))
    query = query.limit(limit).offset(offset)

    results = []

    log.debug(query)
    q = current_app.db_session.execute(query, query_params)
    for row in q:
        download_url = urljoin(
            current_app.config["BASE_URL"], "/files/download/%s" % row.textname
        )
        results.append(
            {
                "download_url": download_url,
                "probe_cc": row.probe_cc,
                "probe_asn": "AS{}".format(row.probe_asn),
                "test_name": row.test_name,
                "index": int(row.report_no) + REPORT_INDEX_OFFSET,
                "test_start_time": row.test_start_time,
            }
        )
    # We got less results than what we expected, we know the count and that we are done
    if len(results) < limit:
        count = offset + len(results)
        pages = math.ceil(count / limit)
        next_url = None
    else:
        next_args = request.args.to_dict()
        next_args["offset"] = "%s" % (offset + limit)
        next_args["limit"] = "%s" % limit
        next_url = urljoin(
            current_app.config["BASE_URL"], "/api/v1/files?%s" % urlencode(next_args)
        )

    metadata = {
        "offset": offset,
        "limit": limit,
        "count": count,
        "pages": pages,
        "current_page": current_page,
        "next_url": next_url,
    }

    return jsonify({"metadata": metadata, "results": results})



@api_msm_blueprint.route("/v1/measurement/<measurement_id>")
def get_measurement(measurement_id, download=None):
    """Get one measurement by measurement_id,
    fetching the file from S3 or the fastpath host as needed
    Returns only the measurement without extra data from the database
    fetching the file from the fastpath host
    ---
    parameters:
      - name: measurement_id
        in: path
        required: true
        type: string
        description: The measurement_id to retrieve the measurement for
      - name: download
        in: query
        type: boolean
        description: If we should be triggering a file download
    responses:
      '200':
        description: Returns the JSON blob for the specified measurement
        schema:
          $ref: "#/definitions/MeasurementBlob"
    """
    if not measurement_id.startswith(FASTPATH_MSM_ID_PREFIX):
        raise BadRequest("No measurement found")

    log = current_app.logger
    tid = measurement_id[len(FASTPATH_MSM_ID_PREFIX) :]
    path = "/measurements/{}.json.lz4".format(tid)
    log.info(
        "Incoming fastpath query %r. Fetching %s:%d%s",
        measurement_id,
        FASTPATH_SERVER,
        FASTPATH_PORT,
        path,
    )
    conn = http.client.HTTPConnection(FASTPATH_SERVER, FASTPATH_PORT)
    conn.request("GET", path)
    r = conn.getresponse()
    log.debug("Response status: %d", r.status)
    try:
        assert r.status == 200
        blob = r.read()
        conn.close()
        log.debug("Decompressing LZ4 data")
        blob = lz4framed.decompress(blob)
        response = make_response(blob)
        response.headers.set("Content-Type", "application/json")
        log.debug("Sending JSON response")
        return response
    except Exception:
        raise BadRequest("No measurement found")




def _merge_results(tmpresults):
    """Trim list_measurements() outputs that share the same report_id/input
    """
    resultsmap = {}
    for r in tmpresults:
        k = (r["report_id"], r["input"])
        if k not in resultsmap:
            resultsmap[k] = r

    return tuple(resultsmap.values())


@api_msm_blueprint.route("/v1/measurements")
def list_measurements():
    """Search for measurements using only the database. Provide pagination.
    ---
    parameters:
      - name: report_id
        in: query
        type: string
        description: The report_id to search measurements for
      - name: input
        in: query
        type: string
        minLength: 3 # `input` is handled by pg_trgm
        description: The input (for example a URL or IP address) to search measurements for
      - name: domain
        in: query
        type: string
        minLength: 3
        description: The domain to search measurements for
      - name: probe_cc
        in: query
        type: string
        description: The two letter country code
      - name: probe_asn
        in: query
        type: string
        description: the Autonomous system number in the format "ASXXX"
      - name: test_name
        in: query
        type: string
        description: The name of the test
        enum:
        - web_connectivity
        - http_requests
        - dns_consistency
        - http_invalid_request_line
        - bridge_reachability
        - tcp_connect
        - http_header_field_manipulation
        - http_host
        - multi_protocol_traceroute
        - meek_fronted_requests_test
        - whatsapp
        - vanilla_tor
        - facebook_messenger
        - ndt
        - dash
        - telegram
        - psiphon
        - tor
      - name: since
        in: query
        type: string
        description: >-
          The start date of when measurements were run (ex.
          "2016-10-20T10:30:00")
      - name: until
        in: query
        type: string
        description: >-
          The end date of when measurement were run (ex.
          "2016-10-20T10:30:00")
      - name: since_index
        in: query
        type: string
        description: Return results only strictly greater than the provided index

      - name: confirmed
        in: query
        type: string
        collectionFormat: csv
        items:
          type: string
        description: |
          Will be true for confirmed network anomalies (we found a blockpage, a middlebox was found, the IM app is blocked, etc.).

      - name: anomaly
        in: query
        type: string
        collectionFormat: csv
        items:
          type: string
        description: |
          Measurements that require special attention (it's likely to be a case of blocking), however it has not necessarily been confirmed

      - name: failure
        in: query
        type: string
        collectionFormat: csv
        items:
          type: string
        description: |
          There was an error in the measurement (the control request failed, there was a bug, etc.).
          Default is to consider it both true or false (`failure=true,false`)

      - name: order_by
        in: query
        type: string
        description: 'By which key the results should be ordered by (default: `null`)'
        enum:
          - test_start_time
          - measurement_start_time
          - input
          - probe_cc
          - probe_asn
          - test_name
      - name: order
        in: query
        type: string
        description: |-
          If the order should be ascending or descending (one of: `asc` or `desc`)
        enum:
          - asc
          - desc
          - ASC
          - DESC
      - name: offset
        in: query
        type: integer
        description: 'Offset into the result set (default: 0)'
      - name: limit
        in: query
        type: integer
        description: 'Number of records to return (default: 100)'
    responses:
      '200':
        description: Returns the list of measurement IDs for the specified criteria
        schema:
          $ref: "#/definitions/MeasurementList"
    """
    # x-code-samples:
    # - lang: 'curl'
    #    source: |
    #    curl "https://api.ooni.io/api/v1/measurements?probe_cc=IT&confirmed=true&since=2017-09-01"
    # TODO: list_measurements and get_measurement will be simplified and
    # made faster by OOID: https://github.com/ooni/pipeline/issues/48
    log = current_app.logger
    param = request.args.get
    report_id = param("report_id")
    probe_asn = param("probe_asn")
    probe_cc = param("probe_cc")
    test_name = param("test_name")
    since = param("since")
    until = param("until")
    since_index = param("since_index")
    order_by = param("order_by")
    order = param("order", "desc")
    offset = int(param("offset", 0))
    limit = int(param("limit", 100))
    failure = param("failure")
    anomaly = param("anomaly")
    confirmed = param("confirmed")
    category_code = param("category_code")

    ## Workaround for https://github.com/ooni/probe/issues/1034
    user_agent = request.headers.get("User-Agent")
    if user_agent.startswith("okhttp"):
        bug_probe1034_response = jsonify(
            {
                "metadata": {
                    "count": 1,
                    "current_page": 1,
                    "limit": 100,
                    "next_url": None,
                    "offset": 0,
                    "pages": 1,
                    "query_time": 0.001,
                },
                "results": [{"measurement_url": ""}],
            }
        )
        return bug_probe1034_response

    ## Prepare query parameters

    input_ = request.args.get("input")
    domain = request.args.get("domain")

    if probe_asn is not None:
        if probe_asn.startswith("AS"):
            probe_asn = probe_asn[2:]
        probe_asn = int(probe_asn)

    # When the user specifies a list that includes all the possible values for
    # boolean arguments, that is logically the same of applying no filtering at
    # all.
    # TODO: treat it as an error?
    if failure is not None:
        if set(failure) == set(["true", "false"]):
            failure = None
        else:
            failure = set(failure) == set(["true"])
    if anomaly is not None:
        if set(anomaly) == set(["true", "false"]):
            anomaly = None
        else:
            anomaly = set(anomaly) == set(["true"])
    if confirmed is not None:
        if set(confirmed) == set(["true", "false"]):
            confirmed = None
        else:
            confirmed = set(confirmed) == set(["true"])

    try:
        if since is not None:
            since = parse_date(since)
    except ValueError:
        raise BadRequest("Invalid since")

    try:
        if until is not None:
            until = parse_date(until)
    except ValueError:
        raise BadRequest("Invalid until")

    if order.lower() not in ("asc", "desc"):
        raise BadRequest("Invalid order")

    INULL = ""  # Special value for input = NULL to merge rows with FULL OUTER JOIN

    ## Create fastpath columns for query
    fpcols = [
        # func.coalesce(0).label("m_input_no"),
        # We use test_start_time here as the batch pipeline has many NULL measurement_start_times
        literal_column("measurement_start_time").label("test_start_time"),
        literal_column("measurement_start_time").label("measurement_start_time"),
        func.concat(FASTPATH_MSM_ID_PREFIX, sql.text("tid")).label("measurement_id"),
        literal_column("anomaly"),
        literal_column("confirmed"),
        literal_column("msm_failure").label("failure"),
        cast(sql.text("scores"), String).label("scores"),
        literal_column("report_id"),
        literal_column("probe_cc"),
        literal_column("probe_asn"),
        literal_column("test_name"),
        func.coalesce(sql.text("fastpath.input"), INULL).label("input"),
    ]

    fpwhere = []
    query_params = {}

    # Populate WHERE clauses and query_params dict

    if since is not None:
        query_params["since"] = since
        fpwhere.append(sql.text("measurement_start_time > :since"))

    if until is not None:
        query_params["until"] = until
        fpwhere.append(sql.text("measurement_start_time <= :until"))

    if report_id:
        query_params["report_id"] = report_id
        fpwhere.append(sql.text("report_id = :report_id"))

    if probe_cc:
        query_params["probe_cc"] = probe_cc
        fpwhere.append(sql.text("probe_cc = :probe_cc"))

    if probe_asn is not None:
        query_params["probe_asn"] = probe_asn
        fpwhere.append(sql.text("probe_asn = :probe_asn"))

    if test_name is not None:
        query_params["test_name"] = test_name
        fpwhere.append(sql.text("test_name = :test_name"))

    # Filter on anomaly, confirmed and failure:
    # The database stores anomaly and confirmed as boolean + NULL and stores
    # failures in different columns. This leads to many possible combinations
    # but only a subset is used.
    # On anomaly and confirmed: any value != TRUE is treated as FALSE
    # See test_list_measurements_filter_flags_fastpath

    if anomaly is True:
        fpwhere.append(sql.text("fastpath.anomaly IS TRUE"))

    elif anomaly is False:
        fpwhere.append(sql.text("fastpath.anomaly IS NOT TRUE"))

    if confirmed is True:
        fpwhere.append(sql.text("fastpath.confirmed IS TRUE"))

    elif confirmed is False:
        fpwhere.append(sql.text("fastpath.confirmed IS NOT TRUE"))

    if failure is True:
        # residual_no is never NULL, msm_failure is always NULL
        fpwhere.append(sql.text("fastpath.msm_failure IS TRUE"))

    elif failure is False:
        # on success measurement.exc is NULL
        fpwhere.append(sql.text("fastpath.msm_failure IS NOT TRUE"))

    fpq_table = sql.table("fastpath")

    if input_ or domain or category_code:
        # join in domain_input
        fpq_table = fpq_table.join(
            sql.table("domain_input"), sql.text("domain_input.input = fastpath.input")
        )

        if input_:
            # input_ overrides domain and category_code
            query_params["input"] = input_
            fpwhere.append(sql.text("domain_input.input = :input"))

        else:
            # both domain and category_code can be set at the same time
            if domain:
                query_params["domain"] = domain
                fpwhere.append(sql.text("domain_input.domain = :domain"))

            if category_code:
                query_params["category_code"] = category_code
                fpq_table = fpq_table.join(
                    sql.table("citizenlab"),
                    sql.text("citizenlab.url = domain_input.input"),
                )
                fpwhere.append(sql.text("citizenlab.category_code = :category_code"))


    # We runs SELECTs on the measurement-report (mr) tables and faspath independently
    # from each other and then merge them.
    # The FULL OUTER JOIN query is using LIMIT and OFFSET based on the
    # list_measurements arguments. To speed up the two nested queries,
    # an ORDER BY + LIMIT on "limit+offset" is applied in each of them to trim
    # away rows that would be removed anyways by the outer query.
    #
    # During a merge we can find that a measurement is:
    # - only in fastpath:       get_measurement will pick the JSON msmt from the fastpath host
    # - in both selects:        pick `scores` from fastpath and the msmt from the can
    # - only in "mr":           the msmt from the can
    #
    # This implements a failover mechanism where new msmts are loaded from fastpath
    # but can fall back to the traditional pipeline.

    fp_query = (
        select(fpcols)
        .where(and_(*fpwhere))
        .select_from(fpq_table)
        .limit(offset + limit)
    )

    if order_by is None:
        # Use test_start_time or measurement_start_time depending on other
        # filters in order to avoid heavy joins.
        # Filtering on anomaly, confirmed, msm_failure -> measurement_start_time
        # Filtering on probe_cc, probe_asn, test_name -> test_start_time
        # See test_list_measurements_slow_order_by_* tests
        if probe_cc or probe_asn or test_name:
            order_by = "test_start_time"
        elif anomaly or confirmed or failure or input_ or domain or category_code:
            order_by = "measurement_start_time"
        else:
            order_by = "measurement_start_time"

    fp_query = fp_query.order_by(text("{} {}".format(order_by, order)))


    #merger = [
    #    coal("test_start_time"),
    #    coal("measurement_start_time"),
    #    func.coalesce(
    #        literal_column("mr.measurement_id"), literal_column("fp.measurement_id")
    #    ).label("measurement_id"),
    #    func.coalesce(literal_column("mr.m_report_no"), 0).label("m_report_no"),
    #    coal("anomaly"),
    #    coal("confirmed"),
    #    coal("failure"),
    #    func.coalesce(literal_column("fp.scores"), "{}").label("scores"),
    #    column("exc"),
    #    func.coalesce(literal_column("mr.residual_no"), 0).label("residual_no"),
    #    coal("report_id"),
    #    coal("probe_cc"),
    #    coal("probe_asn"),
    #    coal("test_name"),
    #    coal("input"),
    #]
    # Assemble the "external" query. Run a final order by followed by limit and
    # offset
    query = fp_query.offset(offset).limit(limit)

    # Run the query, generate the results list
    iter_start_time = time.time()

    try:
        q = current_app.db_session.execute(query, query_params)
        tmpresults = []
        for row in q:
            url = urljoin(
                current_app.config["BASE_URL"],
                "/api/v1/measurement/%s" % row.measurement_id,
            )
            tmpresults.append(
                {
                    "measurement_url": url,
                    "measurement_id": row.measurement_id,
                    "report_id": row.report_id,
                    "probe_cc": row.probe_cc,
                    "probe_asn": "AS{}".format(row.probe_asn),
                    "test_name": row.test_name,
                    "measurement_start_time": row.measurement_start_time,
                    "input": row.input,
                    "anomaly": row.anomaly,
                    "confirmed": row.confirmed,
                    "failure": row.failure,
                    "scores": json.loads(row.scores),
                }
            )
    except OperationalError as exc:
        if isinstance(exc.orig, QueryCanceledError):
            # Timeout due to a slow query. Generate metric and do not feed it
            # to Sentry.
            abort(504)

        raise exc

    # For each report_id / input tuple, we want at most one entry. Measurements
    # from mr_table and fastpath has already been merged by the FULL OUTER JOIN
    # but we have duplicate msmts sharing the same report_id / input.
    results = _merge_results(tmpresults)

    # Replace the special value INULL for "input" with None
    for i, r in enumerate(results):
        if r["input"] == INULL:
            results[i]["input"] = None

    pages = -1
    count = -1
    current_page = math.ceil(offset / limit) + 1

    # We got less results than what we expected, we know the count and that we are done
    if len(results) < limit:
        count = offset + len(results)
        pages = math.ceil(count / limit)
        next_url = None
    else:
        # XXX this is too intensive. find a workaround
        # count_start_time = time.time()
        # count = q.count()
        # pages = math.ceil(count / limit)
        # current_page = math.ceil(offset / limit) + 1
        # query_time += time.time() - count_start_time
        next_args = request.args.to_dict()
        next_args["offset"] = "%s" % (offset + limit)
        next_args["limit"] = "%s" % limit
        next_url = urljoin(
            current_app.config["BASE_URL"],
            "/api/v1/measurements?%s" % urlencode(next_args),
        )

    query_time = time.time() - iter_start_time
    metadata = {
        "offset": offset,
        "limit": limit,
        "count": count,
        "pages": pages,
        "current_page": current_page,
        "next_url": next_url,
        "query_time": query_time,
    }

    return jsonify({"metadata": metadata, "results": results[:limit]})


def _convert_to_csv(r) -> str:
    """Convert aggregation result dict/list to CSV
    """
    csvf = StringIO()
    if isinstance(r, dict):
        # 0-dimensional data
        fieldnames = sorted(r.keys())
        writer = DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(r)

    else:
        fieldnames = sorted(r[0].keys())
        writer = DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for row in r:
            writer.writerow(row)

    result = csvf.getvalue()
    csvf.close()
    return result


yml = "/usr/lib/python3/dist-packages/ooniapi/openapi/measurements.yml"
yml = "/home/fede/projects/ooni-api/newapi/ooniapi/openapi/measurements.yml"
yml = "measurements.yml"


# import Flask
# app = Flask(__name__)
# swagger = Swagger(app)


@api_msm_blueprint.route("/v1/aggregation")
def get_aggregated():
    """Aggregate counters data
    ---
    parameters:
      - name: input
        in: query
        type: string
        minLength: 3
        description: The input (for example a URL or IP address) to search measurements for
      - name: domain
        in: query
        type: string
        minLength: 3
        description: The domain to search measurements for
      - name: category_code
        in: query
        type: string
        description: The category code from the citizenlab list
      - name: probe_cc
        in: query
        type: string
        description: The two letter country code
        minLength: 2
      - name: probe_asn
        in: query
        type: string
        description: the Autonomous system number in the format "ASXXX"
      - name: test_name
        in: query
        type: string
        description: The name of the test
        enum:
        - web_connectivity
        - http_requests
        - dns_consistency
        - http_invalid_request_line
        - bridge_reachability
        - tcp_connect
        - http_header_field_manipulation
        - http_host
        - multi_protocol_traceroute
        - meek_fronted_requests_test
        - whatsapp
        - vanilla_tor
        - facebook_messenger
        - ndt
        - dash
        - telegram
        - psiphon
        - tor
      - name: since
        in: query
        type: string
        description: >-
          The start date of when measurements were run (ex.
          "2016-10-20T10:30:00")
      - name: until
        in: query
        type: string
        description: >-
          The end date of when measurement were run (ex.
          "2016-10-20T10:30:00")
      - name: axis_x
        in: query
        type: string
        description: |
          The dimension on the x axis e.g. measurement_start_day
      - name: axis_y
        in: query
        type: string
        description: |
          The dimension on the y axis e.g. probe_cc
      - name: format
        in: query
        type: string
        description: |
          Output format, JSON (default) or CSV
        enum:
          - JSON
          - CSV
    responses:
      '200':
        description: Returns aggregated counters
    """
    log = current_app.logger
    param = request.args.get
    axis_x = param("axis_x")
    axis_y = param("axis_y")
    category_code = param("category_code")
    domain = param("domain")
    input = param("input")
    test_name = param("test_name")
    probe_asn = param("probe_asn")
    probe_cc = param("probe_cc")
    since = param("since")
    until = param("until")
    format = param("format", "JSON")

    dimension_cnt = int(bool(axis_x)) + int(bool(axis_y))

    cacheable = until and parse_date(until) < datetime.now() - timedelta(hours=72)

    # Assemble query
    def coalsum(name):
        return sql.text("COALESCE(SUM({0}), 0) AS {0}".format(name))

    cols = [
        coalsum("anomaly_count"),
        coalsum("confirmed_count"),
        coalsum("failure_count"),
        coalsum("measurement_count"),
    ]
    table = sql.table("counters")
    where = []
    query_params = {}

    if domain:
        # Join in domain_input table and filter by domain
        table = table.join(
            sql.table("domain_input"), sql.text("counters.input = domain_input.input"),
        )
        where.append(sql.text("domain = :domain"))
        query_params["domain"] = domain

    if category_code:
        # Join in citizenlab table and filter by category_code
        table = table.join(
            sql.table("citizenlab"), sql.text("citizenlab.url = counters.input"),
        )
        where.append(sql.text("category_code = :category_code"))
        query_params["category_code"] = category_code

    if probe_cc:
        where.append(sql.text("probe_cc = :probe_cc"))
        query_params["probe_cc"] = probe_cc

    if probe_asn is not None:
        if probe_asn.startswith("AS"):
            probe_asn = probe_asn[2:]
        probe_asn = int(probe_asn)
        where.append(sql.text("probe_asn = :probe_asn"))
        query_params["probe_asn"] = probe_asn

    if since:
        since = parse_date(since)
        where.append(sql.text("measurement_start_day > :since"))
        query_params["since"] = since

    if until:
        until = parse_date(until)
        where.append(sql.text("measurement_start_day <= :until"))
        query_params["until"] = until

    if axis_x:
        # TODO: check if the value is a valid colum name
        cols.append(column(axis_x))
        if axis_x == "category_code":
            # Join in citizenlab table
            table = table.join(
                sql.table("citizenlab"), sql.text("citizenlab.url = counters.input"),
            )

    if axis_y:
        # TODO: check if the value is a valid colum name
        cols.append(column(axis_y))
        if axis_y == "category_code":
            # Join in citizenlab table
            table = table.join(
                sql.table("citizenlab"), sql.text("citizenlab.url = counters.input"),
            )

    # Assemble query
    where_expr = and_(*where)
    query = select(cols).where(where_expr).select_from(table)

    # Add group-by
    if axis_x:
        query = query.group_by(column(axis_x)).order_by(column(axis_x))

    if axis_y:
        query = query.group_by(column(axis_y)).order_by(column(axis_y))

    try:
        q = current_app.db_session.execute(query, query_params)

        if dimension_cnt == 2:
            r = [dict(row) for row in q]

        elif axis_x or axis_y:
            r = [dict(row) for row in q]

        else:
            r = dict(q.fetchone())

        if format == "CSV":
            return _convert_to_csv(r)

        response = jsonify({"v": 0, "dimension_count": dimension_cnt, "result": r})
        if cacheable:
            response.cache_control.max_age = 3600 * 24
        return response

    except Exception as e:
        return jsonify({"v": 0, "error": str(e)})
