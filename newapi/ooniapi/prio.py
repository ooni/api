"""
OONI Probe Services API - URL prioritization
"""

from typing import List
import random
import time

from flask import Blueprint, current_app, request
from flask.json import jsonify

from ooniapi.config import metrics

prio_bp = Blueprint("prio", "probe_services_prio")

# TODO  add unit tests

failover_test_items = {}


# # failover algorithm


@metrics.timer("fetch_citizenlab_data")
def fetch_citizenlab_data():
    """Fetch the citizenlab table from the database"""
    log = current_app.logger
    log.info("Started fetch_citizenlab_data")

    log.info("Regenerating URL prioritization file")
    sql = """SELECT priority, domain, url, cc, category_code FROM citizenlab"""
    q = current_app.db_session.execute(sql)
    entries = list(q.fetchall())

    # Create dict: cc -> category_code -> [entry, ... ]
    entries_by_country = {}
    for e in entries:
        country = e["cc"].upper()
        if country not in entries_by_country:
            entries_by_country[country] = {}
        ccode = e["category_code"]
        entries_by_country[country].setdefault(ccode, []).append(e)

    # Merge ZZ into each country, so that "global" urls are given out to probes
    # from every country. Also keep ZZ as valid cc in case a probe requests it
    zz = entries_by_country["ZZ"]
    for ccode, country_dict in entries_by_country.items():
        for category_code, prio_test_items in zz.items():
            country_dict.setdefault(category_code, []).extend(prio_test_items)

    log.info("Update done: %d" % len(entries_by_country))
    return entries_by_country


def algo_chao(s: List, k: int) -> List:
    """Chao weighted random sampling"""
    n = len(s)
    assert len(s) >= k
    wsum = 0
    r = s[:k]
    assert len(r) == k
    for i in range(0, n):
        wsum = wsum + s[i]["priority"]
        if i < k:
            continue
        p = s[i]["priority"] / wsum  # probability for this item
        j = random.random()
        if j <= p:
            pos = random.randint(0, k - 1)
            r[pos] = s[i]

    return r


def failover_generate_test_list(country_code: str, category_codes: tuple, limit: int):
    global failover_test_items
    log = current_app.logger
    candidates_d = failover_test_items[
        country_code
    ]  # category_code -> [test_item, ... ]

    if not category_codes:
        category_codes = candidates_d.keys()

    candidates = []
    for ccode in category_codes:
        s = candidates_d.get(ccode, [])
        candidates.extend(s)

    log.info("%d candidates", len(candidates))

    limit = min(limit, len(candidates))
    selected = algo_chao(candidates, limit)

    out = []
    for entry in selected:
        cc = "XX" if entry["cc"] == "ZZ" else entry["cc"].upper()
        out.append(
            {
                "category_code": entry["category_code"],
                "url": entry["url"],
                "country_code": cc,
            }
        )
    return out


# # reactive algorithm


@metrics.timer("fetch_reactive_url_list")
def fetch_reactive_url_list(cc: str):
    """Fetch test URL from the citizenlab table in the database
    weighted by the amount of measurements in the last N days
    """
    log = current_app.logger
    log.info("Started fetch_reactive_url_list")

    sql = """
SELECT category_code, url, cc
FROM (
    SELECT priority, url, cc, category_code
    FROM citizenlab
    WHERE
      UPPER(citizenlab.cc) = :cc
      OR citizenlab.cc = 'ZZ'
) AS citiz
LEFT OUTER JOIN (
    SELECT input, SUM(measurement_count) AS msmt_cnt
    FROM counters
    WHERE
        measurement_start_day < CURRENT_DATE + interval '1 days'
        AND measurement_start_day > CURRENT_DATE - interval '8 days'
        AND probe_cc = :cc
        AND test_name = 'web_connectivity'
    GROUP BY input
) AS cnt
ON (citiz.url = cnt.input)
ORDER BY COALESCE(msmt_cnt, 0)::float / GREATEST(priority, 1)
"""
    q = current_app.db_session.execute(sql, dict(cc=cc))
    entries = tuple(q.fetchall())
    log.info("%d entries", len(entries))
    return entries


@metrics.timer("generate_test_list")
def generate_test_list(country_code: str, category_codes: tuple, limit: int):
    """
    """
    log = current_app.logger
    out = []
    li = fetch_reactive_url_list(country_code)
    for entry in li:
        if category_codes and entry["category_code"] not in category_codes:
            continue

        cc = "XX" if entry["cc"] == "ZZ" else entry["cc"].upper()
        out.append(
            {
                "category_code": entry["category_code"],
                "url": entry["url"],
                "country_code": cc,
            }
        )
        if len(out) >= limit:
            break

    return out


# # API entry point


@prio_bp.route("/api/v1/test-list/urls")
def list_test_urls():
    """Generate test URL list with prioritization
    https://orchestrate.ooni.io/api/v1/test-list/urls?country_code=IT
    ---
    parameters:
      - name: country_code
        in: query
        type: string
        description: Two letter, uppercase country code
      - name: category_code
        in: query
        type: string
        description: Comma separated list of URL categories, all uppercase
    responses:
      '200':
        description: URL test list
    """
    global failover_test_items
    if failover_test_items == {}:  # initialize once
        failover_test_items = fetch_citizenlab_data()

    log = current_app.logger
    param = request.args.get
    try:
        country_code = (param("country_code") or "ZZ").upper()
        category_codes = param("category_code") or ""
        category_codes = set(c.strip().upper() for c in category_codes.split(","))
        category_codes.discard("")
        category_codes = tuple(category_codes)
        limit = int(param("limit") or -1)
        if limit == -1:
            limit = 100
    except Exception as e:
        log.error(e, exc_info=1)
        return jsonify({})

    try:
        test_items = generate_test_list(country_code, category_codes, limit)
    except Exception as e:
        log.error(e, exc_info=1)
        # failover_generate_test_list runs without any database interaction
        test_items = failover_generate_test_list(country_code, category_codes, limit)

    out = {
        "metadata": {
            "count": len(test_items),
            "current_page": -1,
            "limit": -1,
            "next_url": "",
            "pages": 1,
        },
        "results": test_items,
    }
    return jsonify(out)
