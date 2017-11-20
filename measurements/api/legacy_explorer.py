'''
prefix: /api/legacy_explorer

That's legacy API for old version of OONI Explorer that mimics (and replaces)
API at http://explorer.ooni.torproject.org/api/. That's a hack, don't use it.
This API will eventually be refactored & split across private.py and public API.
'''

import json
import itertools

from flask import Blueprint, current_app, request
from flask.json import jsonify
from sqlalchemy import func # , or_, and_, false, true

from measurements.models import Report, Input, Measurement, Autoclaved
from measurements.api.measurements import fetch_autoclaved_text

# prefix: /api/legacy_explorer
api_legacy_explorer_blueprint = Blueprint('api_legacy_explorer', 'measurements')

## $ <access_log grep 'GET.*HTTP/' | sed 's,.*GET ,,; s,[? ].*,,' | grep ^/api | sort | uniq -c
##      1 /api/countries
##    757 /api/countries/findOne
##    992 /api/nettests
##  13829 /api/nettests/findOne
##  88191 /api/reports
##  18663 /api/reports/asnName
##   1065 /api/reports/blockpageCount
##     35 /api/reports/blockpageDetected
##   1760 /api/reports/blockpageList
##   1111 /api/reports/count
##    973 /api/reports/countByCountry
##     26 /api/reports/total
##   2899 /api/reports/vendors
##   2071 /api/reports/websiteDetails
##   2446 /api/reports/websiteMeasurements

## Something that has data:
## https://explorer.ooni.torproject.org/api/reports/vendors?probe_cc=DE

GOOD_REPORTS_ORDER = set('{} {}'.format(*t) for t in itertools.product(
        ('input', 'probe_asn', 'probe_cc', 'test_name', 'test_start_time'),
        ('ASC', 'DESC')))

## {"test_start_time":{"between":["",""]}}
## {"test_start_time":{"between":["",""]}}
@api_legacy_explorer_blueprint.route('/reports')
def reports():
    print(request.args)
    filter_ = json.loads(request.args.get('filter'))

    known_fields = {
        'id': (Report.report_id.label('id'),), # XXX: this API is imperfect, `id` ~ Measurement.id in json
        'input': (Input.input,),
        'probe_asn': (func.concat('AS', Report.probe_asn).label('probe_asn'),),
        'probe_cc': (Report.probe_cc,),
        'test_name': (Report.test_name,), # FIXME: OOTEST ENUM is doomed
        'test_start_time': (Report.test_start_time,), # XXX: datetime formatting may differ a bit
        'test_keys': (Autoclaved.filename.label('filename'),
            Measurement.frame_off, Measurement.frame_size,
            Measurement.intra_off, Measurement.intra_size)
    }

    # default is "everything from raw json + fields that are formatted differently"
    fields = filter_.pop('fields', {'test_keys', 'id', 'probe_asn'})
    try:
        entities = sum((known_fields[k] for k in fields), ())
    except KeyError:
        raise BadRequest('Unknown field in `fields`')

    q = (current_app.db_session.query(*entities)
            .select_from(Measurement)
            .join(Report, Report.report_no == Measurement.report_no)
            .join(Autoclaved, Autoclaved.autoclaved_no == Report.autoclaved_no)
            .outerjoin(Input, Measurement.input_no == Input.input_no))

    where = filter_.pop('where', {})
    if not isinstance(where, dict):
        raise BadRequest('`filter.where` must be dict')
    if 'probe_cc' in where:
        q = q.filter(Report.probe_cc == str(where.pop('probe_cc')))
    if 'input' in where:
        input_ = where.pop('input')
        if isinstance(input_, dict) and input_.keys() == {'like'}:
            q = q.filter(Input.input.like(input_['like']))
        elif isinstance(input_, str):
            q = q.filter(Input.input.like('%{}%'.format(input_))) # %-injection
        elif isinstance(input_, bool):
            pass # WTF is `"input": true` filter? There are ~6 requests like that
        else:
            raise BadRequest('Invalid `filter.where.input`')
    if 'id' in where:
        q = q.filter(Report.report_id == str(where.pop('id')))
    if 'test_name' in where:
        q = q.filter(Report.test_name == str(where.pop('test_name'))) # FIXME: works only for well-known test names
    if isinstance(where.get('test_start_time'), dict) and where['test_start_time'].keys() == {'between'}:
        since, until = where.pop('test_start_time')['between']
        q = q.filter(Measurement.measurement_start_time > since)
        q = q.filter(Measurement.measurement_start_time <= until)
    if where:
        raise BadRequest('Unknown keys in filter.where', where.keys())

    if filter_.get('order') in GOOD_REPORTS_ORDER:
        q = q.order_by(filter_.pop('order'))

    if 'limit' in filter_:
        limit = int(filter_.pop('limit'))
        if limit > 200: # 150 is max found in access.log for ~ half a year
            raise BadRequest('Huge `limit`')
        q = q.limit(limit)
    else:
        raise BadRequest('No `limit`') # current code does not produce alike queries
    if 'offset' in filter_:
        q = q.offset(int(filter_.pop('offset')))

    if filter_:
        raise BadRequest('Unknown field in `filter` arg')

    # FIXME: single-threaded fetching 150 measurements without a cache and
    # keep-alive over a https link with 300ms RTT may be kinda slow :-) Local
    # HTTP cache should be used for that.
    ret = []
    for msm in q:
        print(msm)
        doc = {}
        if 'test_keys' in fields:
            doc = json.loads(str(fetch_autoclaved_text(
                msm.filename, msm.frame_off, msm.frame_size, msm.intra_off, msm.intra_size),
                'utf-8'))
        for k in fields:
            if k != 'test_keys':
                doc[k] = getattr(msm, k)
        ret.append(doc)
    return jsonify(ret)
