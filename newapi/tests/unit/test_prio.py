from ooniapi import prio


def test_prio():
    cz = {
        "category_code": "MISC",
        "domain": "thehiddenwiki.org",
        "url": "https://thehiddenwiki.org/",
        "cc": "ZZ",
        "msmt_cnt": 38,
    }
    pr = {
        "category_code": "MISC",
        "cc": "US",
        "domain": "*",
        "priority": -200,
        "url": "*",
    }
    assert prio.match_prio_rule(cz, pr)


def test_prio_cc_1():
    cz = {"cc": "ZZ"}
    pr = {"cc": "US"}
    for k in ["category_code", "domain", "url"]:
        cz[k] = pr[k] = ""
    assert prio.match_prio_rule(cz, pr)


def test_prio_cc_2():
    cz = {"cc": "US"}
    pr = {"cc": "US"}
    for k in ["category_code", "domain", "url"]:
        cz[k] = pr[k] = ""
    assert prio.match_prio_rule(cz, pr)


def test_prio_cc_3():
    cz = {"cc": "US"}
    pr = {"cc": "*"}
    for k in ["category_code", "domain", "url"]:
        cz[k] = pr[k] = ""
    assert prio.match_prio_rule(cz, pr)


def test_prio_cc_4():
    cz = {"cc": "US"}
    pr = {"cc": "IE"}
    for k in ["category_code", "domain", "url"]:
        cz[k] = pr[k] = ""
    assert not prio.match_prio_rule(cz, pr)
