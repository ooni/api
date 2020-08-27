"""
Integration test for Probe Services API

Warning: this test runs against a real database
See README.adoc

Lint using:
    black -t py37 -l 100 --fast ooniapi/tests/integ/test_probe_services.py

Test using:
    pytest-3 -s --show-capture=no ooniapi/tests/integ/test_probe_services.py
"""

import os
import pytest


@pytest.fixture()
def log(app):
    return app.logger


@pytest.fixture(autouse=True, scope="session")
def setup_database_url():
    os.environ["DATABASE_URL"] = "postgresql://readonly@localhost:5432/metadb"


def gethtml(client, url):
    response = client.get(url)
    assert response.status_code == 200
    assert not response.is_json
    return response.body


def getjson(client, url):
    response = client.get(url)
    assert response.status_code == 200
    assert response.is_json
    return response.json


def test_index(client):
    c = gethtml(client, "/")
    assert "Welcome to" in c


# # Follow the order in ooniapi/probe_services.py


def test_(client):
    c = getjson(client, "/")
    assert True


def test_collectors(client):
    c = getjson(client, "/api/v1/collectors")
    assert len(c) == 6


def test_(client):
    c = post(client, "/api/v1/login")
    assert True


def test_(client):
    c = post(client, "/api/v1/register")
    assert True


def test_test_helpers(client):
    c = getjson(client, "/api/v1/test-helpers")
    assert len(c) == 6


def test_psiphon(client):
    c = getjson(client, "/api/v1/test-list/psiphon-config")
    assert True


def test_tor_targets(client):
    c = getjson(client, "/api/v1/test-list/tor-targets")
    assert True


def test_(client):
    c = getjson(client, "/api/private/v1/wcth")
    assert True


def test_(client):
    c = getjson(client, "/bouncer/net-tests")
    assert True


def test_open_report(client):
    c = post(client, "/report")
    assert True


def test_upload_msmt(client):
    c = post(client, "/report/TestReportID")


def test_close_report(client):
    c = post(client, "/report/TestReportID/close")
    assert True


# Test-list related tests

def test_url_prioritization(client):
    c = getjson(client, "/api/v1/test-list/urls")
    assert "metadata" in c
    assert c["metadata"] == {
        "count": 100,
        "current_page": -1,
        "limit": -1,
        "next_url": "",
        "pages": 1,
    }


def test_url_prioritization_category_code(client):
    c = getjson(client, "/api/v1/test-list/urls?category_code=NEWS")
    assert "metadata" in c
    assert c["metadata"] == {
        "count": 100,
        "current_page": -1,
        "limit": -1,
        "next_url": "",
        "pages": 1,
    }
    for r in c["results"]:
        assert r["category_code"] == "NEWS"


def test_url_prioritization_country_code(client):
    c = getjson(client, "/api/v1/test-list/urls?country_code=US")
    assert "metadata" in c
    assert c["metadata"] == {
        "count": 100,
        "current_page": -1,
        "limit": -1,
        "next_url": "",
        "pages": 1,
    }
    for r in c["results"]:
        assert r["country_code"] in ("XX", "US")
