"""
Integration test for Citizenlab API

Warning: this test runs against GitHub and opens PRs

Warning: writes git repos on disk

Lint using Black.

Test using:
    pytest-3 -s --show-capture=no ooniapi/tests/integ/test_citizenlab.py
"""

import os

import pytest

# debdeps: python3-pytest-mock

from ooniapi.citizenlab import URLListManager, DuplicateURL
import ooniapi.citizenlab

from .test_integration_auth import setup_test_session, _register_and_login
from .test_integration_auth import reset_smtp_mock


@pytest.fixture
def usersession(client):
    # Mock out SMTP, register a user and log in
    user_e = "nick@localhost.local"
    _register_and_login(client, user_e)
    reset_smtp_mock()
    yield
    reset_smtp_mock()


def test_no_auth(client):
    r = client.get("/api/v1/url-submission/test-list/global")
    assert r.status_code == 401


def list_global(client, usersession):
    r = client.get("/api/v1/url-submission/test-list/global")
    assert r.status_code == 200
    assert r.json[0] == [
        "url",
        "category_code",
        "category_description",
        "date_added",
        "source",
        "notes",
    ]
    assert len(r.json) > 1000


def add_url(client, usersession):
    d = dict(
        country_code="US",
        new_entry=[
            "https://www.example.com/",
            "FILE",
            "File-sharing",
            "2017-04-12",
            "",
            "",
        ],
        comment="add example URL",
    )

    r = client.post("/api/v1/url-submission/add-url", json=d)
    assert r.status_code == 200, r.data


def test_update_url_reject(client, usersession):
    d = dict(
        country_code="it",
        old_entry=[
            "http://btdigg.org/",
            "FILE",
            "File-sharing",
            "2017-04-12",
            "",
            "<bogus value not matching anything>",
        ],
        new_entry=[
            "https://btdigg.org/",
            "FILE",
            "File-sharing",
            "2017-04-12",
            "",
            "Meow",
        ],
        comment="add HTTPS to the website url",
    )
    r = client.post("/api/v1/url-submission/update-url", json=d)
    assert r.status_code == 400, r.data


def test_update_url_nochange(client, usersession):
    r = client.get("/api/v1/url-submission/test-list/it")
    assert r.status_code == 200

    old = r.json[1]  # first entry, skip header
    new = old
    d = dict(country_code="it", old_entry=old, new_entry=new, comment="")
    r = client.post("/api/v1/url-submission/update-url", json=d)
    assert r.status_code == 400, r.data
    assert b"No change is" in r.data


# TODO reset git
# TODO open PR
def update_url_basic(client, usersession):
    r = client.get("/api/v1/url-submission/test-list/it")
    assert r.status_code == 200

    old = r.json[1]  # first entry, skip header
    new = list(old)
    new[-1] = "Bogus comment"
    assert new != old
    d = dict(country_code="it", old_entry=old, new_entry=new, comment="")
    r = client.post("/api/v1/url-submission/update-url", json=d)
    assert r.status_code == 200, r.data

    assert get_status(client) == "IN_PROGRESS"


def get_status(client):
    r = client.get("/api/v1/url-submission/state")
    assert r.status_code == 200
    return r.data.decode()


def test_pr_state(client, usersession):
    assert get_status(client) == "CLEAN"


# # Tests with mocked-out GitHub # #


class MK:
    @staticmethod
    def json():  # mock both openin a pr or checking its status
        return {"state": "closed", "url": "testurl"}


@pytest.fixture
def mock_requests(monkeypatch):
    def req(*a, **kw):
        print(a)
        print(kw)
        return MK()

    def push(*a, **kw):
        print(a)
        print(kw)
        return MK()

    monkeypatch.setattr(ooniapi.citizenlab.URLListManager, "push_to_repo", push)
    monkeypatch.setattr(ooniapi.citizenlab.requests, "post", req)


@pytest.fixture
def clean_workdir(app, tmp_path):
    with app.app_context():
        assert app
        conf = ooniapi.citizenlab.current_app.config
        assert conf
        conf["GITHUB_WORKDIR"] = tmp_path.as_posix()


def test_checkout_update_submit(clean_workdir, client, usersession, mock_requests):
    assert get_status(client) == "CLEAN"

    list_global(client, usersession)
    assert get_status(client) == "CLEAN"

    add_url(client, usersession)
    assert get_status(client) == "IN_PROGRESS"

    update_url_basic(client, usersession)

    r = client.post("/api/v1/url-submission/submit")
    assert r.status_code == 200

    assert get_status(client) == "PR_OPEN"

    # Before getting the list URLListManager will check if the PR is done
    # (it is) and set the state to CLEAN
    list_global(client, usersession)
    assert get_status(client) == "CLEAN"


# # Tests with real GitHub # #


@pytest.mark.skipif(not pytest.config.option.ghpr, reason="use --ghpr to run")
def test_ghpr_checkout_update_submit(clean_workdir, client, usersession):
    assert get_status(client) == "CLEAN"

    list_global(client, usersession)
    assert get_status(client) == "CLEAN"

    add_url(client, usersession)
    assert get_status(client) == "IN_PROGRESS"

    update_url_basic(client, usersession)

    r = client.post("/api/v1/url-submission/submit")
    assert r.status_code == 200

    assert get_status(client) == "PR_OPEN"

    list_global(client, usersession)
    assert get_status(client) == "PR_OPEN"
