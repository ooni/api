"""
Integration test for Auth API

Warning: this test runs against a real database and SMTP

Lint using:
    black -t py37 -l 100 --fast ooniapi/tests/integ/test_probe_services.py

Test using:
    pytest-3 -s --show-capture=no ooniapi/tests/integ/test_probe_services.py
"""

import os
from unittest.mock import MagicMock, Mock


import pytest

import ooniapi.auth


@pytest.fixture()
def log(app):
    return app.logger


@pytest.fixture(autouse=True, scope="session")
def setup_test_session():
    os.environ["DATABASE_URL"] = "postgresql://readonly@localhost:5432/metadb"
    os.environ["CONF"] = "tests/integ/api.conf"

    # mock smtplib

    m = Mock(name="MockSMTPInstance")
    s = Mock(name="SMTP session")
    x = Mock(name="mock enter", return_value=s)
    m.__enter__ = x
    m.__exit__ = Mock(name="mock exit")
    setup_test_session.mocked_s = s
    ooniapi.auth.smtplib.SMTP = Mock(name="MockSMTP", return_value=m)
    ooniapi.auth.smtplib.SMTP_SSL = MagicMock()


@pytest.fixture()
def mk():
    ooniapi.auth.smtplib.SMTP.reset_mock()
    ooniapi.auth.smtplib.SMTP_SSL.reset_mock()


def postj(client, url, **kw):
    response = client.post(url, json=kw)
    assert response.status_code == 200
    return response


def test_login_user_bogus_token(client, mk):
    r = client.get(f"/api/v1/user_login?k=BOGUS")
    assert r.status_code == 401
    assert r.json == {"error": "Invalid credentials"}


def test_register_user(client, mk):
    d = dict(nickname="", email_address="nick@localhost.local")
    r = client.post("/api/v1/register_user", json=d)
    assert r.status_code == 400
    assert r.json == {"error": "Invalid user name"}

    d = dict(nickname="x", email_address="nick@localhost.local")
    r = client.post("/api/v1/register_user", json=d)
    assert r.status_code == 400
    assert r.json == {"error": "User name is too short"}

    d = dict(nickname="nick", email_address="nick@localhost")
    r = client.post("/api/v1/register_user", json=d)
    assert r.status_code == 400
    assert r.json == {"error": "Invalid email address"}

    d = dict(nickname="nick", email_address="nick@localhost.local")
    r = client.post("/api/v1/register_user", json=d)
    assert r.status_code == 200
    assert r.json == {"msg": "ok"}

    ooniapi.auth.smtplib.SMTP.assert_called_once()
    ooniapi.auth.smtplib.SMTP_SSL.assert_not_called()
    setup_test_session.mocked_s.send_message.assert_called_once()
    msg = setup_test_session.mocked_s.send_message.call_args[0][0]
    msg = str(msg)
    assert "Subject: OONI Account activation" in msg
    for line in msg.splitlines():
        if '<a href="https://api.ooni.io' in line:
            url = line.split('"')[1]
    assert url.startswith("https://api.ooni.io/api/v1/user_login?k=")
    token = url[40:]

    r = client.get(f"/api/v1/user_login?k={token}")
    assert r.status_code == 200
    cookies = r.headers.getlist("Set-Cookie")
    assert len(cookies) == 1
    c = cookies[0]
    assert c.startswith("ooni=")
    assert c.endswith("; Secure; HttpOnly; Path=/; SameSite=Strict")


def test_role_set(client, mk):
    d = dict(email_address="integtest@openobservatory.org", role="admin")
    r = client.post("/api/v1/set_account_role", json=d)
    assert r.status_code == 200

    r = client.get("/api/v1/get_account_role/integtest@openobservatory.org")
    assert r.status_code == 200
    assert r.data == b"admin"

    d = dict(email_address="integtest@openobservatory.org", role="user")
    r = client.post("/api/v1/set_account_role", json=d)
    assert r.status_code == 200
