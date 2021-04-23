"""
Integration test for Citizenlab API

Warning: this test runs against a real database and SMTP

Lint using Black.

Test using:
    pytest-3 -s --show-capture=no ooniapi/tests/integ/test_citizenlab.py
"""

import pytest
# debdeps: python3-pytest-mock

from ooniapi.citizenlab import URLListManager, DuplicateURL

from .test_integration_auth import setup_test_session, _register_and_login


#@pytest.fixture(autouse=True, scope="session")
@pytest.fixture
def usersession(client):
    # Mock out SMTP, register a user and log in
    user_e = "nick@localhost.local"
    cookh = _register_and_login(client, user_e)
    return cookh


def test_list_global(client, usersession):
    r = client.get("/api/v1/url-submission/test-list/global")
    assert r.status_code == 200


#@pytest.fixture()
#def url_list_manager(tmpdir, mocker):
#    ulm = URLListManager(
#        working_dir=tmpdir.strpath,
#        origin_repo="hellais/test-lists",
#        push_repo="ooni-bot/test-lists",
#        github_token=None,
#    )
#    # We mock out all the calls to github
#    mocker.patch.object(ulm, "push_to_repo")
#    mocker.patch.object(ulm, "open_pr")
#    ulm.open_pr.return_value = (
#        "https://api.github.com/repos/example/test-lists/pulls/123"
#    )
#    mocker.patch.object(ulm, "is_pr_resolved")
#    return ulm
#
#
#def test_add_url_full_workflow(url_list_manager):
#    username = "testusername"
#    url_list_manager.add(
#        username,
#        "it",
#        ["https://apple.com/", "FILE", "File-sharing", "2017-04-12", "", ""],
#        "add apple.com to italian test list",
#    )
#    assert url_list_manager.get_state(username) == "IN_PROGRESS"
#
#    url_list_manager.propose_changes(username)
#    url_list_manager.push_to_repo.assert_called()
#    url_list_manager.open_pr.assert_called()
#
#    assert url_list_manager.get_state(username) == "PR_OPEN"
#
#    url_list_manager.is_pr_resolved.return_value = True
#    url_list_manager.get_test_list(username, "global")
#
#    assert url_list_manager.get_state(username) == "CLEAN"
#
#
#def test_add_duplicate_url(url_list_manager):
#    username = "testusername"
#
#    with pytest.raises(DuplicateURL):
#        url_list_manager.add(
#            username,
#            "it",
#            ["https://www.apple.com/", "FILE", "File-sharing", "2017-04-12", "", ""],
#            "add apple.com to italian test list",
#        )
#
#
#def test_edit_url(url_list_manager):
#    username = "testusername"
#    url_list_manager.edit(
#        username,
#        "it",
#        [
#            "http://btdigg.org/",
#            "FILE",
#            "File-sharing",
#            "2017-04-12",
#            "",
#            "Site reported to be blocked by AGCOM - Italian Autority on Communication",
#        ],
#        [
#            "https://btdigg.org/",
#            "FILE",
#            "File-sharing",
#            "2017-04-12",
#            "",
#            "Site reported to be blocked by AGCOM - Italian Autority on Communication",
#        ],
#        "add https to the website url",
#    )
#    assert url_list_manager.get_state(username) == "IN_PROGRESS"
#