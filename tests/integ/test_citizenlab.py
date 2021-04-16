import pytest

from newapi.ooniapi.citizenlab import URLListManager, DuplicateURL

@pytest.fixture()
def url_list_manager(tmpdir, mocker):
    ulm = URLListManager(
        working_dir=tmpdir.strpath,
        ssh_key_path="",
        master_repo="hellais/test-lists",
        push_repo="ooni-bot/test-lists",
        github_token=None
    )
    # We mock out all the calls to github
    mocker.patch.object(ulm, "push_to_repo")
    mocker.patch.object(ulm, "open_pr")
    ulm.open_pr.return_value = "https://api.github.com/repos/example/test-lists/pulls/123"
    mocker.patch.object(ulm, "is_pr_resolved")
    return ulm

def test_add_url_full_workflow(url_list_manager):
    username = "testusername"
    url_list_manager.add(username, "it", [
        "https://apple.com/",
        "FILE",
        "File-sharing",
        "2017-04-12",
        "",
        ""
    ], "add apple.com to italian test list")
    assert url_list_manager.get_state(username) == "IN_PROGRESS"

    url_list_manager.propose_changes(username)
    url_list_manager.push_to_repo.assert_called()
    url_list_manager.open_pr.assert_called()

    assert url_list_manager.get_state(username) == "PR_OPEN"

    url_list_manager.is_pr_resolved.return_value = True
    url_list_manager.get_test_list(username, "global")

    assert url_list_manager.get_state(username) == "CLEAN"

def test_add_duplicate_url(url_list_manager):
    username = "testusername"

    with pytest.raises(DuplicateURL):
        url_list_manager.add(username, "it", [
            "https://www.apple.com/",
            "FILE",
            "File-sharing",
            "2017-04-12",
            "",
            ""
        ], "add apple.com to italian test list")

def test_edit_url(url_list_manager):
    username = "testusername"
    url_list_manager.edit(username, "it", [
        "http://btdigg.org/",
        "FILE",
        "File-sharing",
        "2017-04-12",
        "",
        "Site reported to be blocked by AGCOM - Italian Autority on Communication"
    ], [
        "https://btdigg.org/",
        "FILE",
        "File-sharing",
        "2017-04-12",
        "",
        "Site reported to be blocked by AGCOM - Italian Autority on Communication"
    ], "add https to the website url")
    assert url_list_manager.get_state(username) == "IN_PROGRESS"
