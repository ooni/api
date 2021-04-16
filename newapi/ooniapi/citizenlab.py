from datetime import datetime
from glob import glob
from urllib.parse import urlparse
import csv
import io
import logging
import os
import re
import shutil

import git
import requests
from filelock import FileLock
from flask import Flask
from requests.auth import HTTPBasicAuth
from werkzeug.exceptions import HTTPException

logging.basicConfig(level=logging.DEBUG)

VALID_URL = regex = re.compile(
    r"^(?:http)s?://"  # http:// or https://
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
    r"(?::\d+)?"  # optional port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)

BAD_CHARS = ["\r", "\n", "\t", "\\"]

CATEGORY_CODES = {
    "ALDR": "Alcohol & Drugs",
    "REL": "Religion",
    "PORN": "Pornography",
    "PROV": "Provocative Attire",
    "POLR": "Political Criticism",
    "HUMR": "Human Rights Issues",
    "ENV": "Environment",
    "MILX": "Terrorism and Militants",
    "HATE": "Hate Speech",
    "NEWS": "News Media",
    "XED": "Sex Education",
    "PUBH": "Public Health",
    "GMB": "Gambling",
    "ANON": "Anonymization and circumvention tools",
    "DATE": "Online Dating",
    "GRP": "Social Networking",
    "LGBT": "LGBT",
    "FILE": "File-sharing",
    "HACK": "Hacking Tools",
    "COMT": "Communication Tools",
    "MMED": "Media sharing",
    "HOST": "Hosting and Blogging Platforms",
    "SRCH": "Search Engines",
    "GAME": "Gaming",
    "CULTR": "Culture",
    "ECON": "Economics",
    "GOVT": "Government",
    "COMM": "E-commerce",
    "CTRL": "Control content",
    "IGO": "Intergovernmental Organizations",
    "MISC": "Miscelaneous content",
}

class DuplicateURL(Exception):
    pass

class ProgressPrinter(git.RemoteProgress):
    def update(self, op_code, cur_count, max_count=None, message=""):
        print(
            op_code,
            cur_count,
            max_count,
            cur_count / (max_count or 100.0),
            message or "NO MESSAGE",
        )


class URLListManager:
    def __init__(self, working_dir, push_repo, master_repo, github_token, ssh_key_path):
        self.working_dir = working_dir
        self.push_repo = push_repo
        self.github_user = push_repo.split("/")[0]
        self.github_token = github_token

        self.master_repo = master_repo
        self.ssh_key_path = ssh_key_path
        self.repo_dir = os.path.join(self.working_dir, "test-lists")

        self.repo = self.init_repo()

    def init_repo(self):
        logging.debug("initializing repo")
        if not os.path.exists(self.repo_dir):
            logging.debug("cloning repo")
            repo = git.Repo.clone_from(
                f"git@github.com:{self.master_repo}.git", self.repo_dir, branch="master"
            )
            repo.create_remote("rworigin", f"git@github.com:{self.push_repo}.git")
        repo = git.Repo(self.repo_dir)
        repo.remotes.origin.pull(progress=ProgressPrinter())
        return repo

    def get_git_env(self):
        return self.repo.git.custom_environment(
            GIT_SSH_COMMAND=f"ssh -i {self.ssh_key_path}"
        )

    def get_user_repo_path(self, username):
        return os.path.join(self.working_dir, "users", username, "test-lists")

    def get_user_statefile_path(self, username):
        return os.path.join(self.working_dir, "users", username, "state")

    def get_user_pr_path(self, username):
        return os.path.join(self.working_dir, "users", username, "pr_id")

    def get_user_branchname(self, username):
        return f"user-contribution/{username}"

    def get_state(self, username):
        """
        Returns the current state of the repo for the given user.

        The possible states are:
        - CLEAN:
            when we are in sync with the current tip of master and no changes have been made
        - IN_PROGRESS:
            when there are some changes in the working tree of the user, but they haven't yet pushed them
        - PR_OPEN:
            when the PR of the user is open on github and it's waiting for being merged
        """
        try:
            with open(self.get_user_statefile_path(username), "r") as in_file:
                return in_file.read()
        except FileNotFoundError:
            return "CLEAN"

    def set_state(self, username, state):
        """
        This will record the current state of the pull request for the user to the statefile.

        The absence of a statefile is an indication of a clean state.
        """
        assert state in ("IN_PROGRESS", "PR_OPEN", "CLEAN")

        logging.debug(f"setting state for {username} to {state}")
        if state == "CLEAN":
            os.remove(self.get_user_statefile_path(username))
            os.remove(self.get_user_pr_path(username))
            return

        with open(self.get_user_statefile_path(username), "w") as out_file:
            out_file.write(state)

    def set_pr_id(self, username, pr_id):
        with open(self.get_user_pr_path(username), "w") as out_file:
            out_file.write(pr_id)

    def get_pr_id(self, username):
        with open(self.get_user_pr_path(username)) as in_file:
            return in_file.read()

    def get_user_repo(self, username):
        repo_path = self.get_user_repo_path(username)
        if not os.path.exists(repo_path):
            print(f"creating {repo_path}")
            self.repo.git.worktree(
                "add", "-b", self.get_user_branchname(username), repo_path
            )
        return git.Repo(repo_path)

    def get_user_lock(self, username):
        lockfile_path = os.path.join(self.working_dir, "users", username, "state.lock")
        return FileLock(lockfile_path, timeout=5)

    def get_test_list(self, username, country_code):
        if not len(country_code) == 2 and not country_code == "global":
            raise Exception("Bad country_code")

        self.sync_state(username)
        self.pull_master_repo()

        repo_path = self.get_user_repo_path(username)
        if not os.path.exists(repo_path):
            repo_path = self.repo_dir

        test_list = []
        path = os.path.join(repo_path, "lists", f"{country_code}.csv")
        with open(path) as tl_file:
            csv_reader = csv.reader(tl_file)
            for line in csv_reader:
                test_list.append(line)
        return test_list

    def is_duplicate_url(self, username, country_code, new_url):
        url_set = set()
        for row in self.get_test_list(username, country_code):
            url = row[0]
            url_set.add(url)
        if country_code != "global":
            for row in self.get_test_list(username, "global"):
                url = row[0]
                url_set.add(url)
        return new_url in url_set

    def pull_master_repo(self):
        self.repo.remotes.origin.pull(progress=ProgressPrinter())

    def sync_state(self, username):
        state = self.get_state(username)

        # If the state is CLEAN or IN_PROGRESS we don't have to do anything
        if state == "CLEAN":
            return
        if state == "IN_PROGRESS":
            return
        if state == "PR_OPEN":
            if self.is_pr_resolved(username):
                shutil.rmtree(self.get_user_repo_path(username))
                self.repo.git.worktree("prune")
                self.repo.delete_head(self.get_user_branchname(username), force=True)

                self.set_state(username, "CLEAN")

    def add(self, username, cc, new_entry, comment):
        self.sync_state(username)
        self.pull_master_repo()

        logging.debug("adding new entry")

        state = self.get_state(username)
        if state in ("PR_OPEN"):
            raise Exception("You cannot edit files while changes are pending")

        repo = self.get_user_repo(username)
        with self.get_user_lock(username):

            filepath = os.path.join(
                self.get_user_repo_path(username), "lists", f"{cc}.csv"
            )

            if self.is_duplicate_url(username, cc, new_entry[0]):
                raise DuplicateURL()

            with open(filepath, "a") as out_file:
                csv_writer = csv.writer(
                    out_file, quoting=csv.QUOTE_MINIMAL, lineterminator="\n"
                )
                csv_writer.writerow(new_entry)
            repo.index.add([filepath])
            repo.index.commit(comment)

            self.set_state(username, "IN_PROGRESS")

    def edit(self, username, cc, old_entry, new_entry, comment):
        self.sync_state(username)
        self.pull_master_repo()

        logging.debug("editing existing entry")

        state = self.get_state(username)
        if state in ("PR_OPEN"):
            raise Exception("You cannot edit the files while changes are pending")

        repo = self.get_user_repo(username)
        with self.get_user_lock(username):

            filepath = os.path.join(
                self.get_user_repo_path(username), "lists", f"{cc}.csv"
            )

            # If the entry we are changing differs from the previously changed
            # entry we need to check if it's already present in the test list
            if new_entry[0] != old_entry[0] and self.is_duplicate_url(
                username, cc, new_entry[0]
            ):
                raise DuplicateURL()

            out_buffer = io.StringIO()
            with open(filepath, "r") as in_file:
                csv_reader = csv.reader(in_file)
                csv_writer = csv.writer(
                    out_buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n"
                )

                found = False
                for row in csv_reader:
                    if row == old_entry:
                        found = True
                        csv_writer.writerow(new_entry)
                    else:
                        csv_writer.writerow(row)
            if not found:
                raise Exception("Could not find the specified row")

            with open(filepath, "w") as out_file:
                out_buffer.seek(0)
                shutil.copyfileobj(out_buffer, out_file)
            repo.index.add([filepath])
            repo.index.commit(comment)

            self.set_state(username, "IN_PROGRESS")

    def open_pr(self, branchname):
        head = f"{self.github_user}:{branchname}"
        logging.debug(f"opening a PR for {head}")

        r = requests.post(
            f"https://api.github.com/repos/{self.master_repo}/pulls",
            auth=HTTPBasicAuth(self.github_user, self.github_token),
            json={
                "head": head,
                "base": "master",
                "title": "Pull requests from the web",
            },
        )
        j = r.json()
        logging.debug(j)
        return j["url"]

    def is_pr_resolved(self, username):
        r = requests.post(
            self.get_pr_id(),
            auth=HTTPBasicAuth(self.github_user, self.github_token),
        )
        j = r.json()
        return j["state"] != "open"

    def push_to_repo(self, username):
        with self.get_git_env():
            self.repo.remotes.rworigin.push(
                self.get_user_branchname(username),
                progress=ProgressPrinter(),
                force=True,
            )

    def propose_changes(self, username):
        with self.get_user_lock(username):
            logging.debug("proposing changes")

            self.push_to_repo(username)

            pr_id = self.open_pr(self.get_user_branchname(username))
            self.set_pr_id(username, pr_id)
            self.set_state(username, "PR_OPEN")


class BadURL(HTTPException):
    code = 400
    description = "Bad URL"


class BadCategoryCode(HTTPException):
    code = 400
    description = "Bad category code"


class BadCategoryDescription(HTTPException):
    code = 400
    description = "Bad category description"


class BadDate(HTTPException):
    code = 400
    description = "Bad date"


def check_url(url):
    if not VALID_URL.match(url):
        raise BadURL()
    elif any([c in url for c in BAD_CHARS]):
        raise BadURL()
    elif url != url.strip():
        raise BadURL()
    elif urlparse(url).path == "":
        raise BadURL()


def validate_entry(entry):
    url, category_code, category_desc, date_str, user, notes = entry
    check_url(url)
    if category_code not in CATEGORY_CODES:
        raise BadCategoryCode()
    if category_desc != CATEGORY_CODES[category_code]:
        raise BadCategoryDescription()
    try:
        if (
            datetime.datetime.strptime(date_str, "%Y-%m-%d").date().isoformat()
            != date_str
        ):
            raise BadDate()
    except:
        raise BadDate()


def get_url_list_manager():
    return URLListManager(
        working_dir=os.path.abspath("working_dir"),
        ssh_key_path=os.path.expanduser("~/.ssh/id_rsa_ooni-bot"),
        master_repo="hellais/test-lists",
        push_repo="ooni-bot/test-lists",
        github_token=github_token,
    )


def get_username():
    return "antani"


app = Flask(__name__)


@app.route("/api/v1/url-submission/test-list/<country_code>", methods=["GET"])
def get_test_list(country_code):
    username = get_username()

    ulm = get_url_list_manager()
    return ulm.get_test_list(username, country_code)


@app.route("/api/v1/url-submission/add-url", methods=["POST"])
def url_submission_add_url():
    """
    parameters:
      - in: body
        name: add new URL
        required: true
        schema:
          type: object
          properties:
            country_code:
              type: string
            comment:
              type: string
            new_entry:
              type: array
    responses:
      '200':
        description: New URL confirmation
        schema:
          type: object
          properties:
            new_entry:
              type: array
    """
    username = get_username()

    ulm = get_url_list_manager()
    validate_entry(request.json["new_entry"])
    ulm.add(
        username=username,
        cc=request.json["country_code"],
        new_entry=request.json["new_entry"],
        comment=request.json["comment"],
    )
    return {"new_entry": request.json["new_entry"]}


@app.route("/api/v1/url-submission/edit-url", methods=["POST"])
def url_submission_edit_url():
    """
    parameters:
      - in: body
        name: add new URL
        required: true
        schema:
          type: object
          properties:
            country_code:
              type: string
            comment:
              type: string
            new_entry:
              type: array
            old_entry:
              type: array
    responses:
      '200':
        description: New URL confirmation
        schema:
          type: object
          properties:
            new_entry:
              type: array
    """
    username = get_username()

    ulm = get_url_list_manager()
    validate_entry(request.json["new_entry"])
    ulm.edit(
        username=username,
        cc=request.json["country_code"],
        old_entry=request.json["old_entry"],
        new_entry=request.json["new_entry"],
        comment=request.json["comment"],
    )
    return {"new_entry": request.json["new_entry"]}


def main():
    with open("GITHUB_TOKEN") as in_file:
        github_token = in_file.read().strip()

    ulm = URLListManager(
        working_dir=os.path.abspath("working_dir"),
        ssh_key_path=os.path.expanduser("~/.ssh/id_rsa_ooni-bot"),
        master_repo="hellais/test-lists",
        push_repo="ooni-bot/test-lists",
        github_token=github_token,
    )

    # test_lists = tlm.get_test_list("antani")
    # pprint(test_lists)
    ulm.add(
        "antani",
        "it",
        ["https://apple.com/", "FILE", "File-sharing", "2017-04-12", "", ""],
        "add apple.com to italian test list",
    )
    ulm.edit(
        "antani",
        "it",
        [
            "http://btdigg.org/",
            "FILE",
            "File-sharing",
            "2017-04-12",
            "",
            "Site reported to be blocked by AGCOM - Italian Autority on Communication",
        ],
        [
            "https://btdigg.org/",
            "FILE",
            "File-sharing",
            "2017-04-12",
            "",
            "Site reported to be blocked by AGCOM - Italian Autority on Communication",
        ],
        "add https to the website url",
    )
    ulm.propose_changes("antani")


if __name__ == "__main__":
    main()
