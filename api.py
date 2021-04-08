import os
import io
import csv

from pprint import pprint

import git
from gitdb import IStream
from git.index.typ import BaseIndexEntry

WORKING_DIR = "working_dir"
REPO_DIR = os.path.join(WORKING_DIR, "test-lists")
REPO_URL = "git@github.com:citizenlab/test-lists.git"

class ProgressPrinter(git.RemoteProgress):
    def update(self, op_code, cur_count, max_count=None, message=""):
        print(op_code, cur_count, max_count, cur_count / (max_count or 100.0), message or "NO MESSAGE")

def clone_repo():
    git.Repo.clone_from(REPO_URL, REPO_DIR, branch="master")

def init_repo():
    if not os.path.exists(REPO_DIR):
        clone_repo()
    repo = git.Repo(REPO_DIR)
    repo.remote().fetch(progress=ProgressPrinter())
    return repo

def blob_to_file(blob):
    tl_bytes = io.BytesIO()
    blob.stream_data(tl_bytes)
    test_list_content = io.TextIOWrapper(tl_bytes, encoding="utf-8")
    test_list_content.seek(0)
    return test_list_content

class TestListManager:
    def __init__(self):
        self.repo = init_repo()

    def get_tree(self, username):
        head = self.repo.heads.master
        # If there is a head with the username it means the user has made some
        # changes, so we need to present the test-list from their branch
        if username in self.repo.heads:
            head = self.repo.heads[username]
        return head.commit.tree

    def get_test_list(self, username):
        test_lists = {}
        tree = self.get_tree(username)
        lists_dir = tree.join("lists")
        for fn in lists_dir.blobs:
            cc = os.path.basename(fn.path).split(".")[0]
            if not len(cc) == 2 and not cc == "global":
                continue
            tl_file = blob_to_file(fn)
            csv_reader = csv.DictReader(tl_file)
            for line in csv_reader:
                test_lists[cc] = test_lists.get(cc, [])
                test_lists[cc].append(dict(line))
        return test_lists

    def add(self, username, cc, new_entry, comment):
        filename = f"lists/{cc}.csv"

        self.repo.create_head(username)
        current_master = self.repo.heads.master.commit

        tl = tree.join(filename)
        tl_string = io.BytesIO()
        csv_reader = csv.reader(blob_to_file(tl))
        csv_writer = csv.writer(tl_string, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
        for row in csv_reader:
            csv_writer.writerow(row)
        csv_writer.writerow(new_entry)

        tl_string_len = tl_string.tell()
        tl_string.seek(0)
        tl_bytes = io.BytesIO(tl_string.read().encode("utf-8"))
        new_blob = self.repo.odb.store(IStream("blob", tl_string_len, tl_bytes))
        entry = BaseIndexEntry((0o100644, new_blob.binsha, 0, filename))
        index = git.IndexFile.from_tree(self.repo, self.repo.heads[username].commit.tree)
        index.add([entry])
        index.write()
        new_commit = index.commit(comment)
        self.repo.heads[username].commit = new_commit
        self.repo.heads.master.commit = current_master

def main():
    tlm = TestListManager()
    #test_lists = tlm.get_test_list("antani")
    #pprint(test_lists)
    tlm.add("antani", "it", [
        "https://apple.com/",
        "FILE",
        "File-sharing",
        "2017-04-12",
        ""
        ""
    ], "this is a comment")

if __name__ == "__main__":
    main()
