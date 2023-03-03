from unittest.mock import Mock, create_autospec, call
from pathlib import Path

import pytest  # debdeps: python3-pytest

import ooni_api_uploader as up


@pytest.fixture(autouse=True, scope="session")
def mock_everything():
    up.metrics = Mock()
    up.Clickhouse = create_autospec(up.Clickhouse)
    up.boto3 = create_autospec(up.boto3)
    up.gzip = create_autospec(up.gzip)
    up.tarfile = create_autospec(up.tarfile)
    pass


def test_fill_postcan_empty():
    hourdir = Mock()
    hourdir.iterdir.return_value = []
    postcanf = Mock()
    li = up.fill_postcan(hourdir, postcanf)
    assert not li
    assert not postcanf.called


def test_fill_postcan():
    hourdir = Mock()
    post = create_autospec(Path)
    post.suffix = ".post"
    post.open.return_value.read.return_value = """{
        "format": "json",}"""

    post2 = create_autospec(Path)
    hourdir.iterdir.return_value = [post, post2]
    up.tarfile.open.return_value.__enter__ = Mock()
    postcanf = Mock()
    postcanf.name = "bogus_tarball"
    postcanf.stat.return_value.st_size = 99999999  # full tar after one .post
    li = up.fill_postcan(hourdir, postcanf)
    assert li == [post]  # the first file is here


def test_fill_jsonl():
    jf = Mock()
    up.gzip.open.return_value.__enter__ = Mock(return_value=jf)
    up.gzip.open.return_value.__exit__ = Mock()

    post = create_autospec(Path)
    post.name = "bogus_post_filename.post"
    post.open.return_value.read.return_value = """{
        "format": "json",
        "content": {
            "report_id": "bogus_rid",
            "input": "bogus_input"
        }
    }
    """
    post_files = [post]
    out_file = Path("/tmp/out.jsonl")
    lookup_list = up.fill_jsonl(post_files, out_file)
    assert jf.write.call_args_list == [
        call(b'{"report_id":"bogus_rid","input":"bogus_input"}'),
        call(b"\n"),
    ]

    assert lookup_list == [
        {
            "input": "bogus_input",
            "linenum": 0,
            "measurement_uid": "bogus_post_filename",
            "report_id": "bogus_rid",
        }
    ]


def test_fill_jsonl_meek():
    jf = Mock()
    up.gzip.open.return_value.__enter__ = Mock(return_value=jf)
    up.gzip.open.return_value.__exit__ = Mock()

    post = create_autospec(Path)
    post.name = "bogus_post_filename.post"
    post.open.return_value.read.return_value = """{
        "format": "json",
        "content": {
            "report_id": "bogus_rid",
            "input": ["bogus_input", "bogus_input_2"]
        }
    }
    """
    post_files = [post]
    out_file = Path("/tmp/out.jsonl")
    lookup_list = up.fill_jsonl(post_files, out_file)
    assert jf.write.call_args_list != [
        call(b'{"report_id":"bogus_rid","input":"bogus_input"}'),
        call(b"\n"),
    ]

    assert lookup_list == [
        {
            "input": ["bogus_input", "bogus_input_2"],
            "linenum": 0,
            "measurement_uid": "bogus_post_filename",
            "report_id": "bogus_rid",
        }
    ]


def test_update_db_table():
    click = up.Clickhouse("localhost")
    lookup_list = [
        {
            "input": "bogus_input",
            "linenum": 0,
            "measurement_uid": "bogus_post_filename",
            "report_id": "bogus_rid",
        }
    ]
    jsonl_s3path = "raw/bogus.jsonl"
    up.serialize_iterable_inputs(lookup_list)
    up.update_db_table(click, lookup_list, jsonl_s3path)

    click.execute.assert_called_with(
        "INSERT INTO jsonl (report_id, input, s3path, linenum, measurement_uid) VALUES",
        [
            {
                "input": "bogus_input",
                "linenum": 0,
                "measurement_uid": "bogus_post_filename",
                "report_id": "bogus_rid",
                "s3path": "raw/bogus.jsonl",
            }
        ],
    ), click.execute.call_args_list


def test_update_db_table_meek():
    click = up.Clickhouse("localhost")
    lookup_list = [
        {
            "input": ["bogus_input", "bogus_input_2"],
            "linenum": 0,
            "measurement_uid": "bogus_post_filename",
            "report_id": "bogus_rid",
        }
    ]
    jsonl_s3path = "raw/bogus.jsonl"
    up.serialize_iterable_inputs(lookup_list)
    up.update_db_table(click, lookup_list, jsonl_s3path)

    click.execute.assert_called_with(
        "INSERT INTO jsonl (report_id, input, s3path, linenum, measurement_uid) VALUES",
        [
            {
                "input": "bogus_input|bogus_input_2",
                "linenum": 0,
                "measurement_uid": "bogus_post_filename",
                "report_id": "bogus_rid",
                "s3path": "raw/bogus.jsonl",
            }
        ],
    ), click.execute.call_args_list
