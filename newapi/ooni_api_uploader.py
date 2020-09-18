#!/usr/bin/env python3
"""
Uploads OONI API measurements to S3
Reads /etc/ooni/api.conf
"""

from configparser import ConfigParser
from pathlib import Path
from datetime import datetime, timedelta
import tarfile
import logging
import sys

import statsd  # debdeps: python3-statsd
from systemd.journal import JournalHandler  # debdeps: python3-systemd
import boto3

metrics = statsd.StatsClient("127.0.0.1", 8125, prefix="ooni_api_uploader")
log = logging.getLogger("ooni_api_uploader")
log.addHandler(JournalHandler(SYSLOG_IDENTIFIER="ooni_api_uploader"))
log.setLevel(logging.DEBUG)


def create_s3_client(conf):
    session = boto3.Session(
        aws_access_key_id=conf.get("aws_access_key_id"),
        aws_secret_access_key=conf.get("aws_secret_access_key"),
    )
    return session.resource("s3")


def read_conf():
    cf = "/etc/ooni/api-uploader.conf"
    log.info(f"Starting. Reading {cf}")
    conf = ConfigParser()
    conf.read(cf)
    return conf["DEFAULT"]


@metrics.timer("upload_measurement")
def upload_minican(s3, bucket_name, tarf, s3path):
    obj = s3.Object(bucket_name, s3path)
    log.info(f"Uploading {s3path}")
    obj.put(Body=tarf.read_bytes())


@metrics.timer("total_run_time")
def main():
    conf = read_conf()
    bucket_name = conf.get("bucket_name")
    spooldir = Path(conf.get("msmt_spool_dir"))
    log.info(f"Using bucket {bucket_name} and spool {spooldir}")

    s3 = create_s3_client(conf)
    bucket = s3.Bucket(bucket_name)

    # Scan spool directories, by age
    idir = spooldir / "incoming"
    threshold = datetime.utcnow() - timedelta(hours=1)
    minican_byte_thresh = 10 * 1000 * 1000
    for hourdir in sorted(idir.iterdir()):
        if not hourdir.is_dir() or hourdir.suffix == ".tmp":
            continue
        try:
            tstamp, cc, testname = hourdir.name.split("_")
        except:
            continue
        if len(tstamp) != 10:
            continue
        hourdir_time = datetime.strptime(tstamp, "%Y%m%d%H")
        if hourdir_time > threshold:
            log.info(f"Stopping before {hourdir_time}")
            break

        tarf = hourdir.with_suffix(".tar.gz")
        s3path = f"raw/{tstamp[:8]}/{tstamp[8:10]}/{cc}/{testname}/{tarf.name}"
        log.info(f"Processing {hourdir}")
        tmphourdir = hourdir.with_suffix(".tmp")
        try:
            hourdir.rename(tmphourdir)
        except FileNotFoundError:
            log.info("Race at {hourdir} - ignoring it")
            continue

        metrics.incr("tarball_count")
        with tarfile.open(str(tarf), "w") as tar:
            for msmt_f in sorted(tmphourdir.iterdir()):
                tar.add(str(msmt_f))
                tarsize = tarf.stat().st_size
                # log.info(tarsize > minican_byte_thresh)
                metrics.incr("msmt_count")

        upload_minican(s3, bucket_name, tarf, s3path)
        for msmt_f in sorted(tmphourdir.iterdir()):
            msmt_f.unlink()
        tarf.unlink()

    log.info("Exiting")


if __name__ == "__main__":
    main()
