#!/bin/bash
TS=$(date +"%Y-%m")

ASN_URL="https://download.db-ip.com/free/dbip-asn-lite-${TS}.mmdb.gz"
CC_URL="https://download.db-ip.com/free/dbip-country-lite-${TS}.mmdb.gz"

mkdir -p /var/lib/ooniapi/
curl -o /var/lib/ooniapi/asn.mmdb.gz $ASN_URL
gunzip /var/lib/ooniapi/asn.mmdb.gz
curl -o /var/lib/ooniapi/cc.mmdb.gz $CC_URL
gunzip /var/lib/ooniapi/cc.mmdb.gz
