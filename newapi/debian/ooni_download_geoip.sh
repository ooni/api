#!/bin/bash
TS=$(date +"%Y-%m")

CURRENT_TS=$(cat /var/lib/ooniapi/geoipdbts)
if [ "$CURRENT_TS" = "$TS" ];then
    echo "Already the latest. Skipping"
    exit 0
fi

ASN_URL="https://download.db-ip.com/free/dbip-asn-lite-${TS}.mmdb.gz"
CC_URL="https://download.db-ip.com/free/dbip-country-lite-${TS}.mmdb.gz"

ASN_STATUS=$(curl -s -o /dev/null -I -w "%{http_code}" ${ASN_URL})
if [ "$ASN_STATUS" != "200" ];then
    echo "$ASN_URL hasn't been updated yet"
    # We exit with 0 to avoid systemd thinking the unit has failed
    exit 0
fi

CC_STATUS=$(curl -s -o /dev/null -I -w "%{http_code}" ${CC_URL})
if [ "$CC_STATUS" != "200" ];then
    echo "$CC_URL hasn't been updated yet"
    # We exit with 0 to avoid systemd thinking the unit has failed
    exit 0
fi

mkdir -p /var/lib/ooniapi/
curl -o /var/lib/ooniapi/asn.mmdb.gz ${ASN_URL}
gunzip /var/lib/ooniapi/asn.mmdb.gz
curl -o /var/lib/ooniapi/cc.mmdb.gz ${CC_URL}
gunzip /var/lib/ooniapi/cc.mmdb.gz
echo $TS > /var/lib/ooniapi/geoipdbts
