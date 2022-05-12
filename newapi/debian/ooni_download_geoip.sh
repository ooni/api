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
    echo "$ASN_URL hasn't been updated yet" | systemd-cat -t ooniapi-geoip
    # We exit with 0 to avoid systemd thinking the unit has failed
    exit 0
fi

CC_STATUS=$(curl -s -o /dev/null -I -w "%{http_code}" ${CC_URL})
if [ "$CC_STATUS" != "200" ];then
    echo "$CC_URL hasn't been updated yet"
    echo "$CC_URL hasn't been updated yet" | systemd-cat -t ooniapi-geoip
    # We exit with 0 to avoid systemd thinking the unit has failed
    exit 0
fi

mkdir -p /var/lib/ooniapi/

echo "Updating GeoIP database from $CC_URL $ASN_URL" | systemd-cat -t ooniapi-geoip
curl -o /var/lib/ooniapi/asn.mmdb.gz ${ASN_URL}
gunzip /var/lib/ooniapi/asn.mmdb.gz
curl -o /var/lib/ooniapi/cc.mmdb.gz ${CC_URL}
gunzip /var/lib/ooniapi/cc.mmdb.gz

# Basic smoke test of the geoip databases
python <<EOF
import geoip2.database
with geoip2.database.Reader('/var/lib/ooniapi/cc.mmdb') as reader:
    resp = reader.country('8.8.8.8')
    assert resp is not None
with geoip2.database.Reader('/var/lib/ooniapi/asn.mmdb') as reader:
    resp = reader.asn('8.8.8.8')
    assert resp is not None
EOF

echo $TS > /var/lib/ooniapi/geoipdbts
echo -n "ooni_download_geoip:1|c" >/dev/udp/localhost/8125
echo "Updated GeoIP databases" | systemd-cat -t ooniapi-geoip
exit 0
