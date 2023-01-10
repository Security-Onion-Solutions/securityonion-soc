#!/bin/sh
# Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
#
# This program is distributed under the terms of version 2 of the
# GNU General Public License.  See LICENSE for further details.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

CERTPATH=${STENO_CERTS:-/etc/stenographer/certs}
URL=${STENO_URL:-https://127.0.0.1:1234/query}
TIMEOUT=${STENO_TIMEOUT:-890}
MAX_PCAP_BYTES=${STENO_MAX_PCAP_BYTES:-2147483648}

if [ $# -lt 1 ]; then
  echo "Usage: $0 <steno-query> [tcpdump-args]"
  exit 1
fi

query=$1
shift

/usr/bin/curl \
    --cert "$CERTPATH/client_cert.pem" \
    --key "$CERTPATH/client_key.pem" \
    --cacert "$CERTPATH/ca_cert.pem" \
    --silent \
    --max-time $TIMEOUT \
    --header "Steno-Limit-Bytes:$MAX_PCAP_BYTES" \
    --show-error \
    -d "$query" \
    "$URL" |
    /usr/bin/tcpdump -r /dev/stdin -s 0 "$@"
