#!/bin/bash

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

PCAP_PATH=/nsm/suripcap/*/
PCAP_TMP=/nsm/suripcaptmp


if [ $# -le 3 ]; then
    echo "usage: $0 <output-file> <start-date> <end-date> <bpf>"
    echo ""
    echo "Extracts a particular packet stream based on the given time range and BPF."
    exit 1
else
    OUTPUTFILE=$1
    shift
    STARTDATE=$1
    shift
    ENDDATE=$1
    shift
    FILTER=$@
    BEFORE=$(date -d"$STARTDATE" "+%Y-%m-%d %H:%I:%S")
    AFTER=$(date -d"$ENDDATE" "+%Y-%m-%d %H:%I:%S")
    FINDIT=$(find $PCAP_PATH -newermt "$AFTER" \! -newermt "$BEFORE")
    TMPDIR=$(mktemp -p $PCAP_TMP -d)
    for filename in $FINDIT; do
        fname=$(basename $filename)
        tcpdump -nn -s 0 -r $filename $FILTER or "(vlan and $FILTER)" -w $TMPDIR/$fname
    done
    mergecap -F pcap -w $OUTPUTFILE $TMPDIR/*
    # Clean up on aisle 4
    rm -rf $TMPDIR
fi
