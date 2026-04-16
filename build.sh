#!/bin/bash
# Copyright 2019 Jason Ertel (github.com/jertel).
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

version=${1:-dev}
now=`date -u +%Y-%m-%dT%H:%M:%S`

echo "Building $version ($now)"

set -e

echo "Running JS unit tests..."
jest test --config jest.config.js

echo "Downloading GO dependencies..."
go get ./...

go mod tidy

echo "Running GO unit tests..."
go test ./...

if [[ "$version" != "0.0.0" ]]; then
    echo "Scanning for vulnerabilities"

    # Export deps to fake package.json/lock files
    grep -h "js/external/" html/index.html html/login/index.html | \
    sed -E 's/.*src="js\/external\/([^"]+)".*/\1/' | sort -u | \
    sed -E 's/([-.]v?)([0-9]+(\.[0-9]+)+.*)\.js$/ \2/' | \
    awk '{n=$1; v=$2; sub(/\.umd\.production.*/, "", v); sub(/\.min$/, "", v); if(n && v) print n, v}' | \
    jq -R 'split(" ") | {(.[0]): .[1]}' | jq -s 'add' | \
    jq '{name: "fake-lib-scan", version: "1.0.0", dependencies: .}' > package.json && \
    jq --arg name "fake-lib-scan" --arg version "1.0.0" '
    {
        name: $name,
        version: $version,
        lockfileVersion: 2,
        requires: true,
        packages: {
        "": {
            name: $name,
            version: $version,
            dependencies: .dependencies
        }
        }
    } as $base |
    $base + {
        packages: ($base.packages + (.dependencies | to_entries | map({key: ("node_modules/" + .key), value: {version: .value}}) | from_entries)),
        dependencies: (.dependencies | to_entries | map({key: .key, value: {version: .value}}) | from_entries)
    }
    ' package.json > package-lock.json

    set +e
    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
    osv-scanner scan --format json -r . > osv-scan.json
    set -e
    jq -r '["PACKAGE", "VERSION", "ID", "SCORE", "SEVERITY", "SUMMARY"], ([.results[].packages[] as $pkg | $pkg.groups[] | (.max_severity | tonumber? // 0) as $score | select($score >= 7.0) | $pkg.vulnerabilities[] | select(.id as $vid | $pkg.groups[] | select(.ids | any(. == $vid)) | .max_severity == ($score | tostring)) | [ $pkg.package.name, $pkg.package.version, .id, $score, (if $score >= 9.0 then "CRITICAL" else "HIGH" end), .summary ]] | unique[]) | @tsv' osv-scan.json | column -t -s $'\t'
    if ! jq -e '[.results[].packages[].groups[] | select((.max_severity | tonumber? // 0) >= 9.0)] | length == 0' osv-scan.json > /dev/null; then
        echo "Found contains critical vulnerabilities"
        exit 1
    fi
    rm -f package.json package-lock.json osv-scan.json
fi

echo "Building application..."
go build -a -ldflags "-X main.BuildVersion=$version -X main.BuildTime=$now -X github.com/security-onion-solutions/securityonion-soc/licensing.revKeys=$REVKEYS -extldflags '-static'" -tags netgo -installsuffix netgo cmd/sensoroni.go
