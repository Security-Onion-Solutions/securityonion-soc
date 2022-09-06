#!/bin/bash
# Copyright Jason Ertel (github.com/jertel).
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

version=${1:-dev}
now=`date -u +%Y-%m-%dT%H:%M:%S`

set -e

echo "Running JS unit tests..."
jest test --config jest.config.js

echo "Downloading GO dependencies..."
go get ./...

echo "Running GO unit tests..."
go test ./...

echo "Building application..."
go build -a -ldflags "-X main.BuildVersion=$version -X main.BuildTime=$now -extldflags '-static'" -tags netgo -installsuffix netgo cmd/sensoroni.go
