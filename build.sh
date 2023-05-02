#!/bin/bash

# Copyright 2019 Jason Ertel (jertel). All rights reserved.
#
# This program is distributed under the terms of version 2 of the
# GNU General Public License.  See LICENSE for further details.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

version=${1:-dev}
now=`date -u +%Y-%m-%dT%H:%M:%S`

set -e

echo "Running JS unit tests..."
jest test --config jest.config.js

echo "Downloading GO dependencies..."
go get ./...

go mod tidy

echo "Running GO unit tests..."
go test ./...

echo "Building application..."
go build -a -ldflags "-X main.BuildVersion=$version -X main.BuildTime=$now -extldflags '-static'" -tags netgo -installsuffix netgo cmd/sensoroni.go
