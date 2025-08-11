#!/bin/bash
# Development build script - skips tests for faster iteration

version=${1:-dev}
now=`date -u +%Y-%m-%dT%H:%M:%S`

set -e

echo "Running JS unit tests..."
jest test --config jest.config.js || echo "JS tests failed, continuing..."

echo "Downloading GO dependencies..."
go get ./...

go mod tidy

echo "Skipping GO unit tests for dev build..."

echo "Building application..."
go build -a -ldflags "-X main.BuildVersion=$version -X main.BuildTime=$now -extldflags '-static'" -tags netgo -installsuffix netgo cmd/sensoroni.go