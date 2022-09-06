// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package importer

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestInitImporter(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewImporter(nil)
	err := sq.Init(cfg)
	assert.NotNil(tester, err)
	assert.Equal(tester, DEFAULT_EXECUTABLE_PATH, sq.executablePath)
	assert.Equal(tester, DEFAULT_PCAP_OUTPUT_PATH, sq.pcapOutputPath)
	assert.Equal(tester, DEFAULT_PCAP_INPUT_PATH, sq.pcapInputPath)
	assert.Equal(tester, DEFAULT_TIMEOUT_MS, sq.timeoutMs)
}

func TestDataLag(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewImporter(nil)
	sq.Init(cfg)
	epoch := sq.GetDataEpoch()
	assert.False(tester, epoch.After(time.Now()), "epoch datetime should be before or equal to current datetime")
}

func validateQuery(tester *testing.T, actual string, expected string) {
	assert.Equal(tester, expected, actual)
}

func TestBuildQuery(tester *testing.T) {
	importer := NewImporter(nil)
	job := model.NewJob()

	query := importer.buildQuery(job)
	validateQuery(tester, query, "")

	job.Filter.SrcIp = "1.2.3.4"
	query = importer.buildQuery(job)
	validateQuery(tester, query, " host 1.2.3.4")

	job.Filter.DstIp = "4.3.2.1"
	query = importer.buildQuery(job)
	validateQuery(tester, query, " host 1.2.3.4 and host 4.3.2.1")

	job.Filter.DstPort = 53
	query = importer.buildQuery(job)
	validateQuery(tester, query, " host 1.2.3.4 and host 4.3.2.1 and port 53")

	job.Filter.SrcPort = 33
	query = importer.buildQuery(job)
	validateQuery(tester, query, " host 1.2.3.4 and host 4.3.2.1 and port 33 and port 53")
}
