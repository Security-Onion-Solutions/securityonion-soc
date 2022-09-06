// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package stenoquery

import (
	"strconv"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestInitStenoQuery(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewStenoQuery(nil)
	err := sq.Init(cfg)
	assert.Error(tester, err)
	assert.Equal(tester, DEFAULT_EXECUTABLE_PATH, sq.executablePath)
	assert.Equal(tester, DEFAULT_PCAP_OUTPUT_PATH, sq.pcapOutputPath)
	assert.Equal(tester, DEFAULT_PCAP_INPUT_PATH, sq.pcapInputPath)
	assert.Equal(tester, DEFAULT_TIMEOUT_MS, sq.timeoutMs)
	assert.Equal(tester, DEFAULT_EPOCH_REFRESH_MS, sq.epochRefreshMs)
	assert.Equal(tester, DEFAULT_DATA_LAG_MS, sq.dataLagMs)
}

func TestDataLag(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewStenoQuery(nil)
	sq.Init(cfg)
	lagDate := sq.getDataLagDate()
	assert.False(tester, lagDate.After(time.Now()), "expected data lag datetime to be before current datetime")
}

func TestCreateQuery(tester *testing.T) {
	sq := NewStenoQuery(nil)

	job := model.NewJob()
	job.Filter.BeginTime, _ = time.Parse(time.RFC3339, "2006-01-02T15:05:05Z")
	job.Filter.EndTime, _ = time.Parse(time.RFC3339, "2006-01-02T15:06:05Z")
	expectedQuery := "before 2006-01-02T15:06:05Z and after 2006-01-02T15:05:05Z"
	query := sq.CreateQuery(job)
	assert.Equal(tester, expectedQuery, query)

	job.Filter.SrcIp = "1.2.3.4"
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and host " + job.Filter.SrcIp
	assert.Equal(tester, expectedQuery, query)

	job.Filter.DstIp = "1.2.1.2"
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and host " + job.Filter.DstIp
	assert.Equal(tester, expectedQuery, query)

	job.Filter.SrcPort = 123
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and port " + strconv.Itoa(job.Filter.SrcPort)
	assert.Equal(tester, expectedQuery, query)

	job.Filter.DstPort = 123
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and port " + strconv.Itoa(job.Filter.DstPort)
	assert.Equal(tester, expectedQuery, query)
}
