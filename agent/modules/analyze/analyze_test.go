// Copyright 2022 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package analyze

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestInitAnalyze(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	err := sq.Init(cfg)
	assert.NotNil(tester, err)
	assert.Equal(tester, DEFAULT_ANALYZERS_PATH, sq.analyzersPath)
	assert.Equal(tester, DEFAULT_TIMEOUT_MS, sq.timeoutMs)
	assert.Equal(tester, DEFAULT_PARALLEL_LIMIT, sq.parallelLimit)
	assert.Equal(tester, DEFAULT_SUMMARY_LENGTH, sq.summaryLength)
}

func TestProcessJob(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	err := sq.Init(cfg)

	// Job kind is not set to analyze, so nothing should execute
	job := model.NewJob()
	reader, err := sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Empty(tester, job.Results)

	// Proper filter, so should execute, but no analyzers exist yet
	job.Kind = "analyze"
	reader, err = sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Empty(tester, job.Results)

	// Now analyzers should exist, but still no params set
	sq.analyzersPath = "test-resources"
	sq.refreshAnalyzers()
	reader, err = sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Empty(tester, job.Results)

	// Everything in its place, all test analyzers should execute
	job.Filter.Parameters["foo"] = "bar"
	sq.analyzersPath = "test-resources"
	sq.refreshAnalyzers()
	reader, err = sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Len(tester, job.Results, 2)
	assert.Equal(tester, "virustotal", job.Results[0].Id)
	assert.Equal(tester, "something here that is so long it will need to be ...", job.Results[0].Summary)
	assert.Equal(tester, "whois", job.Results[1].Id)
	assert.Equal(tester, "botsrv.btc-goblin.ru", job.Results[1].Summary)
}
