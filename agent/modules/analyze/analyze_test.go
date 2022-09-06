// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package analyze

import (
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

const TMP_DIR = "test-resources/whois/site-packages"

func cleanup_tmp() {
	os.RemoveAll(TMP_DIR)
}

func init_tmp(tester *testing.T) {
	cleanup_tmp()
	os.MkdirAll(TMP_DIR, 0777)

	entries, err := ioutil.ReadDir(TMP_DIR)
	assert.NoError(tester, err)
	assert.Equal(tester, 0, len(entries))
}

func TestInitAnalyze(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	err := sq.Init(cfg)
	assert.NotNil(tester, err)
	assert.Equal(tester, DEFAULT_ANALYZERS_PATH, sq.analyzersPath)
	assert.Equal(tester, DEFAULT_ANALYZER_EXECUTABLE, sq.analyzerExecutable)
	assert.Equal(tester, DEFAULT_ANALYZER_INSTALLER, sq.analyzerInstaller)
	assert.Equal(tester, DEFAULT_TIMEOUT_MS, sq.timeoutMs)
	assert.Equal(tester, DEFAULT_PARALLEL_LIMIT, sq.parallelLimit)
	assert.Equal(tester, DEFAULT_SUMMARY_LENGTH, sq.summaryLength)
}

func TestCreateAnalyzer(tester *testing.T) {
	init_tmp(tester)
	defer cleanup_tmp()

	cfg := make(map[string]interface{})
	cfg["analyzersPath"] = "test-resources"
	sq := NewAnalyze(nil)
	err := sq.Init(cfg)
	assert.Error(tester, err, "Unable to invoke JobMgr.AddJobProcessor due to nil agent")
	assert.Equal(tester, 1, len(sq.analyzers))

	entries, err := ioutil.ReadDir(TMP_DIR)
	assert.NoError(tester, err)
	assert.Equal(tester, 2, len(entries))
}

func TestInit(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	err := sq.Init(cfg)
	assert.NotNil(tester, err)
}

func TestJobKindMissing(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	sq.Init(cfg)

	// Job kind is not set to analyze, so nothing should execute
	job := model.NewJob()
	reader, err := sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Empty(tester, job.Results)
}

func TestJobFilterMissing(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	sq.Init(cfg)

	// Proper job kind, but no filter set yet
	job := model.NewJob()
	job.Kind = "analyze"
	reader, err := sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Empty(tester, job.Results)
}

func TestAnalyzersMissing(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewAnalyze(nil)
	sq.Init(cfg)

	// Job kind and filter parameters specified but still no analyzers
	job := model.NewJob()
	job.Kind = "analyze"
	job.Filter.Parameters["foo"] = "bar"
	reader, err := sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.NoError(tester, err)
	assert.Empty(tester, job.Results)
}

func TestAnalyzersExecuted(tester *testing.T) {
	init_tmp(tester)
	defer cleanup_tmp()

	cfg := make(map[string]interface{})
	cfg["analyzersPath"] = "test-resources"
	cfg["analyzerExecutable"] = "python3"
	cfg["sourcePackagesPath"] = "test-source-packages"
	cfg["sitePackagesPath"] = TMP_DIR
	sq := NewAnalyze(nil)
	sq.Init(cfg)

	job := model.NewJob()
	job.Kind = "analyze"
	job.Filter.Parameters["artifact"] = " bar\n"
	reader, err := sq.ProcessJob(job, nil)
	assert.Nil(tester, reader)
	assert.Nil(tester, err)
	assert.Len(tester, job.Results, 1)
	assert.Equal(tester, "whois", job.Results[0].Id)
	assert.Equal(tester, "something here that is so long it will need to be ...", job.Results[0].Summary)
	data := job.Results[0].Data.(map[string]interface{})
	assert.Equal(tester, "bar", data["input"])
}

func TestCreateResult(tester *testing.T) {
	cfg := make(map[string]interface{})
	analyzer := model.NewAnalyzer("test", "path")
	sq := NewAnalyze(nil)
	sq.Init(cfg)
	result := sq.createJobResult(analyzer, "myinput", []byte(`{"foo":"bar"}`), nil)
	assert.Equal(tester, `{"foo":"bar"}`, result.Summary)

	result = sq.createJobResult(analyzer, "myinput", []byte(`{"foo":"bar", "status": "threat", "data":"this is a long piece of data"}`), nil)
	assert.Equal(tester, `{"foo":"bar", "status": "threat", "data":"this is ...`, result.Summary)

	result = sq.createJobResult(analyzer, "myinput", []byte(`{"foo":"bar", "status": "threat", "summary":"this is a long piece of data"}`), nil)
	assert.Equal(tester, `this is a long piece of data`, result.Summary)

	// Normal exit
	err := exec.ExitError{}
	result = sq.createJobResult(analyzer, "myinput", []byte(`{"foo":"bar"}`), &err)
	assert.Equal(tester, `internal_failure`, result.Summary)
}
