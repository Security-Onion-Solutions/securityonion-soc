// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package agent

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

// idJobProcessor is a "sunny day" JobProcessor that simply appends the job id
// to the stream without panicking.
type idJobProcessor struct{}

func (jp *idJobProcessor) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	buf := bytes.NewBuffer([]byte{})

	if reader != nil {
		_, err := io.Copy(buf, reader)
		if err != nil {
			return nil, err
		}
	}

	_, err := buf.WriteString(strconv.Itoa(job.Id))
	if err != nil {
		return nil, err
	}

	return io.NopCloser(buf), nil
}

func (jp *idJobProcessor) CleanupJob(*model.Job) {}

func (jp *idJobProcessor) GetDataEpoch() time.Time {
	t, _ := time.Parse(time.RFC3339, "2022-01-01T00:00:00Z")
	return t
}

// panicProcessor is a JobProcessor that always returns an error.
type panicProcessor struct {
	processCount int
	errorString  string
}

func (jp *panicProcessor) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	jp.processCount++
	return reader, errors.New(jp.errorString)
}

func (jp *panicProcessor) CleanupJob(*model.Job) {}

func (jp *panicProcessor) GetDataEpoch() time.Time {
	t, _ := time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")
	return t
}

func TestProcessJob(t *testing.T) {
	// prep test object
	jm := &JobManager{}

	jm.AddJobProcessor(&idJobProcessor{})
	jm.AddJobProcessor(&panicProcessor{errorString: "panic"})

	// prep model
	job := &model.Job{
		Id: 101,
	}

	// test
	stream, err := jm.ProcessJob(job)

	// verify
	data, rerr := io.ReadAll(stream)
	assert.NoError(t, rerr)

	assert.Equal(t, "101", string(data))
	assert.Nil(t, err)
}

func TestProcessJobContinuesIfNoDataAvailable(t *testing.T) {
	// prep test object
	jm := &JobManager{}

	proc := panicProcessor{errorString: "No data available"}
	jm.AddJobProcessor(&proc)
	jm.AddJobProcessor(&proc)

	// prep model
	job := &model.Job{
		Id: 101,
	}

	// test
	_, err := jm.ProcessJob(job)

	assert.Equal(t, 2, proc.processCount)
	assert.ErrorContains(t, err, "No data available")
}

func TestUpdateDataEpoch(t *testing.T) {
	// prep test object
	jm := &JobManager{
		node: &model.Node{},
	}

	panicProc := &panicProcessor{}

	jm.AddJobProcessor(&idJobProcessor{}) // later epoch
	jm.AddJobProcessor(panicProc)         // earlier epoch

	// test
	jm.updateDataEpoch()

	// verify
	assert.Equal(t, jm.node.EpochTime, panicProc.GetDataEpoch())
}

func TestOnlineTime(t *testing.T) {
	// prep test object
	jm := &JobManager{
		node: &model.Node{},
	}

	tmpFile, _ := os.CreateTemp("", "jobmanager_online_time.tmp")

	// test
	jm.updateOnlineTime(tmpFile.Name())
	defer os.Remove(tmpFile.Name())

	// verify
	assert.GreaterOrEqual(t, jm.node.OnlineTime, time.Now().Add(time.Second*(-2)))
}

type ClientAuthMock struct{}

func (cam *ClientAuthMock) Authorize(*http.Request) error {
	return nil
}

func TestNoJobReady(t *testing.T) {
	// prep test object
	client := &web.Client{
		Auth: &ClientAuthMock{},
	}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
	}

	client.MockResponse(res, nil)

	jm := &JobManager{
		agent: &Agent{
			Client: client,
		},
		node: &model.Node{},
	}

	// test
	job, err := jm.PollPendingJobs()

	// verify
	assert.NoError(t, err)
	assert.Nil(t, job)
}
