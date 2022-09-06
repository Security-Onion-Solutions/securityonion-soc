// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyJob(tester *testing.T) {
	job := NewJob()
	assert.Equal(tester, JobStatusPending, job.Status)

	job.Fail(errors.New("one"))
	assert.Equal(tester, JobStatusIncomplete, job.Status)
	assert.NotEmpty(tester, job.Failure)
	assert.Equal(tester, 1, job.FailCount)

	job.Fail(errors.New("two"))
	assert.Equal(tester, 2, job.FailCount)

	job.Complete()
	assert.Equal(tester, JobStatusCompleted, job.Status)
}

func TestSetNodeId(tester *testing.T) {
	job := NewJob()
	assert.Empty(tester, job.NodeId)

	job.SetNodeId("testing")
	assert.Equal(tester, "testing", job.NodeId)
	assert.Equal(tester, "testing", job.GetNodeId())

	job.SetNodeId("TestingThis")
	assert.Equal(tester, "testingthis", job.NodeId)
	assert.Equal(tester, "testingthis", job.GetNodeId())

	// Check that NodeId is modified by getter
	job.NodeId = "TestingThis2"
	assert.Equal(tester, "TestingThis2", job.NodeId)
	assert.Equal(tester, "testingthis2", job.GetNodeId())
	assert.Equal(tester, "testingthis2", job.NodeId)
}

func TestGetLegacyNodeId(tester *testing.T) {
	job := NewJob()
	assert.Empty(tester, job.GetNodeId())

	job.NodeId = "Foo"
	assert.Equal(tester, "foo", job.GetNodeId())

	job.LegacySensorId = "Bar"
	assert.Equal(tester, "foo", job.GetNodeId())

	// Check that GetNodeId() returns formatted LegacySensorId if NodeId is blank
	job.NodeId = ""
	assert.Equal(tester, "bar", job.GetNodeId())
}

func TestCanProcess(tester *testing.T) {
	job := NewJob()
	assert.True(tester, job.CanProcess())
	job.Fail(errors.New("Something"))
	assert.True(tester, job.CanProcess())

	job.Complete()
	assert.False(tester, job.CanProcess())

	job = NewJob()
	job.Status = JobStatusDeleted
	assert.False(tester, job.CanProcess())
}

func TestKind(tester *testing.T) {
	job := NewJob()
	assert.Equal(tester, DEFAULT_JOB_KIND, job.GetKind())

	job.Kind = "foo"
	assert.Equal(tester, "foo", job.GetKind())
}
