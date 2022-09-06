// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package filedatastore

import (
	"context"
	"os"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

const MY_USER_ID = "123"
const ANOTHER_USER_ID = "124"
const JOB_DIR = "/tmp/sensoroni.jobs"

func newContext() context.Context {
	user := model.NewUser()
	user.Id = MY_USER_ID
	return context.WithValue(context.Background(), web.ContextKeyRequestor, user)
}

func cleanup() {
	os.RemoveAll(JOB_DIR)
}

func createDatastore(authorized bool) (*FileDatastoreImpl, error) {
	cleanup()

	var srv *server.Server
	if authorized {
		srv = server.NewFakeAuthorizedServer(nil)
	} else {
		srv = server.NewFakeUnauthorizedServer()
	}
	ds := NewFileDatastoreImpl(srv)
	cfg := make(module.ModuleConfig)
	cfg["jobDir"] = JOB_DIR
	os.MkdirAll(JOB_DIR, 0777)
	err := ds.Init(cfg)
	node := ds.CreateNode(newContext(), "foo")
	node.Role = "rolo"
	node.Description = "desc"
	node.Address = "addr"
	ds.addNode(node)
	return ds, err
}

func TestFileDatastoreInit(tester *testing.T) {
	defer cleanup()
	ds, err := createDatastore(true)
	assert.NoError(tester, err)
	assert.Equal(tester, DEFAULT_RETRY_FAILURE_INTERVAL_MS, ds.retryFailureIntervalMs)
}

func TestNodes(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(true)
	nodes := ds.GetNodes(newContext())
	if assert.Len(tester, nodes, 1) {
		assert.Equal(tester, "foo", nodes[0].Id)
		assert.Equal(tester, "rolo", nodes[0].Role)
		assert.Equal(tester, "desc", nodes[0].Description)
		assert.Equal(tester, "addr", nodes[0].Address)
	}

	node := ds.CreateNode(newContext(), "bar")
	ds.addNode(node)
	nodes = ds.GetNodes(newContext())
	assert.Len(tester, nodes, 2)
	job := ds.GetNextJob(newContext(), "foo")
	assert.Nil(tester, job)
}

func TestJobs(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(true)

	// Test adding a job
	job := ds.CreateJob(newContext())
	assert.Equal(tester, 1001, job.Id)
	ds.addJob(job)
	job = ds.CreateJob(newContext())
	assert.Equal(tester, 1002, job.Id)
	ds.addJob(job)

	// Add non-default job kind
	job = ds.CreateJob(newContext())
	job.Kind = "foo"
	ds.addJob(job)

	// Test fetching a job
	job = ds.getJobById(1001)
	assert.Equal(tester, 1001, job.Id)

	job = ds.GetJob(newContext(), 1002)
	assert.Equal(tester, 1002, job.Id)

	job = ds.GetJob(newContext(), 1003)
	assert.Equal(tester, 1003, job.Id)
	assert.Equal(tester, "foo", job.GetKind())

	job = ds.GetJob(newContext(), 1004)
	assert.Nil(tester, job)

	// Test fetching all default jobs
	jobs := ds.GetJobs(newContext(), "", nil)
	assert.Len(tester, jobs, 2)

	// Test deleting jobs
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs(newContext(), "", nil)
	assert.Len(tester, jobs, 1)
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs(newContext(), "", nil)
	assert.Len(tester, jobs, 0)

	jobs = ds.GetJobs(newContext(), "foo", nil)
	assert.Len(tester, jobs, 1)
}

func TestJobAddUnauthorized(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(false)

	// Test adding a job
	job := ds.CreateJob(newContext())
	assert.Equal(tester, 1001, job.Id)
	err := ds.AddJob(newContext(), job)
	assert.Error(tester, err)
	assert.Len(tester, ds.jobsById, 0)
}

func TestJobAdd(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(true)
	assert.Len(tester, ds.jobsById, 0)

	// Test adding a job
	job := ds.CreateJob(newContext())
	assert.Equal(tester, 1001, job.Id)
	err := ds.AddJob(newContext(), job)
	assert.NoError(tester, err)
	assert.Len(tester, ds.jobsById, 1)

	newJob := ds.GetJob(newContext(), job.Id)
	assert.Equal(tester, MY_USER_ID, newJob.UserId)
}

func TestJobAddPivotUnauthorized(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(false)

	// Test adding an arbitrary job
	job := ds.CreateJob(newContext())
	assert.Equal(tester, 1001, job.Id)
	err := ds.AddPivotJob(newContext(), job)
	assert.Error(tester, err)
	assert.Len(tester, ds.jobsById, 0)
}

func TestJobAddPivot(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(true)
	assert.Len(tester, ds.jobsById, 0)

	// Test adding a pivot job (requires different permission)
	job := ds.CreateJob(newContext())
	assert.Equal(tester, 1001, job.Id)
	err := ds.AddPivotJob(newContext(), job)
	assert.NoError(tester, err)
	assert.Len(tester, ds.jobsById, 1)

	newJob := ds.GetJob(newContext(), job.Id)
	assert.Equal(tester, MY_USER_ID, newJob.UserId)
}

func TestJobReadAuthorization(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(false)

	myJobId := 10001
	anotherJobId := 10002

	// Test adding a job
	job := ds.CreateJob(newContext())
	job.UserId = ANOTHER_USER_ID
	job.Id = anotherJobId
	ds.addJob(job)

	job = ds.CreateJob(newContext())
	job.UserId = MY_USER_ID // This user's job
	job.Id = myJobId
	ds.addJob(job)

	job = ds.GetJob(newContext(), myJobId)
	assert.Equal(tester, myJobId, job.Id)

	job = ds.GetJob(newContext(), anotherJobId)
	assert.Nil(tester, job)

	// Test fetching all jobs
	jobs := ds.GetJobs(newContext(), "", nil)
	assert.Len(tester, jobs, 1) // Only has my job
}

func TestJobDeleteAuthorization(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(false)

	myJobId := 10001
	anotherJobId := 10002

	// Test adding a job
	anotherJob := ds.CreateJob(newContext())
	anotherJob.UserId = ANOTHER_USER_ID
	anotherJob.Id = anotherJobId
	ds.addJob(anotherJob)

	myJob := ds.CreateJob(newContext())
	myJob.UserId = MY_USER_ID // This user's job
	myJob.Id = myJobId
	ds.addJob(myJob)

	assert.NotNil(tester, ds.jobsById[myJobId])
	assert.NotNil(tester, ds.jobsById[anotherJobId])

	// Should not delete another user's job
	ds.DeleteJob(newContext(), anotherJobId)
	assert.NotNil(tester, ds.jobsById[anotherJobId])

	// Should delete my own job
	ds.DeleteJob(newContext(), myJobId)
	assert.Nil(tester, ds.jobsById[myJobId])
}

func TestGetStreamFilename(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(false)
	filename := ds.getStreamFilename(ds.CreateJob(newContext()))
	assert.Equal(tester, "/tmp/sensoroni.jobs/1001.bin", filename)
}

func TestUpdateInelegible(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(false)

	job := ds.CreateJob(newContext())
	job.UserId = MY_USER_ID
	job.Id = 1212
	ds.addJob(job)

	err := ds.UpdateJob(newContext(), job)
	assert.Error(tester, err, "Job is inelegible for processing")
}

func TestUpdatePreserveData(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(true)

	job := ds.CreateJob(newContext())
	job.UserId = MY_USER_ID
	job.NodeId = "some node"
	job.Id = 1212
	job.Status = model.JobStatusPending
	ds.addJob(job)

	newJob := ds.CreateJob(newContext())
	newJob.Id = job.Id
	newJob.UserId = ANOTHER_USER_ID
	newJob.NodeId = "some other node"
	err := ds.UpdateJob(newContext(), newJob)
	assert.NoError(tester, err)
	assert.Equal(tester, job.UserId, newJob.UserId)
	assert.Equal(tester, job.NodeId, newJob.NodeId)
}

func TestFilterMatches(tester *testing.T) {
	defer cleanup()
	ds, _ := createDatastore(true)

	params := make(map[string]interface{})
	jobParams := make(map[string]interface{})
	nested := make(map[string]interface{})
	jobNested := make(map[string]interface{})
	jobNested["mar"] = "tar"

	// simple match with no params
	assert.True(tester, ds.filterParameterMatches(params, jobParams))

	// parameters exist on job, but not on search filter, so match is true
	jobParams["foo"] = "bar"
	assert.True(tester, ds.filterParameterMatches(params, jobParams))

	// params exist on both, and match
	params["foo"] = "bar"
	assert.True(tester, ds.filterParameterMatches(params, jobParams))

	// params exist on both, but do not match
	params["foo"] = "bar"
	jobParams["foo"] = 1.23
	assert.False(tester, ds.filterParameterMatches(params, jobParams))

	// nested params exist on both, and match
	nested["hello"] = 1.2
	params["foo"] = nested
	jobNested["hello"] = 1.2
	jobParams["foo"] = jobNested
	assert.True(tester, ds.filterParameterMatches(params, jobParams))

	// nest params exist on both, but do not match
	nested["hello"] = 1.2
	params["foo"] = nested
	jobNested["hello"] = 1.3
	jobParams["foo"] = jobNested
	assert.False(tester, ds.filterParameterMatches(params, jobParams))

	// nested parameters exist on search filter, but not on job
	nested["hello"] = 1.2
	params["foo"] = nested
	jobNested = make(map[string]interface{})
	jobNested["bye"] = "unused"
	jobParams["foo"] = jobNested
	assert.False(tester, ds.filterParameterMatches(params, jobParams))
}
