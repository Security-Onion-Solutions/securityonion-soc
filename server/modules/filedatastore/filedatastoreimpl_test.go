// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package filedatastore

import (
	"context"
	"os"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/fake"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

const MY_USER_ID = "123"
const ANOTHER_USER_ID = "124"

func newContext() context.Context {
	user := model.NewUser()
	user.Id = MY_USER_ID
	return context.WithValue(context.Background(), web.ContextKeyRequestor, user)
}

func TestFileDatastoreInit(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	err := ds.Init(cfg)
	assert.Error(tester, err)

	jobDir := "/tmp/sensoroni.jobs"
	cfg["jobDir"] = jobDir
	defer os.Remove(jobDir)
	os.Mkdir(jobDir, 0777)
	err = ds.Init(cfg)
	if assert.Nil(tester, err) {
		assert.Equal(tester, DEFAULT_RETRY_FAILURE_INTERVAL_MS, ds.retryFailureIntervalMs)
	}
}

func TestNodes(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)
	node := ds.CreateNode("foo")
	node.Role = "rolo"
	node.Description = "desc"
	node.Address = "addr"
	ds.addNode(node)
	nodes := ds.GetNodes()
	if assert.Len(tester, nodes, 1) {
		assert.Equal(tester, "foo", nodes[0].Id)
		assert.Equal(tester, "rolo", nodes[0].Role)
		assert.Equal(tester, "desc", nodes[0].Description)
		assert.Equal(tester, "addr", nodes[0].Address)
	}

	node = ds.CreateNode("bar")
	ds.addNode(node)
	nodes = ds.GetNodes()
	assert.Len(tester, nodes, 2)
	job := ds.GetNextJob(newContext(), "foo")
	assert.Nil(tester, job)
}

func TestJobs(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewAuthorizedServer(nil))
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)
	node := ds.CreateNode("foo")
	ds.addNode(node)

	// Test adding a job
	job := ds.CreateJob(newContext())
	assert.Equal(tester, 1001, job.Id)
	ds.addJob(job)
	job = ds.CreateJob(newContext())
	assert.Equal(tester, 1002, job.Id)
	ds.addJob(job)

	// Test fetching a job
	job = ds.getJobById(1001)
	assert.Equal(tester, 1001, job.Id)

	job = ds.GetJob(newContext(), 1002)
	assert.Equal(tester, 1002, job.Id)

	job = ds.GetJob(newContext(), 1003)
	assert.Nil(tester, job)

	// Test fetching all jobs
	jobs := ds.GetJobs(newContext())
	assert.Len(tester, jobs, 2)

	// Test deleting jobs
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs(newContext())
	assert.Len(tester, jobs, 1)
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs(newContext())
	assert.Len(tester, jobs, 0)
}

func TestJobReadAuthorization(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)
	node := ds.CreateNode("foo")
	ds.addNode(node)

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
	jobs := ds.GetJobs(newContext())
	assert.Len(tester, jobs, 1) // Only has my job
}

func TestJobDeleteAuthorization(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)
	node := ds.CreateNode("foo")
	ds.addNode(node)

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
	ds := NewFileDatastoreImpl(fake.NewUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	cfg["jobDir"] = "/tmp/jobs"
	ds.Init(cfg)
	filename := ds.getStreamFilename(ds.CreateJob(newContext()))
	assert.Equal(tester, "/tmp/jobs/1001.bin", filename)
}

func TestUpdateInelegible(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)

	job := ds.CreateJob(newContext())
	job.UserId = MY_USER_ID // This user's job
	job.Id = 1212
	ds.addJob(job)

	err := ds.UpdateJob(newContext(), job)
	assert.Error(tester, err, "Job is inelegible for processing")
}

func TestUpdatePreserveData(tester *testing.T) {
	ds := NewFileDatastoreImpl(fake.NewAuthorizedServer(nil))
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)

	job := ds.CreateJob(newContext())
	job.UserId = MY_USER_ID // This user's job
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
