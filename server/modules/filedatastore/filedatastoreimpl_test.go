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
	"os"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/stretchr/testify/assert"
)

func TestFileDatastoreInit(tester *testing.T) {
	ds := NewFileDatastoreImpl()
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
	ds := NewFileDatastoreImpl()
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
	job := ds.GetNextJob("foo")
	assert.Nil(tester, job)
}

func TestJobs(tester *testing.T) {
	ds := NewFileDatastoreImpl()
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)
	node := ds.CreateNode("foo")
	ds.addNode(node)

	// Test adding a job
	job := ds.CreateJob()
	assert.Equal(tester, 1001, job.Id)
	ds.addJob(job)
	job = ds.CreateJob()
	assert.Equal(tester, 1002, job.Id)
	ds.addJob(job)

	// Test fetching a job
	job = ds.getJobById(1001)
	assert.Equal(tester, 1001, job.Id)

	job = ds.GetJob(1002)
	assert.Equal(tester, 1002, job.Id)

	job = ds.GetJob(1003)
	assert.Nil(tester, job)

	// Test fetching all jobs
	jobs := ds.GetJobs()
	assert.Len(tester, jobs, 2)

	// Test deleting jobs
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs()
	assert.Len(tester, jobs, 1)
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs()
	assert.Len(tester, jobs, 0)
}

func TestGetStreamFilename(tester *testing.T) {
	ds := NewFileDatastoreImpl()
	cfg := make(module.ModuleConfig)
	cfg["jobDir"] = "/tmp/jobs"
	ds.Init(cfg)
	filename := ds.getStreamFilename(ds.CreateJob())
	assert.Equal(tester, "/tmp/jobs/1001.bin", filename)
}
