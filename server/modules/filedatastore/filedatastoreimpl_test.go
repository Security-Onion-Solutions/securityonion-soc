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
	"github.com/security-onion-solutions/securityonion-soc/module"
	"os"
	"testing"
)

func TestFileDatastoreInit(tester *testing.T) {
	ds := NewFileDatastoreImpl()
	cfg := make(module.ModuleConfig)
	err := ds.Init(cfg)
	if err == nil {
		tester.Errorf("expected Init error")
	}

	jobDir := "/tmp/nodeoni.jobs"
	cfg["jobDir"] = jobDir
	defer os.Remove(jobDir)
	os.Mkdir(jobDir, 0777)
	err = ds.Init(cfg)
	if err != nil {
		tester.Errorf("unexpected Init error: %s", err)
	}
	if ds.retryFailureIntervalMs != DEFAULT_RETRY_FAILURE_INTERVAL_MS {
		tester.Errorf("expected retryFailureIntervalMs %d but got %d", DEFAULT_RETRY_FAILURE_INTERVAL_MS, ds.retryFailureIntervalMs)
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
	if len(nodes) != 1 {
		tester.Errorf("expected %d nodes but got %d", 1, len(nodes))
	}
	if nodes[0].Id != "foo" {
		tester.Errorf("expected node.Id %s but got %s", "foo", nodes[0].Id)
	}
	if nodes[0].Role != "rolo" {
		tester.Errorf("expected node.Role %s but got %s", "rolo", nodes[0].Role)
	}
	if nodes[0].Description != "desc" {
		tester.Errorf("expected node.Description %s but got %s", "desc", nodes[0].Description)
	}
	if nodes[0].Address != "addr" {
		tester.Errorf("expected node.Address %s but got %s", "addr", nodes[0].Address)
	}

	node = ds.CreateNode("bar")
	ds.addNode(node)
	nodes = ds.GetNodes()
	if len(nodes) != 2 {
		tester.Errorf("expected %d nodes but got %d", 2, len(nodes))
	}
	job := ds.GetNextJob("foo")
	if job != nil {
		tester.Errorf("expected no job")
	}
}

func TestJobs(tester *testing.T) {
	ds := NewFileDatastoreImpl()
	cfg := make(module.ModuleConfig)
	ds.Init(cfg)
	node := ds.CreateNode("foo")
	ds.addNode(node)

	// Test adding a job
	job := ds.CreateJob()
	if job.Id != 1001 {
		tester.Errorf("expected first job.Id %d but got %d", 1001, job.Id)
	}
	ds.addJob(job)
	job = ds.CreateJob()
	if job.Id != 1002 {
		tester.Errorf("expected second job.Id %d but got %d", 1002, job.Id)
	}
	ds.addJob(job)

	// Test fetching a job
	job = ds.getJobById(1001)
	if job.Id != 1001 {
		tester.Errorf("expected getJobById job.Id %d but got %d", 1001, job.Id)
	}

	job = ds.GetJob(1002)
	if job.Id != 1002 {
		tester.Errorf("expected GetJob job.Id %d but got %d", 1002, job.Id)
	}
	job = ds.GetJob(1003)
	if job != nil {
		tester.Errorf("expected nil GetJob job.Id but got %d", job.Id)
	}

	// Test fetching all jobs
	jobs := ds.GetJobs()
	if len(jobs) != 2 {
		tester.Errorf("expected GetJobs array size to be %d but got %d", 2, len(jobs))
	}

	// Test deleting jobs
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs()
	if len(jobs) != 1 {
		tester.Errorf("expected post-delete GetJobs array size to be %d but got %d", 1, len(jobs))
	}
	ds.deleteJob(jobs[0])
	jobs = ds.GetJobs()
	if len(jobs) != 0 {
		tester.Errorf("expected post-delete GetJobs array size to be %d but got %d", 0, len(jobs))
	}
}

func TestGetStreamFilename(tester *testing.T) {
	ds := NewFileDatastoreImpl()
	cfg := make(module.ModuleConfig)
	cfg["jobDir"] = "/tmp/jobs"
	ds.Init(cfg)
	filename := ds.getStreamFilename(ds.CreateJob())
	if filename != "/tmp/jobs/1001.bin" {
		tester.Errorf("expected job filename %s but got %s", "/tmp/jobs/1001.bin", filename)
	}
}
