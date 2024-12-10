// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"strings"
	"time"
)

const JobStatusPending = 0
const JobStatusCompleted = 1
const JobStatusIncomplete = 2
const JobStatusDeleted = 3

const DEFAULT_JOB_KIND = "pcap"

type JobResult struct {
	// The ID or name of the result; varies depending on the job processor
	Id string `json:"id" example:"malwarebazaar"`
	// The job processor specific data outputs; varies depending on the job processor
	Data interface{} `json:"data"`
	// Brief summarization of the job result
	Summary string `json:"summary" example:"no result"`
}

func NewJobResult(id string, data interface{}, summary string) *JobResult {
	return &JobResult{
		Id:      id,
		Data:    data,
		Summary: summary,
	}
}

type Job struct {
	// The unique Job ID
	Id int `json:"id" example:"1004"`
	// The date and time when the job was created
	CreateTime time.Time `json:"createTime" example:"2024-10-07T06:45:49.52456415Z"`
	// The current state of the job. 0 = pending, 1 = complete, 2 = incomplete, 3 = deleted
	Status int `json:"status" example:"1"`
	// The date and time when the job was completed
	CompleteTime time.Time `json:"completeTime" example:"2024-10-07T12:15:09.12424556Z"`
	// The date and time when the job last failed and was marked incomplete
	FailTime time.Time `json:"failTime" example:"0001-01-01T00:00:00Z"`
	// The failure reason
	Failure string `json:"failure" example:""`
	// The number of times the job was processed but failed
	FailCount int `json:"failCount" example:"0"`
	// Owner field [not actively used by the API]
	Owner string `json:"owner" example:""`
	// The unique node ID that is responsible for completing this job
	NodeId string `json:"nodeId" example:"sensor-001"`
	// Legacy sensor ID field
	LegacySensorId string `json:"sensorId"`
	// The file extension for any attached job result/output data
	FileExtension string `json:"fileExtension" example:"bin"`
	// Optional filter for the job, typically used for packet filtering
	Filter *Filter `json:"filter"`
	// The unique user ID that created this job
	UserId string `json:"userId" example:"39314a6b-0b79-4210-1233-4e3fbcd7bfec"`
	// The kind of job that this object represents; blank values represent pcap jobs
	Kind string `json:"kind" example:"analyze"`
	// The array of job results; will be empty for jobs that only attach output streams
	Results []*JobResult `json:"results"`
	// The size of the job stream output, if a stream output was attached
	Size int `json:"size" example:"3781"`
}

func NewJob() *Job {
	return &Job{
		CreateTime:    time.Now(),
		Status:        JobStatusPending,
		Failure:       "",
		FailCount:     0,
		FileExtension: "bin",
		Filter:        NewFilter(),
	}
}

func (job *Job) GetKind() string {
	if job.Kind == "" {
		return DEFAULT_JOB_KIND
	}
	return job.Kind
}

func (job *Job) SetNodeId(nodeId string) {
	job.NodeId = strings.ToLower(nodeId)
}

func (job *Job) GetNodeId() string {
	// Lower case on the Getter as well since the property could have been
	// manipulated directly. Consider json.Unmarshall().
	job.NodeId = strings.ToLower(job.NodeId)
	if len(job.NodeId) == 0 {
		// See if there's a legacy sensor ID
		job.LegacySensorId = strings.ToLower(job.LegacySensorId)
		return job.LegacySensorId
	}
	return job.NodeId
}

func (job *Job) CanProcess() bool {
	return job.Status != JobStatusCompleted && job.Status != JobStatusDeleted
}

func (job *Job) Complete() {
	job.Status = JobStatusCompleted
	job.CompleteTime = time.Now()
}

func (job *Job) Fail(err error) {
	job.Status = JobStatusIncomplete
	job.Failure = err.Error()
	job.FailTime = time.Now()
	job.FailCount++
}
