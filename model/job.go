// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
  Id      string      `json:"id"`
  Data    interface{} `json:"data"`
  Summary string      `json:"summary"`
}

func NewJobResult(id string, data interface{}, summary string) *JobResult {
  return &JobResult{
    Id:      id,
    Data:    data,
    Summary: summary,
  }
}

type Job struct {
  Id             int          `json:"id"`
  CreateTime     time.Time    `json:"createTime"`
  Status         int          `json:"status"`
  CompleteTime   time.Time    `json:"completeTime"`
  FailTime       time.Time    `json:"failTime"`
  Failure        string       `json:"failure"`
  FailCount      int          `json:"failCount"`
  Owner          string       `json:"owner"`
  NodeId         string       `json:"nodeId"`
  LegacySensorId string       `json:"sensorId"`
  FileExtension  string       `json:"fileExtension"`
  Filter         *Filter      `json:"filter"`
  UserId         string       `json:"userId"`
  Kind           string       `json:"kind"`
  Results        []*JobResult `json:"results"`
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
