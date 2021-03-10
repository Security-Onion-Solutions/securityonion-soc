// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "time"
)

const JobStatusPending = 0
const JobStatusCompleted = 1
const JobStatusIncomplete = 2
const JobStatusDeleted = 3

type Job struct {
  Id												int											`json:"id"`
  CreateTime                time.Time 							`json:"createTime"`
  Status  									int											`json:"status"`
  CompleteTime              time.Time 							`json:"completeTime"`
  FailTime              		time.Time 							`json:"failTime"`
  Failure										string									`json:"failure"`
  FailCount									int											`json:"failCount"`
  Owner                     string    							`json:"owner"`
  NodeId	                  string    							`json:"nodeId"`
  FileExtension							string									`json:"fileExtension"`
  Filter										*Filter									`json:"filter"`
  UserId                    string                  `json:"userId"`
}

func NewJob() *Job {
  return &Job{
    CreateTime: time.Now(),
    Status: JobStatusPending,
    Failure: "",
    FailCount: 0,
    FileExtension: "bin",
    Filter: NewFilter(),
  }
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