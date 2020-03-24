// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "errors"
  "testing"
)

func TestVerifyJob(tester *testing.T) {
  job := NewJob()
  if job.Status != JobStatusPending {
    tester.Errorf("expected Status %d but got %d", JobStatusPending, job.Status)
  }

  job.Fail(errors.New("one"))
  if job.Status != JobStatusIncomplete {
    tester.Errorf("expected Status %d but got %d", JobStatusIncomplete, job.Status)
  }
  if job.Failure == "" {
    tester.Errorf("expected Failure but got none")
  }
  if job.FailCount != 1 {
    tester.Errorf("expected FailCount %d but got %d", 1, job.FailCount)
  }
  job.Fail(errors.New("two"))
  if job.FailCount != 2 {
    tester.Errorf("expected FailCount %d but got %d", 2, job.FailCount)
  }

  job.Complete()
  if job.Status != JobStatusCompleted {
    tester.Errorf("expected Status %d but got %d", JobStatusCompleted, job.Status)
  }
}
