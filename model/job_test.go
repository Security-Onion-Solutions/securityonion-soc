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

func TestSetNodeId(tester *testing.T) {
  job := NewJob()
  if job.NodeId != "" {
    tester.Errorf("expected new jobs to have an empty node ID")
  }

  job.NodeId = "test"
  if job.NodeId != "test" {
    tester.Errorf("expected unmodified Node ID but got %s", job.NodeId)
  }

  job.SetNodeId("testing")
  if job.NodeId != "testing" {
    tester.Errorf("expected unmodified Node ID but got %s", job.NodeId)
  }
  if job.GetNodeId() != "testing" {
    tester.Errorf("expected unmodified Node ID via getter but got %s", job.GetNodeId())
  }

  job.SetNodeId("TestingThis")
  if job.NodeId != "testingthis" {
    tester.Errorf("expected lowercased Node ID but got %s", job.NodeId)
  }
  if job.GetNodeId() != "testingthis" {
    tester.Errorf("expected lowercased Node ID via getter but got %s", job.GetNodeId())
  }

  job.NodeId = "TestingThis2"
  if job.NodeId != "TestingThis2" {
    tester.Errorf("expected unmodified Node ID but got %s", job.NodeId)
  }
  if job.GetNodeId() != "testingthis2" {
    tester.Errorf("expected lowercased Node ID via getter but got %s", job.GetNodeId())
  }
  if job.NodeId != "testingthis2" {
    tester.Errorf("expected lowercased Node ID after getter but got %s", job.NodeId)
  }
}

func TestGetLegacyNodeId(tester *testing.T) {
  job := NewJob()
  if job.GetNodeId() != "" {
    tester.Errorf("expected new jobs to have an empty node ID")
  }

  job.NodeId = "Foo"
  if job.GetNodeId() != "foo" {
    tester.Errorf("expected foo but got %s", job.GetNodeId())
  }

  job.LegacySensorId = "Bar"
  if job.GetNodeId() != "foo" {
    tester.Errorf("expected foo but got %s", job.GetNodeId())
  }

  job.NodeId = ""
  if job.GetNodeId() != "bar" {
    tester.Errorf("expected bar but got %s", job.GetNodeId())
  }
}