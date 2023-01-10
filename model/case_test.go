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
	"bytes"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestNewRelatedEvent(tester *testing.T) {
	event := NewRelatedEvent()
	assert.NotZero(tester, event.CreateTime)
}

func TestNewArtifact(tester *testing.T) {
	event := NewArtifact()
	assert.NotZero(tester, event.CreateTime)
}

func TestNewArtifactStream(tester *testing.T) {
	event := NewArtifactStream()
	assert.NotZero(tester, event.CreateTime)
	reader := strings.NewReader("hello world")
	len, mimeType, md5, sha1, sha256, err := event.Write(reader)
	assert.NoError(tester, err)
	assert.Equal(tester, 11, len)
	assert.Equal(tester, "text/plain; charset=utf-8", mimeType)
	assert.Equal(tester, "5eb63bbbe01eeed093cb22bb8f5acdc3", md5)
	assert.Equal(tester, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", sha1)
	assert.Equal(tester, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", sha256)
	assert.Equal(tester, "aGVsbG8gd29ybGQ=", event.Content)

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(event.Read())
	assert.NoError(tester, err)
	assert.Equal(tester, "hello world", buffer.String())
}

func TestWorkflowForStatus(tester *testing.T) {
	now := time.Now()

	oldCase := NewCase()
	newCase := NewCase()
	newCase.ProcessWorkflowForStatus(oldCase)
	assert.Nil(tester, newCase.CompleteTime)
	assert.Nil(tester, newCase.StartTime)

	newCase.Status = "in progress"
	newCase.ProcessWorkflowForStatus(oldCase)
	assert.Nil(tester, newCase.CompleteTime)
	assert.NotNil(tester, newCase.StartTime)

	newCase.Status = "closed"
	newCase.ProcessWorkflowForStatus(oldCase)
	assert.NotNil(tester, newCase.CompleteTime)
	assert.True(tester, newCase.CompleteTime.After(*newCase.StartTime))

	oldCase.Status = "in progress"
	oldCase.CompleteTime = &now
	newCase.CompleteTime = nil
	newCase.Status = "closed"
	newCase.ProcessWorkflowForStatus(oldCase)
	assert.NotNil(tester, newCase.CompleteTime)
	assert.True(tester, newCase.CompleteTime.After(*oldCase.CompleteTime))

	oldCase.Status = "new"
	oldCase.StartTime = &now
	newCase.Status = "in progress"
	newCase.ProcessWorkflowForStatus(oldCase)
	assert.Equal(tester, oldCase.StartTime, newCase.StartTime)
}
