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
	"bytes"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
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
	len, mimeType, err := event.Write(reader)
	assert.NoError(tester, err)
	assert.Equal(tester, 11, len)
	assert.Equal(tester, "text/plain; charset=utf-8", mimeType)
	assert.Equal(tester, "aGVsbG8gd29ybGQ=", event.Content)

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(event.Read())
	assert.NoError(tester, err)
	assert.Equal(tester, "hello world", buffer.String())
}
