// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
	"context"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func TestAddRemoveConnection(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	conn := &websocket.Conn{}
	tester.Run("testing add connection", func(t *testing.T) {
		socConn := host.AddConnection(conn, "1.2.3.4")
		assert.Len(tester, host.connections, 1)
		assert.Equal(tester, socConn.ip, "1.2.3.4", socConn.ip)
		assert.Equal(tester, 123, host.idleConnectionTimeoutMs)
	})
	tester.Run("testing remove connection", func(t *testing.T) {
		host.RemoveConnection(conn)
		assert.Len(tester, host.connections, 0)
	})
}

func TestMultipleConnections(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	conn1 := &websocket.Conn{}
	conn2 := &websocket.Conn{}
	tester.Run("testing add multiple connections", func(t *testing.T) {
		host.AddConnection(conn1, "1.2.3.4")
		host.AddConnection(conn2, "1.2.3.4")
		assert.Len(tester, host.connections, 2)
	})
	tester.Run("testing remove first connection", func(t *testing.T) {
		host.RemoveConnection(conn1)
		assert.Len(tester, host.connections, 1)
	})
	tester.Run("testing remove second connection", func(t *testing.T) {
		host.RemoveConnection(conn2)
		assert.Len(tester, host.connections, 0)
	})
}

func TestManageConnections(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	conn := host.AddConnection(nil, "")

	conn.lastPingTime = time.Time{}

	go func() {
		time.Sleep(200 * time.Millisecond)
		host.running = false
	}()

	host.running = true
	host.manageConnections(10 * time.Millisecond)

	assert.Len(tester, host.connections, 0)
}

func TestGetSourceIp(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	request, _ := http.NewRequest("GET", "", nil)

	expected := "1.1.1.1"
	request.Header.Set("X-real-IP", expected)

	assert.Equal(tester, expected, host.GetSourceIp(request))
}

type DummyPreprocessor struct {
	priority   int
	statusCode int
	err        error
}

func (dummy *DummyPreprocessor) PreprocessPriority() int {
	return dummy.priority
}

func (dummy *DummyPreprocessor) Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error) {
	return ctx, dummy.statusCode, dummy.err
}

func TestPreprocessorSetup(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	assert.Len(tester, host.Preprocessors(), 1)

	newPreprocessor := &DummyPreprocessor{priority: 123}

	host.AddPreprocessor(newPreprocessor)
	assert.Len(tester, host.Preprocessors(), 2)

	assert.Equal(tester, newPreprocessor, host.Preprocessors()[1], "expected new preprocessors to be processed last")

	newPreprocessor2 := &DummyPreprocessor{priority: 12}

	host.AddPreprocessor(newPreprocessor2)
	assert.Len(tester, host.Preprocessors(), 3)
	assert.Equal(tester, newPreprocessor2, host.Preprocessors()[1], "expected new preprocessors to be processed second")

	// Should collide
	newPreprocessor3 := &DummyPreprocessor{priority: 12}
	err := host.AddPreprocessor(newPreprocessor3)
	assert.Error(tester, err, "Expected error from colliding preprocessors")
	assert.Len(tester, host.Preprocessors(), 3)
}

func TestPreprocessExecute(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	newPreprocessor := &DummyPreprocessor{priority: 123, statusCode: 321}
	host.AddPreprocessor(newPreprocessor)
	request, _ := http.NewRequest("GET", "", nil)
	ctx, statusCode, err := host.Preprocess(context.Background(), request)
	assert.NoError(tester, err)
	assert.Equal(tester, 321, statusCode)
	assert.NotNil(tester, ctx.Value(ContextKeyRequestId), "Context mismatch after preprocessing")
}
