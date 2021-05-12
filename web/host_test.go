// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
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
	"net/http"
  "testing"
  "time"
	"github.com/gorilla/websocket"
)

func TestAddRemoveConnection(tester *testing.T) {
  host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	conn := &websocket.Conn{}
	tester.Run("testing add connection", func(t *testing.T) {
	  socConn := host.AddConnection(conn, "1.2.3.4");
		if len(host.connections) != 1 {
			tester.Errorf("expected %d but got %d", 1, len(host.connections))
		}

		if socConn.ip != "1.2.3.4" {
			tester.Errorf("expected %s but got %s", "1.2.3.4", socConn.ip)
		}

		if host.idleConnectionTimeoutMs != 123 {
			tester.Errorf("expected %d but got %d", 123, host.idleConnectionTimeoutMs)
		}
	})
	tester.Run("testing remove connection", func(t *testing.T) {
		host.RemoveConnection(conn);
		if len(host.connections) != 0 {
			t.Errorf("final expected %d but got %d", 0, len(host.connections))
		}
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

	if len(host.connections) != 0 {
		tester.Errorf("Expected no connections after manage cycle")
	}
}

func TestGetSourceIp(tester *testing.T) {
  host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
  request, _ := http.NewRequest("GET", "", nil)

  expected := "1.1.1.1"
  request.Header.Set("X-real-IP", expected)

  actual := host.GetSourceIp(request)
  if actual != expected {
    tester.Errorf("expected %s but got %s", expected, actual)
  }
}

type DummyPreprocessor struct {
	priority int
	statusCode int
	err error
}

func (dummy *DummyPreprocessor) PreprocessPriority() int {
	return dummy.priority
}

func (dummy *DummyPreprocessor) Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error) {
	return ctx, dummy.statusCode, dummy.err
}

func TestPreprocessorSetup(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	if len(host.Preprocessors()) != 1 {
		tester.Errorf("expected one preprocessors on new host")
	}

	newPreprocessor := &DummyPreprocessor{ priority: 123, }

	host.AddPreprocessor(newPreprocessor)
	if len(host.Preprocessors()) != 2 {
		tester.Errorf("expected two preprocessors on host")
	}

	if host.Preprocessors()[1] != newPreprocessor {
		tester.Errorf("expected new preprocessors to be processed last")
	}

	newPreprocessor2 := &DummyPreprocessor{ priority: 12, }

	host.AddPreprocessor(newPreprocessor2)
	if len(host.Preprocessors()) != 3 {
		tester.Errorf("expected three preprocessors on host")
	}

	if host.Preprocessors()[1] != newPreprocessor2 {
		tester.Errorf("expected new preprocessors to be processed second")
	}

	// Should collide
	newPreprocessor3 := &DummyPreprocessor{ priority: 12, }
	err := host.AddPreprocessor(newPreprocessor3)
	if err == nil {
		tester.Errorf("Expected error from colliding preprocessors")
	}
	if len(host.Preprocessors()) != 3 {
		tester.Errorf("expected three preprocessors on host after collision")
	}
}

func TestPreprocessExecute(tester *testing.T) {
	host := NewHost("http://some.where/path", "/tmp/foo", 123, "unit test")
	newPreprocessor := &DummyPreprocessor{ priority: 123, statusCode: 321}
	host.AddPreprocessor(newPreprocessor)
	request, _ := http.NewRequest("GET", "", nil)
	ctx, statusCode, err := host.Preprocess(context.Background(), request)
	if err != nil {
		tester.Errorf("Unexpected error during testing preprocessing")
	}
	if statusCode != 321 {
		tester.Errorf("Expected status code 321 but got %d", statusCode)
	}
	if ctx.Value(ContextKeyRequestId) == nil {
		tester.Error("Context mismatch after preprocessing")
	}
}