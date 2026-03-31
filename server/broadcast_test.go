package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

type MockBroadcaster struct {
	Server   *httptest.Server
	Messages []BroadcastMessage
	onmsg    func(BroadcastMessage)
}

type BroadcastMessage struct {
	Type   int
	Kind   string
	Object map[string]interface{}
}

func (mb *MockBroadcaster) collectMessages(w http.ResponseWriter, r *http.Request) {
	c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}

		m := map[string]interface{}{}
		err = json.Unmarshal(message, &m)
		if err != nil {
			break
		}

		kind, ok := m["Kind"].(string)
		if !ok {
			break
		}

		obj, ok := m["Object"].(map[string]interface{})
		if !ok {
			break
		}

		msg := BroadcastMessage{Type: mt, Kind: kind, Object: obj}
		mb.Messages = append(mb.Messages, msg)
		if mb.onmsg != nil {
			mb.onmsg(msg)
		}
	}
}

func (mb *MockBroadcaster) Close() {
	mb.Server.Close()
}

type BroadcastMatcher struct {
	validators []BroadcastValidator
}

type BroadcastValidator func(BroadcastMessage) error

func NewBroadcastMatcher(opts ...BroadcastValidator) BroadcastMatcher {
	m := BroadcastMatcher{
		validators: opts,
	}

	return m
}

func (m *BroadcastMatcher) Validate(msg BroadcastMessage) error {
	for _, v := range m.validators {
		if err := v(msg); err != nil {
			return err
		}
	}

	return nil
}

func BroadcastKindEq(kind string) BroadcastValidator {
	return func(msg BroadcastMessage) error {
		if msg.Kind != kind {
			return fmt.Errorf("expected kind %q, got %q", kind, msg.Kind)
		}

		return nil
	}
}

func BroadcastObjectFieldExists(key string) BroadcastValidator {
	return func(msg BroadcastMessage) error {
		_, ok := msg.Object[key]
		if !ok {
			return fmt.Errorf("expected field %q to exist", key)
		}

		return nil
	}
}

func BroadcastObjectFieldEq(key string, value interface{}) BroadcastValidator {
	switch v := value.(type) {
	case int:
		value = float64(v)
	}

	return func(msg BroadcastMessage) error {
		if msg.Object[key] != value {
			return fmt.Errorf("expected field %q to be %v, got %v", key, value, msg.Object[key])
		}

		return nil
	}
}

func MockBroadcast(t *testing.T, srv *Server, onmsg func(BroadcastMessage)) *MockBroadcaster {
	mb := &MockBroadcaster{onmsg: onmsg}
	s := httptest.NewServer(http.HandlerFunc(mb.collectMessages))

	// Convert http://127.0.0.1 to ws://127.0.0.1
	u := "ws" + strings.TrimPrefix(s.URL, "http")

	// Connect to the server
	wsconn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv.Host.AddConnection("11111111-1111-1111-1111-111111111111", wsconn, "127.0.0.1")

	mb.Server = s

	return mb
}
