package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestReverseLookupHandler(t *testing.T) {
	h := UtilHandler{
		server: &Server{
			Config: &config.ServerConfig{
				Dns: "",
			},
		},
	}

	body := []byte(`["1.0.0.1", "2.0.0.2", "3.0.0.3", "4.0.0.4"]`)

	r := httptest.NewRequest("PUT", "/reverse-lookup", bytes.NewReader(body))

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()

	h.putReverseLookup(w, r)

	raw := w.Body.Bytes()
	results := map[string][]string{}

	err := json.Unmarshal(raw, &results)
	assert.NoError(t, err)

	assert.Equal(t, 4, len(results))
	for _, names := range results {
		assert.NotEmpty(t, names)
	}
}
