package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

type FakeConfigstore struct {
	SyncModuleError error
}

func (f *FakeConfigstore) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	return nil, nil
}

func (f *FakeConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	return nil
}

func (f *FakeConfigstore) SyncSettings(ctx context.Context) error {
	return nil
}

func (f *FakeConfigstore) SyncModule(ctx context.Context, module string, force bool) error {
	return f.SyncModuleError
}

func TestConfigHandler_putSyncModule(t *testing.T) {
	tests := []struct {
		name           string
		module         string
		force          string
		syncModuleErr  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Success without force",
			module:         "soc",
			force:          "",
			syncModuleErr:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "Success with force",
			module:         "myapp",
			force:          "true",
			syncModuleErr:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "SyncModule error",
			module:         "soc",
			force:          "false",
			syncModuleErr:  errors.New("ERROR_SYNC_FAILED"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "ERROR_SYNC_FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewFakeAuthorizedServer(nil)
			srv.Configstore = &FakeConfigstore{
				SyncModuleError: tt.syncModuleErr,
			}

			h := &ConfigHandler{
				server: srv,
			}

			r := chi.NewRouter()
			r.Put("/sync/{module}", h.putSyncModule)

			w := httptest.NewRecorder()
			req := httptest.NewRequest("PUT", "/sync/"+tt.module+"?force="+tt.force, bytes.NewReader([]byte{}))
			ctx := context.WithValue(req.Context(), web.ContextKeyRequestId, "test-request")
			ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
			req = req.WithContext(ctx)

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			} else {
				assert.Empty(t, w.Body.String())
			}
		})
	}
}

func TestConfigHandler_putSyncModule_NoConfigstore(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = nil

	h := &ConfigHandler{
		server: srv,
	}

	r := chi.NewRouter()
	r.Use(h.configEnabled)
	r.Put("/sync/{module}", h.putSyncModule)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/sync/soc", bytes.NewReader([]byte{}))
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestId, "test-request")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Contains(t, w.Body.String(), "The request could not be processed.")
}
