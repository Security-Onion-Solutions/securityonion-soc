package model

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSubgrid_refreshAccessToken(t *testing.T) {
	t.Run("token is valid, no refresh needed", func(t *testing.T) {
		grid := Subgrid{
			TokenExpiration: time.Now().Add(time.Hour),
			AccessToken:     "valid-token",
		}
		err := grid.refreshAccessToken()
		if err != nil {
			t.Errorf("refreshAccessToken() error = %v", err)
		}
		if grid.AccessToken != "valid-token" {
			t.Errorf("AccessToken should not be refreshed, got = %v", grid.AccessToken)
		}
	})

	t.Run("successful token refresh", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/oauth2/token" {
				t.Errorf("Expected request to /oauth2/token, got %v", req.URL.Path)
			}
			if req.Method != http.MethodPost {
				t.Errorf("Expected POST request, got %v", req.Method)
			}
			rw.WriteHeader(http.StatusOK)
			rw.Header().Set("Content-Type", "application/json")
			resp := `{"access_token": "new-access-token", "expires_in": 3600}`
			rw.Write([]byte(resp))
		}))
		defer server.Close()

		grid := Subgrid{
			ManagerUrl:   server.URL,
			ClientId:     "socl_test",
			ClientSecret: "test-secret",
		}
		err := grid.refreshAccessToken()
		if err != nil {
			t.Errorf("refreshAccessToken() error = %v", err)
		}
		if grid.AccessToken != "new-access-token" {
			t.Errorf("AccessToken not updated, got = %v", grid.AccessToken)
		}
		if grid.TokenExpiration.Before(time.Now()) {
			t.Errorf("TokenExpiration not updated, got = %v", grid.TokenExpiration)
		}
	})

	t.Run("failed token refresh - network error", func(t *testing.T) {
		grid := Subgrid{
			ManagerUrl:   "http://localhost:invalid-port", // Simulate network error
			ClientId:     "socl_test",
			ClientSecret: "test-secret",
		}
		err := grid.refreshAccessToken()
		if err == nil {
			t.Errorf("Expected refreshAccessToken() to return error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to create token") {
			t.Errorf("Expected error to contain 'failed to create token', got = %v", err)
		}
	})

	t.Run("failed token refresh - invalid credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		grid := Subgrid{
			ManagerUrl:   server.URL,
			ClientId:     "socl_test",
			ClientSecret: "test-secret",
		}
		err := grid.refreshAccessToken()
		if err == nil {
			t.Errorf("Expected refreshAccessToken() to return error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to get token, status code: 401") {
			t.Errorf("Expected error to contain 'failed to get token, status code: 401', got = %v", err)
		}
	})

	t.Run("failed token refresh - invalid response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
			rw.Header().Set("Content-Type", "application/json")
			resp := `{"invalid_response": "invalid"}`
			rw.Write([]byte(resp))
		}))
		defer server.Close()

		grid := Subgrid{
			ManagerUrl:   server.URL,
			ClientId:     "socl_test",
			ClientSecret: "test-secret",
		}
		err := grid.refreshAccessToken()
		if err == nil {
			t.Errorf("Expected refreshAccessToken() to return error, got nil")
		}
		if !strings.Contains(err.Error(), "access_token not found in token response") {
			t.Errorf("Expected error to contain 'access_token not found in token response', got = %v", err)
		}
	})
}

func TestSubgrid_makeApiCall(t *testing.T) {
	t.Run("successful api call", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/connect/testpath" {
				t.Errorf("Expected request to /connect/testpath, got %v", req.URL.Path)
			}
			if req.Method != http.MethodGet {
				t.Errorf("Expected GET request, got %v", req.Method)
			}
			if req.Header.Get("Authorization") != "Bearer new-access-token" {
				t.Errorf("Expected Authorization header with token, got %v", req.Header.Get("Authorization"))
			}
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(`{"status": "ok"}`))
		}))
		defer server.Close()

		grid := Subgrid{
			ManagerUrl:      server.URL,
			ClientId:        "socl_test",
			ClientSecret:    "test-secret",
			AccessToken:     "new-access-token", // Assume token is already refreshed
			TokenExpiration: time.Now().Add(time.Hour),
		}

		resp, err := grid.MakeApiCall(http.MethodGet, "/testpath", nil, nil)
		if err != nil {
			t.Errorf("makeApiCall() error = %v", err)
		}

		bytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, `{"status": "ok"}`, string(bytes))
	})

	t.Run("failed api call - refresh token fails", func(t *testing.T) {
		grid := Subgrid{
			ManagerUrl:   "http://localhost:invalid-port", // Simulate network error for token refresh
			ClientId:     "socl_test",
			ClientSecret: "test-secret",
		}

		resp, err := grid.MakeApiCall(http.MethodGet, "/testpath", nil, nil)
		if err == nil {
			t.Errorf("Expected makeApiCall() to return error, got nil")
		}
		if resp != nil {
			t.Errorf("Expected nil response when refresh token fails, got = %v", resp)
		}
		if !strings.Contains(err.Error(), "failed to refresh access token") {
			t.Errorf("Expected error to contain 'failed to refresh access token', got = %v", err)
		}
	})

	t.Run("failed api call - server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		grid := Subgrid{
			ManagerUrl:      server.URL,
			ClientId:        "socl_test",
			ClientSecret:    "test-secret",
			AccessToken:     "new-access-token", // Assume token is already refreshed
			TokenExpiration: time.Now().Add(time.Hour),
		}

		resp, err := grid.MakeApiCall(http.MethodGet, "/testpath", nil, nil)
		if err == nil {
			t.Errorf("Expected makeApiCall() to return error, got nil")
		}
		if resp != nil {
			t.Errorf("Expected nil response for server error, got = %v", resp)
		}
		if !strings.Contains(err.Error(), "API call failed with status code: 500") {
			t.Errorf("Expected error to contain 'API call failed with status code: 500', got = %v", err)
		}
	})

	t.Run("api call with body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost {
				t.Errorf("Expected POST request, got %v", req.Method)
			}
			body, _ := io.ReadAll(req.Body)
			if string(body) != `{"key":"value"}` {
				t.Errorf("Expected request body %v, got %v", `{"key":"value"}`, string(body))
			}
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(`{"status": "ok"}`))
		}))
		defer server.Close()

		grid := Subgrid{
			ManagerUrl:      server.URL,
			ClientId:        "socl_test",
			ClientSecret:    "test-secret",
			AccessToken:     "new-access-token", // Assume token is already refreshed
			TokenExpiration: time.Now().Add(time.Hour),
		}

		requestBody := bytes.NewBuffer([]byte(`{"key":"value"}`))
		resp, err := grid.MakeApiCall(http.MethodPost, "/testpath", requestBody, nil)
		if err != nil {
			t.Errorf("makeApiCall() error = %v", err)
		}

		bytes, _ := io.ReadAll(resp.Body)
		assert.Equal(t, `{"status": "ok"}`, string(bytes))
	})
}

func TestSubgrid_Verify(t *testing.T) {
	tests := []struct {
		name    string
		grid    Subgrid
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid subgrid",
			grid: Subgrid{
				Enabled:      true,
				Id:           "test-subgrid",
				ManagerUrl:   "https://manager.example.com",
				ClientId:     "socl_test_client",
				ClientSecret: "abc",
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			grid: Subgrid{
				Enabled:    true,
				Id:         "",
				ManagerUrl: "https://manager.example.com",
				ClientId:   "socl_test_client",
			},
			wantErr: true,
			errMsg:  "invalid subgrid ID; must not be empty",
		},
		{
			name: "empty ManagerUrl",
			grid: Subgrid{
				Enabled:    true,
				Id:         "test-subgrid",
				ManagerUrl: "",
				ClientId:   "socl_test_client",
			},
			wantErr: true,
			errMsg:  "invalid subgrid Manager URL; must not be empty",
		},
		{
			name: "ManagerUrl without HTTPS",
			grid: Subgrid{
				Enabled:    true,
				Id:         "test-subgrid",
				ManagerUrl: "http://manager.example.com",
				ClientId:   "socl_test_client",
			},
			wantErr: true,
			errMsg:  "invalid subgrid Manager URL; must specify the HTTPS protocol",
		},
		{
			name: "empty ClientId",
			grid: Subgrid{
				Enabled:    true,
				Id:         "test-subgrid",
				ManagerUrl: "https://manager.example.com",
				ClientId:   "",
			},
			wantErr: true,
			errMsg:  "invalid subgrid client ID; must not be empty",
		},
		{
			name: "ClientId without prefix",
			grid: Subgrid{
				Enabled:    true,
				Id:         "test-subgrid",
				ManagerUrl: "https://manager.example.com",
				ClientId:   "test_client",
			},
			wantErr: true,
			errMsg:  "invalid subgrid client ID; malformed client ID",
		},
		{
			name: "not empty ClientSecret",
			grid: Subgrid{
				Enabled:      true,
				Id:           "test-subgrid",
				ManagerUrl:   "https://manager.example.com",
				ClientId:     "socl_test_client",
				ClientSecret: "",
			},
			wantErr: true,
			errMsg:  "invalid subgrid client secret; must not be empty",
		},
		{
			name: "not empty ClientSecret, but disabled so ignore it",
			grid: Subgrid{
				Enabled:      false,
				Id:           "test-subgrid",
				ManagerUrl:   "https://manager.example.com",
				ClientId:     "socl_test_client",
				ClientSecret: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.grid.Verify()
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					assert.Equal(t, tt.errMsg, err.Error())
				} else {
					t.Log("Expected error: " + tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
