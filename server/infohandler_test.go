package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestInfoHandler_getCustomReports(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  map[string]string
		expectLogs  bool
		expectedMap map[string]string
		pathExists  bool
	}{
		{
			name:        "Empty directory",
			setupFiles:  map[string]string{},
			expectedMap: map[string]string{},
			pathExists:  true,
		},
		{
			name: "Directory with markdown files",
			setupFiles: map[string]string{
				"report1.md":       "Test Report 1\n===============\nContent here",
				"report2.md":       "Another Report\n==============\nMore content",
				"not_markdown.txt": "This should be ignored",
			},
			expectedMap: map[string]string{
				"report1.md": "Test Report 1",
				"report2.md": "Another Report",
			},
			pathExists: true,
		},
		{
			name: "Markdown file without title format",
			setupFiles: map[string]string{
				"simple.md": "# Simple Header\nNo underline format",
			},
			expectedMap: map[string]string{
				"simple.md": "simple.md",
			},
			pathExists: true,
		},
		{
			name: "Mixed files and subdirectories",
			setupFiles: map[string]string{
				"report.md":        "Valid Report\n=============\nContent",
				"subdir/nested.md": "Should be ignored as it's in subdir",
			},
			expectedMap: map[string]string{
				"report.md": "Valid Report",
			},
			pathExists: true,
		},
		{
			name:        "Non-existent directory",
			setupFiles:  map[string]string{},
			expectedMap: map[string]string{},
			expectLogs:  true,
			pathExists:  false,
		},
		{
			name: "File read error simulation",
			setupFiles: map[string]string{
				"good.md": "Good Report\n===========\nContent",
			},
			expectedMap: map[string]string{
				"good.md": "Good Report",
			},
			pathExists: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testDir string
			if tt.pathExists {
				testDir = t.TempDir()

				for filename, content := range tt.setupFiles {
					filePath := filepath.Join(testDir, filename)
					if filepath.Dir(filename) != "." {
						err := os.MkdirAll(filepath.Dir(filePath), 0755)
						require.NoError(t, err)
					}
					err := os.WriteFile(filePath, []byte(content), 0644)
					require.NoError(t, err)
				}
			} else {
				testDir = "/nonexistent/path"
			}

			handler := &InfoHandler{}

			result := handler.getCustomReports(testDir)

			assert.Equal(t, tt.expectedMap, result)
		})
	}
}

func TestInfoHandler_parseReportTitle(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		deflt    string
		expected string
	}{
		{
			name: "Valid title with equals underline",
			content: []byte(`My Report Title
===============
Some content here`),
			deflt:    "default.md",
			expected: "My Report Title",
		},
		{
			name: "Multiple underlines, first one wins",
			content: []byte(`First Title
===========
Content
Second Title
============
More content`),
			deflt:    "default.md",
			expected: "First Title",
		},
		{
			name: "No valid title format",
			content: []byte(`# Header
Some content
## Another header`),
			deflt:    "fallback.md",
			expected: "fallback.md",
		},
		{
			name:     "Empty content",
			content:  []byte(``),
			deflt:    "empty.md",
			expected: "empty.md",
		},
		{
			name: "Only underline without title",
			content: []byte(`===============
Content`),
			deflt:    "noTitle.md",
			expected: "noTitle.md",
		},
		{
			name: "Title with whitespace",
			content: []byte(`   Trimmed Title   
===================
Content`),
			deflt:    "default.md",
			expected: "Trimmed Title",
		},
		{
			name: "Underline too short",
			content: []byte(`Title Here
===
Content`),
			deflt:    "short.md",
			expected: "Title Here",
		},
		{
			name:     "Single line content",
			content:  []byte(`Just one line`),
			deflt:    "single.md",
			expected: "single.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &InfoHandler{}
			result := handler.parseReportTitle(tt.content, tt.deflt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInfoHandler_getInfo_NotificationLicense(t *testing.T) {
	defer licensing.Shutdown()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	mockUserstore := servermock.NewMockUserstore(ctrl)

	srv := &Server{
		Host:              web.NewHost("127.0.0.1:0", "", 1000, "1.0", []byte("12345678901234567890123456789012")),
		Notificationstore: mockStore,
		Userstore:         mockUserstore,
		Config: &config.ServerConfig{
			SrvKeyBytes: []byte("12345678901234567890123456789012"),
		},
	}

	mockUserstore.EXPECT().GetUserById(gomock.Any(), "user-1").Return(&model.User{
		Id:         "user-1",
		Email:      "user@soc.local",
		TotpStatus: "enabled",
	}, nil).AnyTimes()

	h := &InfoHandler{server: srv}

	// 1. When FEAT_NTF is disabled: GetLastUnreadTime should NOT be called
	licensing.Shutdown()
	req := httptest.NewRequest("GET", "/api/info", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
	ctx = context.WithValue(ctx, web.ContextKeyRequestCSRFExempt, false)
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.getInfo(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp1 model.Info
	_ = json.Unmarshal(w.Body.Bytes(), &resp1)
	assert.Nil(t, resp1.LastUnreadNotificationTime)
	assert.False(t, resp1.NotificationsStarted)

	// 2. When FEAT_NTF is enabled: GetLastUnreadTime SHOULD be called
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
	fixedTime := time.Date(2026, 8, 20, 17, 0, 0, 0, time.UTC)
	mockStore.EXPECT().GetLastUnreadTime(gomock.Any()).Return(&fixedTime, nil).Times(1)

	req2 := httptest.NewRequest("GET", "/api/info", nil)
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	h.getInfo(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	var resp2 model.Info
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)
	assert.NotNil(t, resp2.LastUnreadNotificationTime)
	assert.Equal(t, fixedTime, *resp2.LastUnreadNotificationTime)
	assert.True(t, resp2.NotificationsStarted)

	// 3. When FEAT_NTF is enabled but Notificationstore is nil: NotificationsStarted is false
	srv.Notificationstore = nil
	req3 := httptest.NewRequest("GET", "/api/info", nil)
	req3 = req3.WithContext(ctx)
	w3 := httptest.NewRecorder()
	h.getInfo(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
	var resp3 model.Info
	_ = json.Unmarshal(w3.Body.Bytes(), &resp3)
	assert.Nil(t, resp3.LastUnreadNotificationTime)
	assert.False(t, resp3.NotificationsStarted)
}
