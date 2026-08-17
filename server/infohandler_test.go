package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getInfoResponse(srv *Server) *model.Info {
	h := &InfoHandler{server: srv}

	req := httptest.NewRequest("GET", "/info", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "user-id-1")
	ctx = context.WithValue(ctx, web.ContextKeyRequestCSRFExempt, true)
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.getInfo(w, req)

	info := &model.Info{}
	json.Unmarshal(w.Body.Bytes(), info)
	return info
}

// The client derives the events health link from this per-grid flag
func TestInfoHandler_EventstoreEnabled(t *testing.T) {
	licensing.Test("foo", 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Eventstore = NewFakeEventstore()
	assert.True(t, getInfoResponse(srv).EventstoreEnabled)

	srv.Eventstore = nil
	assert.False(t, getInfoResponse(srv).EventstoreEnabled)
}

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
