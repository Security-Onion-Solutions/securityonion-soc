package export

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"io"

	"github.com/security-onion-solutions/securityonion-soc/agent"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

// FakeClientAuth is a mock implementation of web.ClientAuth for testing purposes
type FakeClientAuth struct{}

func (f FakeClientAuth) Authorize(request *http.Request) error {
	return nil // No authorization needed for tests
}

func TestInit(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	err := export.Init(nil)
	assert.Nil(t, err)
}

const caseJson = `{
	"id":"case1", 
	"createTime": "2025-07-01T16:41:09.698562704-04:00",
	"updateTime": "2025-07-01T16:41:09.698562704-04:00"
}`

const commentJson = `[{
	"id":"comment1", 
	"createTime": "2025-07-01T16:41:09.698562704-04:00",
	"updateTime": "2025-07-01T16:41:09.698562704-04:00",
	"description": "This is a test comment",
	"hours": 1.2
}]`

const attachmentsJson = `[{
	"id":"attachment1", 
	"createTime": "2025-07-01T16:41:09.698562704-04:00",
	"updateTime": "2025-07-01T16:41:09.698562704-04:00",
	"description": "This is a test file"
}]`

const observablesJson = `[{
	"id":"observable1", 
	"createTime": "2025-07-01T16:41:09.698562704-04:00",
	"updateTime": "2025-07-01T16:41:09.698562704-04:00",
	"description": "This is a test obs"
}]`

const eventsJson = `[{
	"id":"event1", 
	"createTime": "2025-07-01T16:41:09.698562704-04:00",
	"updateTime": "2025-07-01T16:41:09.698562704-04:00",
	"fields": {
		"soc_timestamp": "2025-07-01T16:41:09.698562704-04:00",
		"id": "xyz",
		"tags": ["alert"],
		"rule.uuid": "detection123"
	}
}]`

const detectionJson = `{
	"publicId": "detection123",
	"name": "Test Detection",
	"description": "This is a test detection"
}`

const historyJson = `[{
	"id":"history1",
	"createTime": "2025-07-01T16:41:09.698562704-04:00",
	"updateTime": "2025-07-01T16:41:09.698562704-04:00"
}]`

func TestProcessJob(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	config := module.ModuleConfig{}
	config["executablePath"] = "../../../scripts/md2pdf"
	config["templatePath"] = "../../../templates/export"
	export.Init(config)
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	export.agent.Client.MockStringResponse(`[{"id":"xyz"}]`, 200, nil) // Get Users
	export.agent.Client.MockStringResponse(caseJson, 200, nil)         // Get Case
	export.agent.Client.MockStringResponse(commentJson, 200, nil)      // Get Case Comments
	export.agent.Client.MockStringResponse(attachmentsJson, 200, nil)  // Get Case Attachments
	export.agent.Client.MockStringResponse(observablesJson, 200, nil)  // Get Case Observables
	export.agent.Client.MockStringResponse(eventsJson, 200, nil)       // Get Case Related Events
	export.agent.Client.MockStringResponse(detectionJson, 200, nil)    // Get Detection for Event
	export.agent.Client.MockStringResponse(historyJson, 200, nil)      // Get Case History

	// Test: Wrong job kind
	job := model.NewJob()
	job.Kind = "pcap"
	reader, err := export.ProcessJob(job, nil)
	assert.Nil(t, err)
	assert.Nil(t, reader)
	assert.Empty(t, job.Results)

	// Test: Missing parameters
	job = model.NewJob()
	job.Kind = model.JOB_KIND_EXPORT
	reader, err = export.ProcessJob(job, nil)
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "missing required parameters")
	assert.Empty(t, job.Results)

	// Test: Missing type parameter
	job = model.NewJob()
	job.Kind = model.JOB_KIND_EXPORT
	job.Filter.Parameters = make(map[string]interface{})
	job.Filter.Parameters["id"] = "testid"
	reader, err = export.ProcessJob(job, nil)
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "missing required parameter: type")
	assert.Empty(t, job.Results)

	// Test: Missing templates
	job = model.NewJob()
	job.Kind = model.JOB_KIND_EXPORT
	job.Filter.Parameters = make(map[string]interface{})
	job.Filter.Parameters["type"] = "case"
	job.Filter.Parameters["id"] = "case1"
	reader, err = export.ProcessJob(job, nil)
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "failed to load templates for export")
	assert.Empty(t, job.Results)
}

func TestGetCaseDetailsFromServer(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	caseId := "test-case-id"

	// Mock successful responses
	export.agent.Client.MockStringResponse(caseJson, 200, nil)        // Get Case
	export.agent.Client.MockStringResponse(commentJson, 200, nil)     // Get Case Comments
	export.agent.Client.MockStringResponse(attachmentsJson, 200, nil) // Get Case Attachments
	export.agent.Client.MockStringResponse(observablesJson, 200, nil) // Get Case Observables
	export.agent.Client.MockStringResponse(eventsJson, 200, nil)      // Get Case Related Events
	export.agent.Client.MockStringResponse(detectionJson, 200, nil)   // Get Detection for Event
	export.agent.Client.MockStringResponse(historyJson, 200, nil)     // Get Case History

	templateInput, err := export.getCaseDetailsFromServer(caseId)
	assert.Nil(t, err)
	assert.NotNil(t, templateInput)

	assert.Equal(t, "case1", templateInput.Case.Id)
	assert.Len(t, templateInput.Comments, 1)
	assert.Equal(t, 1.2, templateInput.TotalHours)
	assert.Len(t, templateInput.Attachments, 1)
	assert.Len(t, templateInput.Observables, 1)
	assert.Len(t, templateInput.RelatedEvents, 1)
	assert.Len(t, templateInput.Detections, 1)
	assert.Equal(t, "detection123", templateInput.Detections[0].PublicID)
	assert.Len(t, templateInput.History, 1)

	// Test case where getting case data fails
	export.agent.Client.MockStringResponse("", 500, assert.AnError) // Simulate error
	_, err = export.getCaseDetailsFromServer(caseId)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assert.AnError general error for testing")

	// Test case where getting comments fails (should still return templateInput)
	export.agent.Client.MockStringResponse(caseJson, 200, nil)
	export.agent.Client.MockStringResponse("", 500, assert.AnError) // Simulate error for comments
	export.agent.Client.MockStringResponse(attachmentsJson, 200, nil)
	export.agent.Client.MockStringResponse(observablesJson, 200, nil)
	export.agent.Client.MockStringResponse(eventsJson, 200, nil)
	export.agent.Client.MockStringResponse(detectionJson, 200, nil)
	export.agent.Client.MockStringResponse(historyJson, 200, nil)
	templateInput, err = export.getCaseDetailsFromServer(caseId)
	assert.Nil(t, err) // Error is logged but not returned for comments, attachments, observables, events, history
	assert.NotNil(t, templateInput)
}

func TestPrerequisiteModules(t *testing.T) {
	export := NewExport(nil)
	assert.Nil(t, export.PrerequisiteModules())
}

func TestLifecycle(t *testing.T) {
	export := NewExport(nil)
	assert.Nil(t, export.Start())
	assert.Nil(t, export.Stop())
	assert.False(t, export.IsRunning())
}

func TestStripTrailingSlash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Path with trailing slash",
			input:    "/path/to/dir/",
			expected: "/path/to/dir",
		},
		{
			name:     "Path without trailing slash",
			input:    "/path/to/dir",
			expected: "/path/to/dir",
		},
		{
			name:     "Empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "Path with only a slash",
			input:    "/",
			expected: "",
		},
		{
			name:     "Path with multiple trailing slashes",
			input:    "/path/to/dir///",
			expected: "/path/to/dir//",
		},
		{
			name:     "Path with backslashes (should not be affected)",
			input:    "C:\\path\\to\\dir\\",
			expected: "C:\\path\\to\\dir\\",
		},
		{
			name:     "Root path",
			input:    "/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripTrailingSlash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetParamsFromTemplate(t *testing.T) {
	export := NewExport(nil)

	tests := []struct {
		name         string
		filepath     string
		param        string
		params       string
		fileContent  string
		expectedArgs []string
		expectError  bool
	}{
		{
			name:         "No param or params specified",
			filepath:     "testdata/template.md",
			param:        "",
			params:       "",
			fileContent:  "/* pdf_param: value */",
			expectedArgs: []string{},
			expectError:  false, // Error is logged, but function returns empty slice
		},
		{
			name:         "No template filepath specified",
			filepath:     "",
			param:        "pdf_param:",
			params:       "",
			fileContent:  "/* pdf_param: value */",
			expectedArgs: []string{},
			expectError:  false, // Error is logged, but function returns empty slice
		},
		{
			name:         "File not found",
			filepath:     "nonexistent.md",
			param:        "pdf_param:",
			params:       "",
			fileContent:  "",
			expectedArgs: []string{},
			expectError:  false, // Error is logged, but function returns empty slice
		},
		{
			name:         "Single parameter extraction",
			filepath:     "testdata/template_single.md",
			param:        "pdf_param:",
			params:       "",
			fileContent:  "Some content\n/* pdf_param: param1 */\nMore content",
			expectedArgs: []string{"param1"},
			expectError:  false,
		},
		{
			name:         "Multiple parameters extraction",
			filepath:     "testdata/template_multiple.md",
			param:        "",
			params:       "pdf_params:",
			fileContent:  "Some content\n/* pdf_params: paramA paramB paramC */\nMore content",
			expectedArgs: []string{"paramA", "paramB", "paramC"},
			expectError:  false,
		},
		{
			name:         "Mixed parameters (single first)",
			filepath:     "testdata/template_mixed1.md",
			param:        "pdf_param:",
			params:       "pdf_params:",
			fileContent:  "/* pdf_param: single1 */\n/* pdf_params: multi1 multi2 */",
			expectedArgs: []string{"single1", "multi1", "multi2"},
			expectError:  false,
		},
		{
			name:         "Mixed parameters (multiple first)",
			filepath:     "testdata/template_mixed2.md",
			param:        "pdf_param:",
			params:       "pdf_params:",
			fileContent:  "/* pdf_params: multiA multiB */\n/* pdf_param: singleA */",
			expectedArgs: []string{"multiA", "multiB", "singleA"},
			expectError:  false,
		},
		{
			name:         "Empty file",
			filepath:     "testdata/template_empty.md",
			param:        "pdf_param:",
			params:       "pdf_params:",
			fileContent:  "",
			expectedArgs: []string{},
			expectError:  false,
		},
		{
			name:         "File with no matching parameters",
			filepath:     "testdata/template_nomatch.md",
			param:        "pdf_param:",
			params:       "pdf_params:",
			fileContent:  "Some content\nNo params here\nAnother line",
			expectedArgs: []string{},
			expectError:  false,
		},
		{
			name:         "Parameter with leading/trailing spaces",
			filepath:     "testdata/template_spaces.md",
			param:        "pdf_param:",
			params:       "",
			fileContent:  "/* pdf_param:  valueWithSpaces  */",
			expectedArgs: []string{"valueWithSpaces"},
			expectError:  false,
		},
		{
			name:         "Multiple parameters with leading/trailing spaces",
			filepath:     "testdata/template_multi_spaces.md",
			param:        "",
			params:       "pdf_params:",
			fileContent:  "/* pdf_params:  val1  val2   val3  */",
			expectedArgs: []string{"val1", "val2", "val3"},
			expectError:  false,
		},
	}

	// Create a temporary directory for test files
	err := os.MkdirAll("testdata", 0755)
	assert.Nil(t, err)
	defer os.RemoveAll("testdata") // Clean up after tests

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.filepath != "" && !strings.Contains(tt.filepath, "nonexistent") {
				// Create temporary file for the test case
				tmpfile, err := os.Create(tt.filepath)
				assert.Nil(t, err)
				_, err = tmpfile.WriteString(tt.fileContent)
				assert.Nil(t, err)
				tmpfile.Close()
			}

			args := export.getParamsFromTemplate(tt.filepath, tt.param, tt.params)
			assert.Equal(t, tt.expectedArgs, args)
		})
	}
}

func TestGetUserDetail(t *testing.T) {
	export := NewExport(nil)

	// Mock usersById map
	export.usersById = map[string]*model.User{
		"user1": {
			Id:             "user1",
			Email:          "user1@example.com",
			FirstName:      "John",
			LastName:       "Doe",
			Note:           "Test User 1",
			OidcStatus:     "active",
			Status:         "enabled",
			SearchUsername: "john.doe",
			Roles:          []string{"admin", "analyst"},
		},
		"user2": {
			Id:             "user2",
			Email:          "user2@example.com",
			FirstName:      "Jane",
			LastName:       "Smith",
			Note:           "",
			OidcStatus:     "inactive",
			Status:         "disabled",
			SearchUsername: "jane.smith",
			Roles:          []string{"analyst"},
		},
	}

	tests := []struct {
		name     string
		attr     string
		userId   string
		expected string
	}{
		{
			name:     "Existing user, get email",
			attr:     "email",
			userId:   "user1",
			expected: "user1@example.com",
		},
		{
			name:     "Existing user, get firstname",
			attr:     "firstname",
			userId:   "user1",
			expected: "John",
		},
		{
			name:     "Existing user, get lastname",
			attr:     "lastname",
			userId:   "user1",
			expected: "Doe",
		},
		{
			name:     "Existing user, get note",
			attr:     "note",
			userId:   "user1",
			expected: "Test User 1",
		},
		{
			name:     "Existing user, get oidcstatus",
			attr:     "oidcstatus",
			userId:   "user1",
			expected: "active",
		},
		{
			name:     "Existing user, get status",
			attr:     "status",
			userId:   "user1",
			expected: "enabled",
		},
		{
			name:     "Existing user, get searchusername",
			attr:     "searchusername",
			userId:   "user1",
			expected: "john.doe",
		},
		{
			name:     "Existing user, get roles",
			attr:     "roles",
			userId:   "user1",
			expected: "admin, analyst",
		},
		{
			name:     "Existing user, attribute not found",
			attr:     "invalid_attr",
			userId:   "user1",
			expected: "user1", // Should return userId if attribute not found
		},
		{
			name:     "Non-existing user",
			attr:     "email",
			userId:   "user3",
			expected: "user3", // Should return userId if user not found
		},
		{
			name:     "Existing user, empty note",
			attr:     "note",
			userId:   "user2",
			expected: "",
		},
		{
			name:     "Existing user, get roles for user with single role",
			attr:     "roles",
			userId:   "user2",
			expected: "analyst",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := export.getUserDetail(tt.attr, tt.userId)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPopulateTemplatesCache(t *testing.T) {
	export := NewExport(nil)

	// Create a temporary directory for test templates
	tmpDir, err := os.MkdirTemp("", "export_templates_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir) // Clean up after tests

	export.templatePath = tmpDir

	// Create custom template directory
	customDir := tmpDir + "/custom"
	err = os.MkdirAll(customDir, 0755)
	assert.Nil(t, err)

	// Test case 1: Valid templates
	t.Run("ValidTemplates", func(t *testing.T) {
		// Create dummy template files
		err = os.WriteFile(customDir+"/template1.md", []byte("Template 1 content"), 0644)
		assert.Nil(t, err)
		err = os.WriteFile(customDir+"/template2.md", []byte("Template 2 content"), 0644)
		assert.Nil(t, err)

		export.populateTemplatesCache()

		assert.NotNil(t, export.templates)
		assert.Contains(t, export.templates.DefinedTemplates(), "template1.md")
		assert.Contains(t, export.templates.DefinedTemplates(), "template2.md")
	})

	// Test case 2: Invalid template path (should log error, templates should be nil)
	t.Run("InvalidTemplatePath", func(t *testing.T) {
		export.templates = nil // Reset templates
		export.templatePath = "/nonexistent/path/to/templates"

		export.populateTemplatesCache()

		assert.Nil(t, export.templates) // Templates should remain nil or be reset to nil on error
	})
}

func TestFormatDateTime(t *testing.T) {
	export := NewExport(nil)

	// Define a specific time for testing
	testTime := time.Date(2025, time.July, 15, 17, 30, 0, 0, time.UTC)
	testTimePtr := &testTime

	tests := []struct {
		name     string
		format   string
		time     *time.Time
		expected string
	}{
		{
			name:     "RFC3339 format",
			format:   time.RFC3339,
			time:     testTimePtr,
			expected: "2025-07-15T17:30:00Z",
		},
		{
			name:     "Custom format YYYY-MM-DD",
			format:   "2006-01-02",
			time:     testTimePtr,
			expected: "2025-07-15",
		},
		{
			name:     "Custom format HH:MM:SS",
			format:   "15:04:05",
			time:     testTimePtr,
			expected: "17:30:00",
		},
		{
			name:     "Full custom format",
			format:   "Jan 02, 2006 3:04 PM",
			time:     testTimePtr,
			expected: "Jul 15, 2025 5:30 PM",
		},
		{
			name:     "Empty format string",
			format:   "",
			time:     testTimePtr,
			expected: "", // time.Format("") returns an empty string
		},
		{
			name:     "Nil time pointer",
			format:   time.RFC3339,
			time:     nil,
			expected: "", // Calling Format on a nil time.Time pointer will panic, but the function signature takes *time.Time, so it should be handled.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.time == nil {
				// Expect a panic if time is nil, as per Go's time.Format behavior
				assert.Panics(t, func() {
					export.formatDateTime(tt.format, tt.time)
				}, "The code should panic when time is nil")
			} else {
				result := export.formatDateTime(tt.format, tt.time)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestPopulateUsersCache(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	// Test case 1: Successful user fetch
	t.Run("SuccessfulFetch", func(t *testing.T) {
		mockUsersJson := `[{"id":"user1","email":"user1@example.com"},{"id":"user2","email":"user2@example.com"}]`
		export.agent.Client.MockStringResponse(mockUsersJson, 200, nil)

		export.populateUsersCache()

		assert.NotNil(t, export.usersById)
		assert.Len(t, export.usersById, 2)
		assert.Equal(t, "user1@example.com", export.usersById["user1"].Email)
		assert.Equal(t, "user2@example.com", export.usersById["user2"].Email)
	})

	// Test case 2: API call fails
	t.Run("APIFail", func(t *testing.T) {
		export.usersById = nil // Reset cache
		export.agent.Client.MockStringResponse("", 500, assert.AnError)

		export.populateUsersCache()

		assert.Nil(t, export.usersById) // Cache should remain nil or empty on error
	})

	// Test case 3: No users found (found = false)
	t.Run("NoUsersFound", func(t *testing.T) {
		export.usersById = nil                               // Reset cache
		export.agent.Client.MockStringResponse("", 200, nil) // Simulate not found by returning empty string and 200

		export.populateUsersCache()

		assert.Nil(t, export.usersById)
		assert.Len(t, export.usersById, 0) // Cache should be empty
	})

	// Test case 4: Empty JSON array (no users)
	t.Run("EmptyJsonArray", func(t *testing.T) {
		export.usersById = nil // Reset cache
		export.agent.Client.MockStringResponse("[]", 200, nil)

		export.populateUsersCache()

		assert.NotNil(t, export.usersById)
		assert.Len(t, export.usersById, 0)
	})
}

func TestProcessJob_ProductivityReport(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))

	// Create a temporary directory for test templates
	tmpDir, err := os.MkdirTemp("", "export_templates_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir) // Clean up after tests

	export.templatePath = tmpDir

	// Create custom template directory
	stdDir := tmpDir + "/standard"
	err = os.MkdirAll(stdDir, 0755)
	assert.Nil(t, err)

	// Create fake productivity report
	err = os.WriteFile(stdDir+"/productivity_report.md", []byte("Template 1 content"), 0644)
	assert.Nil(t, err)

	fmt.Printf("Current working directory: %s\n", os.Getenv("PWD"))
	config := module.ModuleConfig{}
	config["executablePath"] = "../../../scripts/md2pdf"
	config["templatePath"] = tmpDir
	export.Init(config)
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	// Mock responses for users, event, alert, case, and comment queries
	export.agent.Client.MockStringResponse(`[{"id":"xyz"}]`, 200, nil) // Get Users
	export.agent.Client.MockStringResponse(`{"totalEvents": 10, "metrics": {"|event.module": [{"keys":["modA"], "value": 6}, {"keys":["modB"], "value": 4}]}, "|event.module|event.dataset": {"modA|ds1": 3, "modB|ds2": 2}}}`, 200, nil)
	export.agent.Client.MockStringResponse(`{"totalEvents": 5, "metrics": {"|event.escalated": [{"keys":["true"], "value": 2}, {"keys":["false"], "value": 3}]}}`, 200, nil)
	export.agent.Client.MockStringResponse(`{"totalEvents": 2, "metrics": {"|so_case.status": [{"keys":["open"], "value": 1}, {"keys":["closed"], "value": 1}]}, "events": [{"payload": {"so_case.createTime": "2025-07-01T10:00:00Z", "so_case.completeTime": "2025-07-01T12:00:00Z"}}]}`, 200, nil)
	export.agent.Client.MockStringResponse(`{"totalEvents": 1, "metrics": {"|so_comment.userId": [{"keys": ["user1"], "value": 1}]}, "events": [{"payload": {"so_comment.hours": 2.5, "so_comment.userId": "user1"}}]}`, 200, nil)

	job := model.NewJob()
	job.Kind = model.JOB_KIND_EXPORT
	job.Filter.Parameters = map[string]interface{}{
		"type": "productivity",
		"id":   "dummy", // Not used by productivity, but required by ProcessJob
	}
	job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
	job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

	reader, err := export.ProcessJob(job, nil)
	assert.Nil(t, err)
	assert.NotNil(t, reader)

	// Read the output and check for expected content
	output, err := io.ReadAll(reader)
	assert.Nil(t, err)
	assert.Contains(t, string(output), "Helvetica") // A valid PDF should contain a font name
}

func TestProcessJob_TabularReport(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))

	// Create a temporary directory for test templates
	tmpDir, err := os.MkdirTemp("", "export_templates_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir) // Clean up after tests

	export.templatePath = tmpDir

	// Create custom template directory
	stdDir := tmpDir + "/standard"
	err = os.MkdirAll(stdDir, 0755)
	assert.Nil(t, err)

	// Create fake productivity report
	err = os.WriteFile(stdDir+"/unused_report.md", []byte("Template 1 content"), 0644)
	assert.Nil(t, err)

	config := module.ModuleConfig{}
	config["executablePath"] = "../../../scripts/md2pdf" // Not used for tabular, but part of standard config
	config["templatePath"] = tmpDir                      // Not used for tabular, but must have at least one template during cache refresh
	export.Init(config)
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	// Test case 1: Tabular export for events (no group parameter)
	t.Run("TabularEventsExport", func(t *testing.T) {
		export.agent.Client.MockStringResponse(`[{"id":"xyz"}]`, 200, nil) // Get Users

		mockEventsJson := `{
			"totalEvents": 2,
			"events": [
				{
					"id": "event1",
					"timestamp": "2025-07-01T10:00:00Z",
					"payload": {
						"field1": "value1",
						"field2": 123
					}
				},
				{
					"id": "event2",
					"timestamp": "2025-07-01T11:00:00Z",
					"payload": {
						"field1": "valueA",
						"field3": true
					}
				}
			]
		}`
		export.agent.Client.MockStringResponse(mockEventsJson, 200, nil)

		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type":  "tabular",
			"id":    "dummy", // Required by ProcessJob, but not used by tabular
			"query": "some query string",
		}
		job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
		job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

		reader, err := export.ProcessJob(job, nil)
		assert.Nil(t, err)
		assert.NotNil(t, reader)

		output, err := io.ReadAll(reader)
		assert.Nil(t, err)

		expectedCsv := `field1,field2,field3,soc_id,soc_score,soc_type,soc_timestamp,soc_source
value1,123,,event1,0,,2025-07-01T10:00:00Z,
valueA,,true,event2,0,,2025-07-01T11:00:00Z,
`
		assert.Equal(t, expectedCsv, string(output))
	})

	// Test case 2: Tabular export for metrics (with group parameter)
	t.Run("TabularMetricsExport", func(t *testing.T) {
		mockMetricsJson := `{
			"totalEvents": 15,
			"metrics": {
				"groupby_0|event.module": [
					{"value": 10, "keys": ["moduleA"]},
					{"value": 5, "keys": ["moduleB"]}
				]
			}
		}`
		export.agent.Client.MockStringResponse(mockMetricsJson, 200, nil)

		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type":  "tabular",
			"id":    "dummy",
			"query": "some query string",
			"group": "groupby_0|event.module",
		}
		job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
		job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

		reader, err := export.ProcessJob(job, nil)
		assert.Nil(t, err)
		assert.NotNil(t, reader)

		output, err := io.ReadAll(reader)
		assert.Nil(t, err)

		expectedCsv := `count,event.module
10,moduleA
5,moduleB
`
		assert.Equal(t, expectedCsv, string(output))
	})

	// Test case 3: Missing query parameter
	t.Run("MissingQueryParameter", func(t *testing.T) {
		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type": "tabular",
			"id":   "dummy",
		}

		reader, err := export.ProcessJob(job, nil)
		assert.Error(t, err)
		assert.Nil(t, reader)
		assert.Contains(t, err.Error(), "query parameter is missing or empty")
	})

	// Test case 4: API call fails for tabular events
	t.Run("APIFailTabularEvents", func(t *testing.T) {
		export.agent.Client.MockStringResponse("", 500, assert.AnError) // Simulate error
		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type":  "tabular",
			"id":    "dummy",
			"query": "failing query",
		}

		reader, err := export.ProcessJob(job, nil)
		assert.Error(t, err)
		assert.Nil(t, reader)
		assert.Contains(t, err.Error(), "failed to generate tabular data")
	})

	// Test case 5: API call fails for tabular metrics
	t.Run("APIFailTabularMetrics", func(t *testing.T) {
		export.agent.Client.MockStringResponse("", 500, assert.AnError) // Simulate error
		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type":  "tabular",
			"id":    "dummy",
			"query": "failing query",
			"group": "event.module",
		}

		reader, err := export.ProcessJob(job, nil)
		assert.Error(t, err)
		assert.Nil(t, reader)
		assert.Contains(t, err.Error(), "failed to generate tabular data")
	})
}

func TestGetMetricLimit(t *testing.T) {
	tests := []struct {
		name              string
		paramMetricLimit  interface{}
		exportMetricLimit int
		expected          int
	}{
		{
			name:              "Parameter exists and is valid",
			paramMetricLimit:  100,
			exportMetricLimit: 500,
			expected:          100,
		},
		{
			name:              "Parameter exists but is zero",
			paramMetricLimit:  0,
			exportMetricLimit: 500,
			expected:          500,
		},
		{
			name:              "Parameter exists but is negative",
			paramMetricLimit:  -10,
			exportMetricLimit: 500,
			expected:          500,
		},
		{
			name:              "Parameter exists but is not an int",
			paramMetricLimit:  "invalid",
			exportMetricLimit: 500,
			expected:          500,
		},
		{
			name:              "Parameter does not exist, export limit is valid",
			paramMetricLimit:  nil,
			exportMetricLimit: 500,
			expected:          500,
		},
		{
			name:              "Parameter does not exist, export limit is zero",
			paramMetricLimit:  nil,
			exportMetricLimit: 0,
			expected:          DEFAULT_METRIC_LIMIT,
		},
		{
			name:              "Parameter does not exist, export limit is negative",
			paramMetricLimit:  nil,
			exportMetricLimit: -10,
			expected:          DEFAULT_METRIC_LIMIT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			export := NewExport(nil)
			export.exportMetricLimit = tt.exportMetricLimit
			job := model.NewJob()
			job.Filter.Parameters = make(map[string]interface{})
			if tt.paramMetricLimit != nil {
				job.Filter.Parameters["metricLimit"] = tt.paramMetricLimit
			}

			result := export.getMetricLimit(job)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetEventLimit(t *testing.T) {
	tests := []struct {
		name             string
		paramEventLimit  interface{}
		exportEventLimit int
		expected         int
	}{
		{
			name:             "Parameter exists and is valid",
			paramEventLimit:  200,
			exportEventLimit: 600,
			expected:         200,
		},
		{
			name:             "Parameter exists but is zero",
			paramEventLimit:  0,
			exportEventLimit: 600,
			expected:         600,
		},
		{
			name:             "Parameter exists but is negative",
			paramEventLimit:  -20,
			exportEventLimit: 600,
			expected:         600,
		},
		{
			name:             "Parameter exists but is not an int",
			paramEventLimit:  "invalid",
			exportEventLimit: 600,
			expected:         600,
		},
		{
			name:             "Parameter does not exist, export limit is valid",
			paramEventLimit:  nil,
			exportEventLimit: 600,
			expected:         600,
		},
		{
			name:             "Parameter does not exist, export limit is zero",
			paramEventLimit:  nil,
			exportEventLimit: 0,
			expected:         DEFAULT_EVENT_LIMIT,
		},
		{
			name:             "Parameter does not exist, export limit is negative",
			paramEventLimit:  nil,
			exportEventLimit: -20,
			expected:         DEFAULT_EVENT_LIMIT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			export := NewExport(nil)
			export.exportEventLimit = tt.exportEventLimit
			job := model.NewJob()
			job.Filter.Parameters = make(map[string]interface{})
			if tt.paramEventLimit != nil {
				job.Filter.Parameters["eventLimit"] = tt.paramEventLimit
			}

			result := export.getEventLimit(job)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToString(t *testing.T) {
	export := NewExport(nil) // convertToString doesn't depend on agent or client

	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: "",
		},
		{
			name:     "int input",
			input:    123,
			expected: "123",
		},
		{
			name:     "float64 input",
			input:    123.456,
			expected: "123.456000",
		},
		{
			name:     "bool true input",
			input:    true,
			expected: "true",
		},
		{
			name:     "bool false input",
			input:    false,
			expected: "false",
		},
		{
			name:     "string input",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "time.Time input",
			input:    time.Date(2025, time.July, 30, 10, 30, 0, 0, time.UTC),
			expected: "2025-07-30 10:30:00",
		},
		{
			name:     "slice of strings",
			input:    []string{"a", "b", "c"},
			expected: "[a b c]",
		},
		{
			name:     "map input",
			input:    map[string]int{"key": 1},
			expected: "map[key:1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := export.convertToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToCsv(t *testing.T) {
	export := NewExport(nil) // convertToCsv doesn't depend on agent or client

	tests := []struct {
		name        string
		records     [][]string
		expected    string
		expectError bool
	}{
		{
			name: "simple records",
			records: [][]string{
				{"header1", "header2"},
				{"value1", "value2"},
				{"value3", "value4"},
			},
			expected:    "header1,header2\nvalue1,value2\nvalue3,value4\n",
			expectError: false,
		},
		{
			name: "records with commas and quotes",
			records: [][]string{
				{"Name", "Address"},
				{"John Doe", "123 Main St, Anytown"},
				{"Jane \"The Great\" Smith", "456 Oak Ave"},
			},
			expected:    "Name,Address\nJohn Doe,\"123 Main St, Anytown\"\n\"Jane \"\"The Great\"\" Smith\",456 Oak Ave\n",
			expectError: false,
		},
		{
			name:        "empty records",
			records:     [][]string{},
			expected:    "",
			expectError: false,
		},
		{
			name: "records with empty strings",
			records: [][]string{
				{"A", "B"},
				{"", "val2"},
				{"val3", ""},
			},
			expected:    "A,B\n,val2\nval3,\n",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, size, err := export.convertToCsv(tt.records)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, reader)
				assert.Zero(t, size)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, reader)

				output, readErr := io.ReadAll(reader)
				assert.Nil(t, readErr)
				assert.Equal(t, tt.expected, string(output))
				assert.Equal(t, len(tt.expected), size)
			}
		})
	}
}

func TestProcessJob_GenericReport(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	config := module.ModuleConfig{}
	config["executablePath"] = "../../../scripts/md2pdf"
	config["templatePath"] = "../../../templates/export"
	export.Init(config)
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	// Create a temporary directory for test templates
	tmpDir, err := os.MkdirTemp("", "export_generic_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir)

	// Create custom template directory
	customDir := tmpDir + "/custom"
	err = os.MkdirAll(customDir, 0755)
	assert.Nil(t, err)

	export.templatePath = tmpDir

	t.Run("ValidGenericReport", func(t *testing.T) {
		// Create a test template with query options
		templateContent := `Custom Report
=============

/* query.alerts.oql = event.module:suricata AND tags:alert */
/* query.alerts.metricLimit = 50 */
/* query.alerts.eventLimit = 100 */

Total Alerts: {{ .Results.alerts.TotalEvents }}

{{ range $key, $value := .Results.alerts.Metrics }}
{{ $key }}: {{ $value }}
{{ end }}
`
		templatePath := customDir + "/test_report.md"
		err = os.WriteFile(templatePath, []byte(templateContent), 0644)
		assert.Nil(t, err)

		// Mock responses for users and the alert query
		export.agent.Client.MockStringResponse(`[{"id":"xyz"}]`, 200, nil) // Get Users
		export.agent.Client.MockStringResponse(`{"totalEvents": 25, "metrics": {"|event.module": {"suricata": 25}, "|event.severity": {"high": 10, "medium": 15}}}`, 200, nil)

		// Populate templates cache
		export.populateTemplatesCache()

		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type": "test_report",
			"id":   "dummy",
		}
		job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
		job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

		reader, err := export.ProcessJob(job, nil)
		assert.Nil(t, err)
		assert.NotNil(t, reader)

		// Read the output and check for expected content
		output, err := io.ReadAll(reader)
		assert.Nil(t, err)
		assert.Contains(t, string(output), "Helvetica") // A valid PDF should contain a font name
	})

	t.Run("InvalidTemplateType", func(t *testing.T) {
		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type": "invalid/template",
			"id":   "dummy",
		}

		reader, err := export.ProcessJob(job, nil)
		assert.Error(t, err)
		assert.Nil(t, reader)
		assert.Contains(t, err.Error(), "invalid template type")
	})

	t.Run("MissingTemplate", func(t *testing.T) {
		job := model.NewJob()
		job.Kind = model.JOB_KIND_EXPORT
		job.Filter.Parameters = map[string]interface{}{
			"type": "",
			"id":   "dummy",
		}

		reader, err := export.ProcessJob(job, nil)
		assert.Error(t, err)
		assert.Nil(t, reader)
		assert.Contains(t, err.Error(), "missing required parameter: template")
	})
}

func TestGenerateGenericReport(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	// Create a temporary directory for test templates
	tmpDir, err := os.MkdirTemp("", "generic_report_test")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir)

	// Create custom template directory
	customDir := tmpDir + "/custom"
	err = os.MkdirAll(customDir, 0755)
	assert.Nil(t, err)

	export.templatePath = tmpDir

	tests := []struct {
		name            string
		templateContent string
		templateName    string
		mockResponse    string
		expectError     bool
		expectNilResult bool
	}{
		{
			name: "Valid template with single query",
			templateContent: `Test Report
============

/* query.events.oql = * */
/* query.events.metricLimit = 100 */

Total: {{ .Results.events.TotalEvents }}`,
			templateName:    "single_query.md",
			mockResponse:    `{"totalEvents": 10, "metrics": {"|event.module": [{"keys": ["test"], "value": 10}]}}`,
			expectError:     false,
			expectNilResult: false,
		},
		{
			name: "Template with multiple queries",
			templateContent: `Multi Query Report
=================

/* query.alerts.oql = tags:alert */
/* query.events.oql = * */
/* query.alerts.eventLimit = 50 */

Alerts: {{ .Results.alerts.TotalEvents }}
Events: {{ .Results.events.TotalEvents }}`,
			templateName:    "multi_query.md",
			mockResponse:    `{"totalEvents": 5, "metrics": {}}`,
			expectError:     false,
			expectNilResult: false,
		},
		{
			name: "Template with no query options",
			templateContent: `No Queries Report
================

This template has no query options.`,
			templateName:    "no_queries.md",
			mockResponse:    "",
			expectError:     false,
			expectNilResult: true,
		},
		{
			name: "Template with invalid query format",
			templateContent: `Invalid Format Report
====================

/* query.invalid = missing equals */
/* query.valid.oql = * */`,
			templateName:    "invalid_format.md",
			mockResponse:    `{"totalEvents": 1, "metrics": {}}`,
			expectError:     false,
			expectNilResult: false,
		},
		{
			name: "Template with invalid attribute",
			templateContent: `Invalid Attribute Report
=======================

/* query.test.invalidattr = value */
/* query.test.oql = * */`,
			templateName:    "invalid_attr.md",
			mockResponse:    `{"totalEvents": 1, "metrics": {}}`,
			expectError:     false,
			expectNilResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create template file
			templatePath := customDir + "/" + tt.templateName
			err = os.WriteFile(templatePath, []byte(tt.templateContent), 0644)
			assert.Nil(t, err)

			// Mock response if needed
			if tt.mockResponse != "" {
				export.agent.Client.MockStringResponse(tt.mockResponse, 200, nil) // Query response
				export.agent.Client.MockStringResponse(tt.mockResponse, 200, nil) // Query response
			}

			// Populate templates cache
			export.populateTemplatesCache()

			job := model.NewJob()
			job.Id = 1
			job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
			job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

			result, err := export.generateGenericReport(job, tt.templateName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else if tt.expectNilResult {
				assert.Nil(t, err)
				assert.Nil(t, result)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, result)
				assert.Greater(t, len(result), 0)
			}
		})
	}
}

func TestGetGenericDetailsFromServer(t *testing.T) {
	export := NewExport(agent.NewAgent(&config.AgentConfig{}, "test-version"))
	export.agent.Client = web.NewClient("http://localhost:8080", true)
	export.agent.Client.Auth = FakeClientAuth{}

	t.Run("ValidQueries", func(t *testing.T) {
		// Mock successful responses
		export.agent.Client.MockStringResponse(`{"totalEvents": 10, "metrics": {"|event.module": [{"keys": ["suricata"], "value": 10}]}, "events": [{"payload": {"field1": "value1"}}]}`, 200, nil)
		export.agent.Client.MockStringResponse(`{"totalEvents": 5, "metrics": {"|event.severity": [{"keys": ["high"], "value": 5}]}, "events": []}`, 200, nil)

		queries := map[string]*CustomQuery{
			"alerts": {
				Oql:         "tags:alert",
				MetricLimit: 100,
				EventLimit:  50,
			},
			"events": {
				Oql:         "*",
				MetricLimit: 200,
				EventLimit:  100,
			},
		}

		job := model.NewJob()
		job.Id = 1
		job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
		job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

		result, err := export.getGenericDetailsFromServer(job, queries)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 2, len(result.Results))
		assert.Equal(t, 10, result.Results["alerts"].TotalEvents)
		assert.Equal(t, 5, result.Results["events"].TotalEvents)
		assert.Equal(t, job.Filter.BeginTime, result.BeginDate)
		assert.Equal(t, job.Filter.EndTime, result.EndDate)
	})

	t.Run("EmptyOQLQuery", func(t *testing.T) {
		queries := map[string]*CustomQuery{
			"empty": {
				Oql:         "",
				MetricLimit: 100,
				EventLimit:  50,
			},
			"valid": {
				Oql:         "*",
				MetricLimit: 100,
				EventLimit:  50,
			},
		}

		export.agent.Client.MockStringResponse(`{"totalEvents": 1, "metrics": {}}`, 200, nil)

		job := model.NewJob()
		job.Id = 1
		job.Filter.BeginTime = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
		job.Filter.EndTime = time.Date(2025, 7, 2, 0, 0, 0, 0, time.UTC)

		result, err := export.getGenericDetailsFromServer(job, queries)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result.Results)) // Only valid query should be processed
		assert.NotNil(t, result.Results["valid"])
		assert.Nil(t, result.Results["empty"])
	})

	t.Run("QueryError", func(t *testing.T) {
		export.agent.Client.MockStringResponse(`[{"id":"xyz"}]`, 200, nil) // Users
		export.agent.Client.MockStringResponse("", 500, assert.AnError)    // Query fails

		queries := map[string]*CustomQuery{
			"failing": {
				Oql:         "invalid query",
				MetricLimit: 100,
				EventLimit:  50,
			},
		}

		job := model.NewJob()
		job.Id = 1

		result, err := export.getGenericDetailsFromServer(job, queries)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestParseJobParameterInt(t *testing.T) {
	export := NewExport(nil)

	tests := []struct {
		name       string
		paramName  string
		paramValue interface{}
		expected   int
		valid      bool
	}{
		{
			name:       "Valid int parameter",
			paramName:  "testParam",
			paramValue: 100,
			expected:   100,
			valid:      true,
		},
		{
			name:       "Valid string parameter",
			paramName:  "testParam",
			paramValue: "200",
			expected:   200,
			valid:      true,
		},
		{
			name:       "Zero int parameter",
			paramName:  "testParam",
			paramValue: 0,
			expected:   0,
			valid:      false,
		},
		{
			name:       "Negative int parameter",
			paramName:  "testParam",
			paramValue: -50,
			expected:   0,
			valid:      false,
		},
		{
			name:       "Invalid string parameter",
			paramName:  "testParam",
			paramValue: "invalid",
			expected:   0,
			valid:      false,
		},
		{
			name:       "Empty string parameter",
			paramName:  "testParam",
			paramValue: "",
			expected:   0,
			valid:      false,
		},
		{
			name:       "Float parameter",
			paramName:  "testParam",
			paramValue: 100.5,
			expected:   0,
			valid:      false,
		},
		{
			name:       "Parameter not present",
			paramName:  "missingParam",
			paramValue: nil,
			expected:   0,
			valid:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := model.NewJob()
			job.Filter.Parameters = make(map[string]interface{})

			if tt.paramValue != nil {
				job.Filter.Parameters[tt.paramName] = tt.paramValue
			}

			result, valid := export.parseJobParameterInt(job, tt.paramName)
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.valid, valid)
		})
	}
}
