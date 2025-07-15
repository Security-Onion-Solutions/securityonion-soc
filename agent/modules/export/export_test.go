package export

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

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

	// Test: Missing id parameter
	job = model.NewJob()
	job.Kind = model.JOB_KIND_EXPORT
	job.Filter.Parameters = make(map[string]interface{})
	job.Filter.Parameters["type"] = "case"
	reader, err = export.ProcessJob(job, nil)
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "missing required parameter: id")
	assert.Empty(t, job.Results)

	// Test: Valid PDF export
	job = model.NewJob()
	job.Kind = model.JOB_KIND_EXPORT
	job.Filter.Parameters = make(map[string]interface{})
	job.Filter.Parameters["type"] = "case"
	job.Filter.Parameters["id"] = "x03459821fsfkjh2"
	reader, err = export.ProcessJob(job, nil)
	assert.Nil(t, err)
	assert.NotNil(t, reader)
	assert.Equal(t, "pdf", job.FileExtension)
	assert.Len(t, job.Results, 0)
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
			param:        "pdf_param",
			params:       "",
			fileContent:  "/* pdf_param: value */",
			expectedArgs: []string{},
			expectError:  false, // Error is logged, but function returns empty slice
		},
		{
			name:         "File not found",
			filepath:     "nonexistent.md",
			param:        "pdf_param",
			params:       "",
			fileContent:  "",
			expectedArgs: []string{},
			expectError:  false, // Error is logged, but function returns empty slice
		},
		{
			name:         "Single parameter extraction",
			filepath:     "testdata/template_single.md",
			param:        "pdf_param",
			params:       "",
			fileContent:  "Some content\n/* pdf_param: param1 */\nMore content",
			expectedArgs: []string{"param1"},
			expectError:  false,
		},
		{
			name:         "Multiple parameters extraction",
			filepath:     "testdata/template_multiple.md",
			param:        "",
			params:       "pdf_params",
			fileContent:  "Some content\n/* pdf_params: paramA paramB paramC */\nMore content",
			expectedArgs: []string{"paramA", "paramB", "paramC"},
			expectError:  false,
		},
		{
			name:         "Mixed parameters (single first)",
			filepath:     "testdata/template_mixed1.md",
			param:        "pdf_param",
			params:       "pdf_params",
			fileContent:  "/* pdf_param: single1 */\n/* pdf_params: multi1 multi2 */",
			expectedArgs: []string{"single1", "multi1", "multi2"},
			expectError:  false,
		},
		{
			name:         "Mixed parameters (multiple first)",
			filepath:     "testdata/template_mixed2.md",
			param:        "pdf_param",
			params:       "pdf_params",
			fileContent:  "/* pdf_params: multiA multiB */\n/* pdf_param: singleA */",
			expectedArgs: []string{"multiA", "multiB", "singleA"},
			expectError:  false,
		},
		{
			name:         "Empty file",
			filepath:     "testdata/template_empty.md",
			param:        "pdf_param",
			params:       "pdf_params",
			fileContent:  "",
			expectedArgs: []string{},
			expectError:  false,
		},
		{
			name:         "File with no matching parameters",
			filepath:     "testdata/template_nomatch.md",
			param:        "pdf_param",
			params:       "pdf_params",
			fileContent:  "Some content\nNo params here\nAnother line",
			expectedArgs: []string{},
			expectError:  false,
		},
		{
			name:         "Parameter with leading/trailing spaces",
			filepath:     "testdata/template_spaces.md",
			param:        "pdf_param",
			params:       "",
			fileContent:  "/* pdf_param:  valueWithSpaces  */",
			expectedArgs: []string{"valueWithSpaces"},
			expectError:  false,
		},
		{
			name:         "Multiple parameters with leading/trailing spaces",
			filepath:     "testdata/template_multi_spaces.md",
			param:        "",
			params:       "pdf_params",
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

func TestPrepareMapForTemplate(t *testing.T) {
	export := NewExport(nil)

	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "Map with dot in key",
			input: map[string]interface{}{
				"field.subfield":        "value1",
				"another.key.with.dots": 123,
				"no_dots":               "value3",
			},
			expected: map[string]interface{}{
				"field.subfield":        "value1",
				"field_subfield":        "value1",
				"another.key.with.dots": 123,
				"another_key_with_dots": 123,
				"no_dots":               "value3",
			},
		},
		{
			name:     "Empty map",
			input:    map[string]interface{}{},
			expected: map[string]interface{}{},
		},
		{
			name: "Map with no dots in keys",
			input: map[string]interface{}{
				"key1": "value1",
				"key2": 123,
			},
			expected: map[string]interface{}{
				"key1": "value1",
				"key2": 123,
			},
		},
		{
			name: "Map with multiple dots in a single key",
			input: map[string]interface{}{
				"a.b.c.d": "test",
			},
			expected: map[string]interface{}{
				"a.b.c.d": "test",
				"a_b_c_d": "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			export.prepareMapForTemplate(tt.input)
			assert.Equal(t, tt.expected, tt.input)
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

	// Test case 1: Valid templates
	t.Run("ValidTemplates", func(t *testing.T) {
		// Create dummy template files
		err = os.WriteFile(tmpDir+"/template1.md", []byte("Template 1 content"), 0644)
		assert.Nil(t, err)
		err = os.WriteFile(tmpDir+"/template2.md", []byte("Template 2 content"), 0644)
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
				result = export.formatDateTime(tt.format, tt.time)
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
