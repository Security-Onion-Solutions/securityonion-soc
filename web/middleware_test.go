// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
)

type TestHandler struct {
	Host *Host
}

func MustRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}

	return request
}

func TestValidateRequest(tester *testing.T) {
	testKey := []byte("some key")
	testExpirationSeconds := 60

	host := NewHost("http://some.where", "mydir", 1000, "1.2.3", testKey)

	ctx := context.WithValue(context.Background(), ContextKeyRequestorId, "foo")

	// Test GET - no validate
	request := MustRequest(tester, http.MethodGet, "somewhere", nil)
	err := validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test POST, with exempt ID - no validate
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, true)
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test POST, with no ContextKeyRequestCSRFExempt in context - no panic
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	err = validateRequest(context.Background(), host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test DELETE - fail since missing token in req header
	request = MustRequest(tester, http.MethodDelete, "somewhere", nil)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test PUT - fail since missing token in req header
	request = MustRequest(tester, http.MethodPut, "somewhere", nil)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test POST - fail since missing token in req header
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test PATCH - fail since missing token in req header
	request = MustRequest(tester, http.MethodPatch, "somewhere", nil)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test POST - fail due to bad token
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	request.Header.Set("x-srv-token", "e30K")
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	ctx = context.WithValue(ctx, ContextKeyRequestorId, "123")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "SRV token HMAC failed validation")

	// Test POST - success
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	token, _ := model.GenerateSrvToken(testKey, "nonExemptId", testExpirationSeconds)
	request.Header.Set("x-srv-token", token)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	ctx = context.WithValue(ctx, ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test path exemption - success
	request = MustRequest(tester, http.MethodPost, "/api/util/reverse-lookup", nil)
	ctx = context.WithValue(context.Background(), ContextKeyRequestCSRFExempt, false)
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)
}

func TestRespond(t *testing.T) {
	t.Parallel()

	type CircularRef struct {
		Ref *CircularRef
	}

	circle := &CircularRef{}
	circle.Ref = circle

	table := []struct {
		Name           string
		StatusCode     int
		Obj            any
		ExpectBodyJSON bool
		ExpectedBody   []byte
		ExpectedCode   int
		ExpectedType   string
	}{
		{
			Name:           "Sunny Day - 200",
			StatusCode:     http.StatusOK,
			Obj:            map[string]string{"foo": "bar", "baz": "qux"},
			ExpectBodyJSON: true,
			ExpectedBody:   []byte(`{"foo":"bar","baz":"qux"}`),
			ExpectedCode:   http.StatusOK,
			ExpectedType:   "application/json",
		},
		{
			Name:         "Unauthorized - 403",
			StatusCode:   http.StatusOK,
			Obj:          &model.Unauthorized{},
			ExpectedBody: []byte(`ERROR_PERMISSION_DENIED`),
			ExpectedCode: http.StatusForbidden,
		},
		{
			Name:         "200 but Error",
			StatusCode:   http.StatusOK,
			Obj:          io.EOF,
			ExpectedBody: []byte(`The request could not be processed.`),
			ExpectedCode: http.StatusInternalServerError,
		},
		{
			Name:         "Raw Response",
			StatusCode:   http.StatusOK,
			Obj:          []byte{1, 2, 3},
			ExpectedBody: []byte{1, 2, 3},
			ExpectedCode: http.StatusOK,
			ExpectedType: "application/octet-stream",
		},
		{
			Name:         "Error Writing - 500",
			StatusCode:   http.StatusOK,
			Obj:          circle,
			ExpectedBody: []byte(`The request could not be processed.`),
			ExpectedCode: http.StatusInternalServerError,
		},
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, ContextKeyRequestId, "x")

	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			w := &httptest.ResponseRecorder{
				Body: &bytes.Buffer{},
			}

			r := MustRequest(t, http.MethodGet, "/", nil)

			r = r.WithContext(ctx)

			Respond(w, r, tt.StatusCode, tt.Obj)

			assert.Equal(t, tt.ExpectedCode, w.Code)

			if tt.ExpectBodyJSON {
				goodResponse, err := compareJSON(tt.ExpectedBody, w.Body.Bytes())
				assert.NoError(t, err)
				assert.True(t, goodResponse)
			} else {
				assert.Equal(t, tt.ExpectedBody, w.Body.Bytes())
			}

			if tt.ExpectedType != "" {
				assert.Equal(t, []string{tt.ExpectedType}, w.Result().Header["Content-Type"])
			}
		})
	}
}

func compareJSON(jsn1 []byte, jsn2 []byte) (success bool, err error) {
	var one interface{}
	var two interface{}

	// this is guarded by prettyPrint
	_ = json.Unmarshal(jsn1, &one)
	_ = json.Unmarshal(jsn2, &two)

	return reflect.DeepEqual(one, two), nil
}

func TestProxySubgridRequest(tester *testing.T) {
	// Create a mock subgrid
	var subgrids []*model.Subgrid
	subgrid := &model.Subgrid{
		Id:         "test-subgrid",
		ManagerUrl: "http://test-subgrid",
	}
	subgrids = append(subgrids, subgrid)

	table := []struct {
		Name         string
		Subgrids     []*model.Subgrid
		GridId       string
		ExpectedBody []byte
		ExpectedCode int
	}{
		{
			Name:         "Nil subgrids",
			Subgrids:     nil,
			GridId:       `123`,
			ExpectedBody: []byte(`ERROR_SUBGRID_INVALID`),
			ExpectedCode: http.StatusBadRequest,
		},
		{
			Name:         "Empty subgrids",
			Subgrids:     make([]*model.Subgrid, 0),
			GridId:       `123`,
			ExpectedBody: []byte(`ERROR_SUBGRID_INVALID`),
			ExpectedCode: http.StatusBadRequest,
		},
		{
			Name:         "Matching subgrids",
			Subgrids:     subgrids,
			GridId:       `test-subgrid`,
			ExpectedBody: []byte(`ERROR_SUBGRID_API_UNREACHABLE`),
			ExpectedCode: http.StatusBadGateway,
		},
	}

	for _, tt := range table {
		tester.Run(tt.Name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			// Create a mock response writer
			respWriter := &httptest.ResponseRecorder{
				Body: &bytes.Buffer{},
			}

			ctx := context.Background()
			ctx = context.WithValue(ctx, ContextKeyRequestStart, time.Now())
			ctx = context.WithValue(ctx, ContextKeyRequestId, "x")

			req := MustRequest(tester, http.MethodGet, "somewhere?gridId=123", nil)
			req = req.WithContext(ctx)

			proxySubgridRequest(tt.Subgrids, tt.GridId, ctx, respWriter, req)
			assert.Equal(tester, tt.ExpectedCode, respWriter.Result().StatusCode)
			assert.Equal(tester, tt.ExpectedBody, respWriter.Body.Bytes())
		})
	}
}

func TestIsLocalGridSelected(t *testing.T) {
	assert.True(t, isLocalGridSelected(ALL_GRIDS), "ALL_GRIDS should return true")
	assert.False(t, isLocalGridSelected("some_other_grid"), "Any other grid ID should return false")
}

func TestIsSubgridSelected(t *testing.T) {
	grid := &model.Subgrid{Id: "test-grid"}

	assert.True(t, isSubgridSelected(grid, ALL_GRIDS), "ALL_GRIDS should return true")
	assert.True(t, isSubgridSelected(grid, "test-grid"), "Matching grid ID should return true")
	assert.False(t, isSubgridSelected(grid, "some_other_grid"), "Non-matching grid ID should return false")
}

func TestIsOnlySubgridSelected(t *testing.T) {
	grid := &model.Subgrid{Id: "test-grid"}

	assert.True(t, isOnlySubgridSelected(grid, "test-grid"), "Matching grid ID should return true")
	assert.False(t, isOnlySubgridSelected(grid, ALL_GRIDS), "ALL_GRIDS should return false")
	assert.False(t, isOnlySubgridSelected(grid, "some_other_grid"), "Non-matching grid ID should return false")
}

func TestCheckForRedirect(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyRequestId, "test-req-id")
	ctx = context.WithValue(ctx, ContextKeyRequestorId, "test-user")

	// Scenario 1: Redirect header is present
	t.Run("RedirectPresent", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/some/path", nil)
		resp := &http.Response{
			StatusCode: http.StatusFound, // 302
			Header:     make(http.Header),
		}
		redirectURL := "/new/location"
		resp.Header.Set("Location", redirectURL)

		redirected := checkForRedirect(ctx, w, r, resp)

		assert.True(t, redirected, "Expected checkForRedirect to return true when location header is present")
		assert.Equal(t, http.StatusFound, w.Code, "Expected status code to be StatusFound (302)")
		assert.Equal(t, redirectURL, w.Header().Get("Location"), "Expected Location header in response writer to match")
	})

	// Scenario 2: Redirect header is not present
	t.Run("RedirectNotPresent", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/some/path", nil)
		resp := &http.Response{
			StatusCode: http.StatusOK, // 200
			Header:     make(http.Header),
		}

		redirected := checkForRedirect(ctx, w, r, resp)

		assert.False(t, redirected, "Expected checkForRedirect to return false when location header is absent")
		// Recorder should not have been written to in this case, so Code remains 0 (default)
		// and headers remain empty. We don't need explicit asserts for that unless we want
		// to be extra sure, but asserting the return value is the primary goal.
	})
}

func TestCopyProxiedHttpHeaders(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name                string
		RespHeaders         http.Header
		ExpectedContentType string
		ExpectedContentDisp string
		ExpectedTransferEnc string
	}{
		{
			Name:                "All headers present",
			RespHeaders:         http.Header{"Content-Type": []string{"application/json"}, "Content-Disposition": []string{"attachment; filename=test.txt"}, "Content-Transfer-Encoding": []string{"binary"}},
			ExpectedContentType: "application/json",
			ExpectedContentDisp: "attachment; filename=test.txt",
			ExpectedTransferEnc: "binary",
		},
		{
			Name:                "Missing Content-Disposition",
			RespHeaders:         http.Header{"Content-Type": []string{"text/plain"}, "Content-Transfer-Encoding": []string{"base64"}},
			ExpectedContentType: "text/plain",
			ExpectedContentDisp: "",
			ExpectedTransferEnc: "base64",
		},
		{
			Name:                "Missing Content-Transfer-Encoding",
			RespHeaders:         http.Header{"Content-Type": []string{"application/xml"}, "Content-Disposition": []string{"inline"}},
			ExpectedContentType: "application/xml",
			ExpectedContentDisp: "inline",
			ExpectedTransferEnc: "",
		},
		{
			Name:                "No optional headers",
			RespHeaders:         http.Header{"Content-Type": []string{"text/html"}},
			ExpectedContentType: "text/html",
			ExpectedContentDisp: "",
			ExpectedTransferEnc: "",
		},
	}

	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			resp := &http.Response{
				Header:     tt.RespHeaders,
				StatusCode: http.StatusOK,
				Body:       nil,
			}

			copyProxiedHttpHeaders(w, resp)

			assert.Equal(t, tt.ExpectedContentType, w.Header().Get("Content-Type"))
			assert.Equal(t, tt.ExpectedContentDisp, w.Header().Get("Content-Disposition"))
			assert.Equal(t, tt.ExpectedTransferEnc, w.Header().Get("Content-Transfer-Encoding"))
		})
	}
}

type recordingAuthorizer struct {
	authorized      bool
	lastOperation   string
	lastTarget      string
}

func (r *recordingAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
	r.lastOperation = operation
	r.lastTarget = target
	if r.authorized {
		return nil
	}
	return model.NewUnauthorized("test-user", operation, target)
}

func (r *recordingAuthorizer) CheckUserOperationAuthorized(userId string, operation string, target string) error {
	r.lastOperation = operation
	r.lastTarget = target
	if r.authorized {
		return nil
	}
	return model.NewUnauthorized(userId, operation, target)
}

func TestMiddleware_SubgridProxyAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		method            string
		url               string
		authorized        bool
		expectedOp        string
		expectedTarget    string
		expectedStatus    int
		expectedBody      string
		expectNextCalled  bool
	}{
		{
			name:             "GET with gridId denied",
			method:           http.MethodGet,
			url:              "/api/events?gridId=subgrid1",
			authorized:       false,
			expectedOp:       "read",
			expectedTarget:   "subgrid",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "ERROR_PERMISSION_DENIED",
			expectNextCalled: false,
		},
		{
			name:             "HEAD with gridId denied",
			method:           http.MethodHead,
			url:              "/api/events?gridId=subgrid1",
			authorized:       false,
			expectedOp:       "read",
			expectedTarget:   "subgrid",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "ERROR_PERMISSION_DENIED",
			expectNextCalled: false,
		},
		{
			name:             "POST with gridId denied",
			method:           http.MethodPost,
			url:              "/api/events?gridId=subgrid1",
			authorized:       false,
			expectedOp:       "write",
			expectedTarget:   "subgrid",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "ERROR_PERMISSION_DENIED",
			expectNextCalled: false,
		},
		{
			name:             "DELETE with gridId denied",
			method:           http.MethodDelete,
			url:              "/api/events?gridId=subgrid1",
			authorized:       false,
			expectedOp:       "write",
			expectedTarget:   "subgrid",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "ERROR_PERMISSION_DENIED",
			expectNextCalled: false,
		},
		{
			name:             "GET without gridId passes to next handler",
			method:           http.MethodGet,
			url:              "/api/events",
			authorized:       false,
			expectedOp:       "",
			expectedTarget:   "",
			expectedStatus:   http.StatusOK,
			expectedBody:     "OK",
			expectNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &recordingAuthorizer{authorized: tt.authorized}
			host := NewHost("http://localhost", "html", 1000, "1.0.0", []byte("srv-key"))
			host.Authorizer = auth
			_ = host.AddPreprocessor(&mockAuthPreprocessor{priority: 100, userId: "test-user"})

			nextCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			})

			middleware := Middleware(host, false, nil)
			handler := middleware(nextHandler)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, tt.url, nil)
			if tt.method == http.MethodPost || tt.method == http.MethodDelete {
				ctx := context.WithValue(r.Context(), ContextKeyRequestCSRFExempt, true)
				r = r.WithContext(ctx)
			}

			handler.ServeHTTP(w, r)

			assert.Equal(t, tt.expectedOp, auth.lastOperation)
			assert.Equal(t, tt.expectedTarget, auth.lastTarget)
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.expectNextCalled, nextCalled)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
		})
	}
}

type mockAuthPreprocessor struct {
	priority int
	userId   string
}

func (m *mockAuthPreprocessor) PreprocessPriority() int {
	return m.priority
}

func (m *mockAuthPreprocessor) Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error) {
	ctx = context.WithValue(ctx, ContextKeyRequestorId, m.userId)
	return ctx, 0, nil
}
