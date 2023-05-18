package server

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
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/tj/assert"
)

type TestHandler struct {
	Host *web.Host
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

	host := web.NewHost("http://some.where", "mydir", 1000, "1.2.3", testKey, "exemptId")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "foo")

	// Test GET - no validate
	request := MustRequest(tester, http.MethodGet, "somewhere", nil)
	err := validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test POST, with exempt ID - no validate
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "exemptId")
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test DELETE - fail since missing token in req header
	request = MustRequest(tester, http.MethodDelete, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test PUT - fail since missing token in req header
	request = MustRequest(tester, http.MethodPut, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test POST - fail since missing token in req header
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test PATCH - fail since missing token in req header
	request = MustRequest(tester, http.MethodPatch, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test POST - fail due to bad token
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	request.Header.Set("x-srv-token", "e30K")
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "SRV token HMAC failed validation")

	// Test POST - success
	request = MustRequest(tester, http.MethodPost, "somewhere", nil)
	token, _ := model.GenerateSrvToken(testKey, "nonExemptId", testExpirationSeconds)
	request.Header.Set("x-srv-token", token)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
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
	}{
		{
			Name:           "Sunny Day - 200",
			StatusCode:     http.StatusOK,
			Obj:            map[string]string{"foo": "bar", "baz": "qux"},
			ExpectBodyJSON: true,
			ExpectedBody:   []byte(`{"foo":"bar","baz":"qux"}`),
			ExpectedCode:   http.StatusOK,
		},
		{
			Name:         "Unauthorized - 401",
			StatusCode:   http.StatusOK,
			Obj:          &model.Unauthorized{},
			ExpectedBody: []byte(`The request could not be processed. Contact a server admin for assistance with reviewing error details in SOC logs.`),
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			Name:         "200 but Error",
			StatusCode:   http.StatusOK,
			Obj:          io.EOF,
			ExpectedBody: []byte(`The request could not be processed. Contact a server admin for assistance with reviewing error details in SOC logs.`),
			ExpectedCode: http.StatusInternalServerError,
		},
		{
			Name:         "Raw Response",
			StatusCode:   http.StatusOK,
			Obj:          []byte{1, 2, 3},
			ExpectedBody: []byte{1, 2, 3},
			ExpectedCode: http.StatusOK,
		},
		{
			Name:         "Error Writing - 500",
			StatusCode:   http.StatusOK,
			Obj:          circle,
			ExpectedBody: []byte(`The request could not be processed. Contact a server admin for assistance with reviewing error details in SOC logs.`),
			ExpectedCode: http.StatusInternalServerError,
		},
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "x")
	ctx = context.WithValue(ctx, web.ContextKeyRequestor, "x")

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
		})
	}
}

func compareJSON(jsn1 []byte, jsn2 []byte) (success bool, err error) {
	var one interface{}
	var two interface{}

	// this is guarded by prettyPrint
	json.Unmarshal(jsn1, &one)
	json.Unmarshal(jsn2, &two)

	return reflect.DeepEqual(one, two), nil
}
