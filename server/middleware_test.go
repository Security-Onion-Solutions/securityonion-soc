package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/tj/assert"
)

type TestHandler struct {
	Host *web.Host
}

func TestValidateRequest(tester *testing.T) {
	testKey := []byte("some key")
	testExpirationSeconds := 60

	host := web.NewHost("http://some.where", "mydir", 1000, "1.2.3", testKey, "exemptId")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "foo")

	// Test GET - no validate
	request, err := http.NewRequest(http.MethodGet, "somewhere", nil)
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test POST, with exempt ID - no validate
	request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "exemptId")
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)

	// Test DELETE - fail since missing token in req header
	request, err = http.NewRequest(http.MethodDelete, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test PUT - fail since missing token in req header
	request, err = http.NewRequest(http.MethodPut, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test POST - fail since missing token in req header
	request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test PATCH - fail since missing token in req header
	request, err = http.NewRequest(http.MethodPatch, "somewhere", nil)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "Missing SRV token on request")

	// Test POST - fail due to bad token
	request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
	request.Header.Set("x-srv-token", "e30K")
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.EqualError(tester, err, "SRV token HMAC failed validation")

	// Test POST - success
	request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
	token, _ := model.GenerateSrvToken(testKey, "nonExemptId", testExpirationSeconds)
	request.Header.Set("x-srv-token", token)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "nonExemptId")
	err = validateRequest(ctx, host, request)
	assert.NoError(tester, err)
}
