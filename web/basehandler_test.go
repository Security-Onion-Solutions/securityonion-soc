// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/stretchr/testify/assert"
  "net/http"
  "strconv"
  "testing"
)

type TestHandler struct {
  BaseHandler
}

func NewTestHandler() *TestHandler {
  handler := &TestHandler{}
  return handler
}

func TestGetPathParameter(tester *testing.T) {
  handler := NewTestHandler()
  var testTable = []struct {
    path     string
    index    int
    expected string
  }{
    {"", -1, ""},
    {"", 0, ""},
    {"", 1, ""},
    {"/", -1, ""},
    {"/", 0, ""},
    {"/", 1, ""},
    {"/123", -1, ""},
    {"/123", 0, "123"},
    {"/123", 1, ""},
    {"/123/", 0, "123"},
    {"/123/", 1, ""},
    {"/123/456", 0, "123"},
    {"/123/456", 1, "456"},
  }

  for _, test := range testTable {
    tester.Run("path="+test.path+", index="+strconv.Itoa(test.index), func(t *testing.T) {
      actual := handler.GetPathParameter(test.path, test.index)
      assert.Equal(tester, test.expected, actual)
    })
  }
}

func TestConvertErrorToSafeString(tester *testing.T) {
  handler := NewTestHandler()

  assert.Equal(tester, "ERROR_FOO", handler.convertErrorToSafeString(errors.New("ERROR_FOO")))
  assert.Equal(tester, GENERIC_ERROR_MESSAGE, handler.convertErrorToSafeString(errors.New("ERROR2_FOO")))
}

func TestValidateRequest(tester *testing.T) {
  testKey := []byte("some key")
  testExpirationSeconds := 60

  handler := NewTestHandler()
  handler.Host = NewHost("http://some.where", "mydir", 1000, "1.2.3", testKey, "exemptId")

  ctx := context.WithValue(context.Background(), ContextKeyRequestorId, "foo")

  // Test GET - no validate
  request, err := http.NewRequest(http.MethodGet, "somewhere", nil)
  err = handler.validateRequest(ctx, request)
  assert.NoError(tester, err)

  // Test POST, with exempt ID - no validate
  request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "exemptId")
  err = handler.validateRequest(ctx, request)
  assert.NoError(tester, err)

  // Test DELETE - fail since missing token in req header
  request, err = http.NewRequest(http.MethodDelete, "somewhere", nil)
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "nonExemptId")
  err = handler.validateRequest(ctx, request)
  assert.EqualError(tester, err, "Missing SRV token on request")

  // Test PUT - fail since missing token in req header
  request, err = http.NewRequest(http.MethodPut, "somewhere", nil)
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "nonExemptId")
  err = handler.validateRequest(ctx, request)
  assert.EqualError(tester, err, "Missing SRV token on request")

  // Test POST - fail since missing token in req header
  request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "nonExemptId")
  err = handler.validateRequest(ctx, request)
  assert.EqualError(tester, err, "Missing SRV token on request")

  // Test PATCH - fail since missing token in req header
  request, err = http.NewRequest(http.MethodPatch, "somewhere", nil)
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "nonExemptId")
  err = handler.validateRequest(ctx, request)
  assert.EqualError(tester, err, "Missing SRV token on request")

  // Test POST - fail due to bad token
  request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
  request.Header.Set("x-srv-token", "e30K")
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "nonExemptId")
  err = handler.validateRequest(ctx, request)
  assert.EqualError(tester, err, "SRV token HMAC failed validation")

  // Test POST - success
  request, err = http.NewRequest(http.MethodPost, "somewhere", nil)
  token, _ := model.GenerateSrvToken(testKey, "nonExemptId", testExpirationSeconds)
  request.Header.Set("x-srv-token", token)
  ctx = context.WithValue(context.Background(), ContextKeyRequestorId, "nonExemptId")
  err = handler.validateRequest(ctx, request)
  assert.NoError(tester, err)
}
