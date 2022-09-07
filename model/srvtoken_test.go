// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "encoding/base64"
  "strings"
  "testing"

  "github.com/stretchr/testify/assert"
)

func TestStructValidity(tester *testing.T) {
  token := NewSrvToken("foo", 200)
  err := token.validate("foo")
  assert.NoError(tester, err)
  err = token.validate("bar")
  assert.EqualError(tester, err, "SRV token id mismatch")
}

func TestFullValidity(tester *testing.T) {
  key := []byte("testkey")
  token, err := GenerateSrvToken(key, "myId", 60)
  assert.NoError(tester, err)
  assert.Greater(tester, len(token), 100)

  err = ValidateSrvToken(key, "myId", token)
  assert.NoError(tester, err)

  // test mismatched id
  err = ValidateSrvToken(key, "myId2", token)
  assert.EqualError(tester, err, "SRV token id mismatch")

  // test token expired scenario
  expiredToken := "eyJpZCI6Im15SWQiLCJleHBpcmF0aW9uIjoiMjAyMi0wNy0xNVQyMDo1Nzo0MS43MjA5NDEtMDQ6MDAiLCJoYXNoIjoiT2F6MXlNc2FMdS9TRTBKS2hFV1kzb0hiU042dGRKallMTU83Z0NqUGk4aEEza1FDUEU2di9MUWswVk50eDBnQklxQVZFMm9WdWRreFdvaGU3eWY0bVE9PSJ9"
  err = ValidateSrvToken(key, "myId", expiredToken)
  assert.EqualError(tester, err, "SRV token expired")

  // test different key scenario
  key2 := []byte("testkey2")
  err = ValidateSrvToken(key2, "myId", token)
  assert.EqualError(tester, err, "SRV token HMAC failed validation")

  // test manipulated username inside of token
  decoded, noerr := base64.StdEncoding.DecodeString(token)
  assert.NoError(tester, noerr)
  manipulated := strings.Replace(string(decoded), "myId", "byId", 1)
  encoded := base64.StdEncoding.EncodeToString([]byte(manipulated))
  err = ValidateSrvToken(key, "myId", encoded)
  assert.EqualError(tester, err, "SRV token HMAC failed validation")
}
