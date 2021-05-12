// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package statickeyauth

import (
	"context"
	"net/http"
	"testing"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func TestValidateAuthorization(tester *testing.T) {
	validateAuthorization(tester, "abc", "1.1.1.1", true)
	validateAuthorization(tester, "a", "1.1.1.1", false)
	validateAuthorization(tester, "", "1.1.1.1", false)
	validateAuthorization(tester, "", "172.17.1.1", false)
	validateAuthorization(tester, "", "172.17.0.1", true)
	validateAuthorization(tester, "abc", "172.17.0.1", true)
}

func validateAuthorization(tester *testing.T, key string, ip string, expected bool) {
	ai := NewStaticKeyAuthImpl()
	ai.Init("abc", "172.17.0.0/24")
	actual := ai.validateAuthorization(key, ip)
	if actual != expected {
		tester.Errorf("expected authorization [key=%s, ip=%s] result %t but got %t", key, ip, expected, actual)
	}
}

func TestValidateApiKey(tester *testing.T) {
	validateKey(tester, "", false)
	validateKey(tester, "basic xyz", false)
	validateKey(tester, "basic", false)
	validateKey(tester, "abc", true)
	validateKey(tester, "basic abc", true)
}

func validateKey(tester *testing.T, key string, expected bool) {
	ai := NewStaticKeyAuthImpl()
	ai.apiKey = "abc"
	actual := ai.validateApiKey(key)
	if actual != expected {
		tester.Errorf("expected validateApiKey %t but got %t", expected, actual)
	}
}

func TestAuthImplInit(tester *testing.T) {
	ai := NewStaticKeyAuthImpl()
	err := ai.Init("abc", "1")
	if err == nil {
		tester.Errorf("expected Init error")
	}
	err = ai.Init("abc", "1.2.3.4/16")
	if err != nil {
		tester.Errorf("unexpected Init error")
	}
	if ai.apiKey != "abc" {
		tester.Errorf("expected apiKey %s but got %s", "abc", ai.apiKey)
	}
	if ai.anonymousNetwork.String() != "1.2.0.0/16" {
		tester.Errorf("expected anonymousNetwork %s but got %s", "1.2.3.4/16", ai.anonymousNetwork.String())
	}
}

func TestPreprocessPriority(tester *testing.T) {
  handler := NewStaticKeyAuthImpl()
  if handler.PreprocessPriority() != 100 {
    tester.Error("expected 100 priority")
  }
}

func TestPreprocess(tester *testing.T) {
	ai := NewStaticKeyAuthImpl()
	err := ai.Init("abc", "1")
	ai.apiKey = "123"
	request, _ := http.NewRequest("GET", "", nil)
	request.Header.Set("authorization", ai.apiKey)
  ctx, statusCode, err := ai.Preprocess(context.Background(), request)
  if err != nil {
  	tester.Errorf("Unexpected error: %v", err)
  }
  if statusCode != 0 {
  	tester.Errorf("expected 0 statusCode but got %d", statusCode)
  }
  if ctx == nil {
  	tester.Errorf("Unexpected nil context return")
  }
  requestor := ctx.Value(web.ContextKeyRequestor)
  if requestor == nil {
  	tester.Errorf("Expected non-nil requestor")
  }
  actualId := requestor.(string)
  if actualId != "SONODE" {
  	tester.Errorf("Expected SONODE but got %s", actualId)
  }
}