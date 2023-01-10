// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestFormatUrl(tester *testing.T) {
  client := NewClient("http://some.where/path", true)
  var testTable = []struct {
    url      string
    path     string
    expected string
  }{
    {"http://far.out", "path", "http://far.out/path"},
    {"http://far.out", "/path", "http://far.out/path"},
    {"http://far.out/", "path", "http://far.out/path"},
    {"http://far.out/", "/path", "http://far.out/path"},
    {"http://far.out/", "/path/end", "http://far.out/path/end"},
  }

  for _, test := range testTable {
    tester.Run("url="+test.url+", path="+test.path, func(t *testing.T) {
      actual := client.FormatUrl(test.url, test.path)
      assert.Equal(tester, test.expected, actual)
    })
  }
}

type TestObject struct {
  Foo string
}

func TestMock(tester *testing.T) {
  client := NewClient("http://some.where/path", true)
  respObj := &TestObject{}
  respBody := `{"foo": "bar"}`
  client.MockStringResponse(respBody, 200, nil)
  client.SendObject("GET", "subpath", nil, respObj, false)
  assert.Equal(tester, "bar", respObj.Foo)
}
