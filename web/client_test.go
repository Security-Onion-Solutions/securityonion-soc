// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "testing"
)

func TestFormatUrl(tester *testing.T) {
  client := NewClient("http://some.where/path", true)
  var testTable = []struct {
    url string
    path string
    expected string
  } {
    { "http://far.out", "path", "http://far.out/path" },
    { "http://far.out", "/path", "http://far.out/path" },
    { "http://far.out/", "path", "http://far.out/path" },
    { "http://far.out/", "/path", "http://far.out/path" },
    { "http://far.out/", "/path/end", "http://far.out/path/end" },
  }

  for _, test := range testTable {
    tester.Run("url=" + test.url + ", path=" + test.path, func(t *testing.T) {
      actual := client.FormatUrl(test.url, test.path) 
      if actual != test.expected {
        t.Errorf("expected %s but got %s", test.expected, actual)
      }
    })
  }
}