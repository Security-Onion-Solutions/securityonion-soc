// Copyright 2020-2021 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
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
			if actual != test.expected {
				t.Errorf("expected %s but got %s", test.expected, actual)
			}
		})
	}
}

func TestGetUserId(tester *testing.T) {
	handler := NewTestHandler()
	request, _ := http.NewRequest("GET", "", nil)

	expectedId := "112233"
	request.Header.Set("x-user-id", expectedId)

	actualId := handler.GetUserId(request)
	if actualId != expectedId {
		tester.Errorf("expected %s but got %s", expectedId, actualId)
	}
}
