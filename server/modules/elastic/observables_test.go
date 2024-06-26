// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2024 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestObservables(t *testing.T) {
	obs := NewObservables()
	for i, v := range []struct {
		expr   string
		expect ObservableType
	}{
		{expr: "www.google.com", expect: ObservableFQDN},
		{expr: "sub.www.google.com", expect: ObservableFQDN},
		{expr: "test.com", expect: ObservableDomain},
		{expr: "test.co", expect: ObservableDomain},
		{expr: "c:/test.doc", expect: ObservableFilename},
		{expr: "/var/log/syslog.tgz", expect: ObservableFilename},
		{expr: "/test/foo", expect: ObservableURIPath},
		{expr: "/test/foo/bar", expect: ObservableURIPath},
		{expr: "file://some/file/path.txt", expect: ObservableURL},
		{expr: "http://www.example.com:8080/path", expect: ObservableURL},
		{expr: "127.0.0.1", expect: ObservableIP},
		{expr: "ff02::1:ffc5:a922", expect: ObservableIP},
		{expr: "ff02::16", expect: ObservableIP},
		{expr: "0e2fc59194659497c8d0aec1762add1324ad2e02549bb3e41d58ca8f39e14843", expect: ObservableHash},
		{expr: "3b43c8fadd64750525a2e285d83fa01d62227999", expect: ObservableHash},
		{expr: "db7298d2ae5733b53f40ab2e99058a9f", expect: ObservableHash},
		{expr: "ea04541a17986a92e4d68f57e97d477845e778721044d0dcf96d380a7eddfc427a7ff0528931c39c35428cf78176da2c9741023b9c298be82521c96d547d68e8", expect: ObservableHash},
		{expr: "xyz", expect: ObservableOther},
	} {
		ot := obs.GetType(v.expr)
		assert.Equal(t, v.expect, ot, "%d: input: '%s' - expected '%s' but got '%s", i, v.expr, v.expect, ot)
	}
}
