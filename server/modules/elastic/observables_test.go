// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
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
		{expr: "http://www.example.com:8080/path", expect: ObservableURL},
		{expr: "xyz", expect: ObservableOther},
		{expr: "127.0.0.1", expect: ObservableIP},
	} {
		ot := obs.GetType(v.expr)
		assert.Equal(t, v.expect, ot, "%d: input: '%s' - expected '%s' but got '%s", i, v.expr, v.expect, ot)
	}
}
