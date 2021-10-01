// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package statickeyauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitStaticKeyAuth(tester *testing.T) {
	cfg := make(map[string]interface{})
	auth := NewStaticKeyAuth(nil)
	err := auth.Init(cfg)
	assert.Error(tester, err)

	cfg["apiKey"] = "123"
	err = auth.Init(cfg)
	assert.Error(tester, err)
	assert.Equal(tester, "123", auth.apiKey)
}
