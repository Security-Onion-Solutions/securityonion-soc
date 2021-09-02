// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestNewUnauthorized(tester *testing.T) {
  event := NewUnauthorized("mysubject", "myop", "mytarget")
  assert.NotZero(tester, event.CreateTime)
  assert.Equal(tester, event.Subject, "mysubject")
  assert.Equal(tester, event.Operation, "myop")
  assert.Equal(tester, event.Target, "mytarget")
}
