// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
  "testing"
)

func TestUserstoreInit(tester *testing.T) {
  ai := NewKratosUserstore()
  err := ai.Init("abc")
  if err != nil {
    tester.Errorf("unexpected Init error")
  } 
}