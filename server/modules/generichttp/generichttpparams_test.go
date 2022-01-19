// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package generichttp

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestNewHttpParams(tester *testing.T) {
  cfg := make(module.ModuleConfig)
  params := NewGenericHttpParams(cfg, "create")
  assert.Equal(tester, "POST", params.Method)
  assert.Equal(tester, "", params.Path)
  assert.Equal(tester, "application/json", params.ContentType)
  assert.Equal(tester, "", params.Body)
  assert.Equal(tester, 200, params.SuccessStatusCode)
}
