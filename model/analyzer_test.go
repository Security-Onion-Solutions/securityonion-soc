// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
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

func TestGetModule(tester *testing.T) {
  analyzer := NewAnalyzer("id", "path")
  assert.Equal(tester, "id.id", analyzer.GetModule())
  assert.Equal(tester, "path/site-packages", analyzer.GetSitePackagesPath())
  assert.Equal(tester, "path/source-packages", analyzer.GetSourcePackagesPath())
  assert.Equal(tester, "path/requirements.txt", analyzer.GetRequirementsPath())
}
