// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package module

import (
  "testing"
)

func TestMeetsPrerequisites(tester *testing.T) {
  mgr := NewModuleManager()
  mcm := make(ModuleConfigMap)

  prereqs := make([]string, 0)
  prereqs = append(prereqs, "foo")
  prereqs = append(prereqs, "bar")

  actual := mgr.meetsPrerequisites(prereqs, mcm)
  if actual != false {
    tester.Errorf("expected meetsPrerequisites %t but got %t", false, actual)
  }

  mcm["foo"] = make(ModuleConfig)
  actual = mgr.meetsPrerequisites(prereqs, mcm)
  if actual != false {
    tester.Errorf("expected meetsPrerequisites %t but got %t", false, actual)
  }

  mcm["bar"] = make(ModuleConfig)
  actual = mgr.meetsPrerequisites(prereqs, mcm)
  if actual != true {
    tester.Errorf("expected meetsPrerequisites %t but got %t", true, actual)
  }
}
