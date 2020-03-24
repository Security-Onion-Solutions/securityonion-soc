// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package modules

import (
  "testing"
  "github.com/sensoroni/sensoroni/module"
)

func TestBuildModuleMap(tester *testing.T) {
  mm := BuildModuleMap(nil)
  findModule(tester, mm, "statickeyauth")
  findModule(tester, mm, "stenoquery")
}

func findModule(tester *testing.T, mm map[string]module.Module, module string) {
  if _, ok := mm[module]; !ok {
    tester.Errorf("missing module %s", module)
  }
}
