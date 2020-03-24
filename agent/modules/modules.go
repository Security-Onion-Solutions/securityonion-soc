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
  "github.com/sensoroni/sensoroni/agent"
  "github.com/sensoroni/sensoroni/agent/modules/statickeyauth"
  "github.com/sensoroni/sensoroni/agent/modules/stenoquery"
  "github.com/sensoroni/sensoroni/module"
)

func BuildModuleMap(agt *agent.Agent) map[string]module.Module {
  moduleMap := make(map[string]module.Module)
  moduleMap["statickeyauth"] = statickeyauth.NewStaticKeyAuth(agt)
  moduleMap["stenoquery"] = stenoquery.NewStenoQuery(agt)
  return moduleMap
}
