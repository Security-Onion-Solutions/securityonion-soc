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
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/server"
  "github.com/sensoroni/sensoroni/server/modules/filedatastore"
  "github.com/sensoroni/sensoroni/server/modules/securityonion"
  "github.com/sensoroni/sensoroni/server/modules/statickeyauth"
)

func BuildModuleMap(srv *server.Server) map[string]module.Module {
  moduleMap := make(map[string]module.Module)
  moduleMap["filedatastore"] = filedatastore.NewFileDatastore(srv)
  moduleMap["securityonion"] = securityonion.NewSecurityOnion(srv)
  moduleMap["statickeyauth"] = statickeyauth.NewStaticKeyAuth(srv)
  return moduleMap
}
