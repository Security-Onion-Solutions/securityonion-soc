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
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/filedatastore"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/kratos"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/elastic"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/statickeyauth"
)

func BuildModuleMap(srv *server.Server) map[string]module.Module {
  moduleMap := make(map[string]module.Module)
  moduleMap["filedatastore"] = filedatastore.NewFileDatastore(srv)
  moduleMap["kratos"] = kratos.NewKratos(srv)
  moduleMap["elastic"] = elastic.NewElastic(srv)
  moduleMap["statickeyauth"] = statickeyauth.NewStaticKeyAuth(srv)
  return moduleMap
}
