// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package modules

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/elastic"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/elasticcases"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/filedatastore"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/generichttp"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/influxdb"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/kratos"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/salt"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/sostatus"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/statickeyauth"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/staticrbac"
  "github.com/security-onion-solutions/securityonion-soc/server/modules/thehive"
)

func BuildModuleMap(srv *server.Server) map[string]module.Module {
  moduleMap := make(map[string]module.Module)
  moduleMap["filedatastore"] = filedatastore.NewFileDatastore(srv)
  moduleMap["httpcase"] = generichttp.NewHttpCase(srv)
  moduleMap["influxdb"] = influxdb.NewInfluxDB(srv)
  moduleMap["kratos"] = kratos.NewKratos(srv)
  moduleMap["elastic"] = elastic.NewElastic(srv)
  moduleMap["elasticcases"] = elasticcases.NewElasticCases(srv)
  moduleMap["salt"] = salt.NewSalt(srv)
  moduleMap["sostatus"] = sostatus.NewSoStatus(srv)
  moduleMap["statickeyauth"] = statickeyauth.NewStaticKeyAuth(srv)
  moduleMap["staticrbac"] = staticrbac.NewStaticRbac(srv)
  moduleMap["thehive"] = thehive.NewTheHive(srv)
  return moduleMap
}
