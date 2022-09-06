// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
)

type GenericHttpParams struct {
  ContentType       string
  Method            string
  Path              string
  Body              string
  SuccessStatusCode int
}

func NewGenericHttpParams(cfg module.ModuleConfig, prefix string) *GenericHttpParams {
  params := &GenericHttpParams{}
  params.Method = module.GetStringDefault(cfg, prefix+"Method", "POST")
  params.Path = module.GetStringDefault(cfg, prefix+"Path", "")
  params.ContentType = module.GetStringDefault(cfg, prefix+"ContentType", "application/json")
  params.Body = module.GetStringDefault(cfg, prefix+"Body", "")
  params.SuccessStatusCode = module.GetIntDefault(cfg, prefix+"SuccessCode", 200)
  return params
}
