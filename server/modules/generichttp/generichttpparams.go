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
