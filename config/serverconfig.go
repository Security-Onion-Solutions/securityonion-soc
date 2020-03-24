// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package config

import (
  "errors"
  "github.com/sensoroni/sensoroni/module"
  "strings"
)

const DEFAULT_MAX_PACKET_COUNT = 5000

type ServerConfig struct {
  BindAddress               			string    												`json:"bindAddress"`
  BaseUrl                         string                            `json:"baseUrl"`
  HtmlDir													string														`json:"htmlDir"`
  MaxPacketCount									int																`json:"maxPacketCount"`
  Modules													module.ModuleConfigMap						`json:"modules"`
  ModuleFailuresIgnored						bool															`json:"moduleFailuresIgnored"`
}

func (config *ServerConfig) Verify() error {
  var err error
  if config.MaxPacketCount <= 0 {
    config.MaxPacketCount = DEFAULT_MAX_PACKET_COUNT
  }
  if config.BindAddress == "" {
    err = errors.New("Server.BindAddress configuration value is required")
  }
  if strings.TrimSpace(config.BaseUrl) == ""{
    config.BaseUrl = "/"
  }
  if config.BaseUrl[len(config.BaseUrl)-1] != '/' {
    config.BaseUrl = config.BaseUrl + "/"
  }
  return err
}