// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
  "crypto/rand"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "io"
  "strings"
)

const DEFAULT_MAX_PACKET_COUNT = 5000
const DEFAULT_IDLE_CONNECTION_TIMEOUT_MS = 300000
const DEFAULT_MAX_UPLOAD_SIZE_BYTES = 26214400
const DEFAULT_SRV_EXP_SECONDS = 600
const REQUIRED_SRV_KEY_LENGTH = 64

type ServerConfig struct {
  AirgapEnabled           bool                   `json:"airgapEnabled"`
  BindAddress             string                 `json:"bindAddress"`
  BaseUrl                 string                 `json:"baseUrl"`
  DeveloperEnabled        bool                   `json:"developerEnabled"`
  HtmlDir                 string                 `json:"htmlDir"`
  MaxPacketCount          int                    `json:"maxPacketCount"`
  Modules                 module.ModuleConfigMap `json:"modules"`
  ModuleFailuresIgnored   bool                   `json:"moduleFailuresIgnored"`
  ClientParams            ClientParameters       `json:"client"`
  IdleConnectionTimeoutMs int                    `json:"idleConnectionTimeoutMs"`
  TimezoneScript          string                 `json:"timezoneScript"`
  MaxUploadSizeBytes      int                    `json:"maxUploadSizeBytes"`
  SrvKey                  string                 `json:"srvKey"`
  SrvKeyBytes             []byte
  SrvExpSeconds           int `json:"srvExpSeconds"`
}

func (config *ServerConfig) Verify() error {
  var err error
  if config.MaxPacketCount <= 0 {
    config.MaxPacketCount = DEFAULT_MAX_PACKET_COUNT
  }
  if config.BindAddress == "" {
    err = errors.New("Server.BindAddress configuration value is required")
  }
  if strings.TrimSpace(config.BaseUrl) == "" {
    config.BaseUrl = "/"
  }
  if config.BaseUrl[len(config.BaseUrl)-1] != '/' {
    config.BaseUrl = config.BaseUrl + "/"
  }
  if err == nil {
    err = config.ClientParams.Verify()
  }
  if config.IdleConnectionTimeoutMs <= 0 {
    config.IdleConnectionTimeoutMs = DEFAULT_IDLE_CONNECTION_TIMEOUT_MS
  }
  if len(config.TimezoneScript) == 0 {
    config.TimezoneScript = "/opt/sensoroni/scripts/timezones.sh"
  }
  if config.MaxUploadSizeBytes == 0 {
    config.MaxUploadSizeBytes = DEFAULT_MAX_UPLOAD_SIZE_BYTES
  }
  if config.SrvExpSeconds <= 0 {
    config.SrvExpSeconds = DEFAULT_SRV_EXP_SECONDS
  }

  keyLen := len(config.SrvKey)
  if keyLen != REQUIRED_SRV_KEY_LENGTH {
    log.WithFields(log.Fields{
      "required": REQUIRED_SRV_KEY_LENGTH,
      "actual":   keyLen,
    }).Warn("Generating temporary, random SRV key")
    config.SrvKeyBytes = make([]byte, REQUIRED_SRV_KEY_LENGTH)
    if _, err := io.ReadFull(rand.Reader, config.SrvKeyBytes); err != nil {
      log.WithError(err).Error("Unable to generate SRV key")
    }
  } else {
    config.SrvKeyBytes = []byte(config.SrvKey)
  }

  return err
}
