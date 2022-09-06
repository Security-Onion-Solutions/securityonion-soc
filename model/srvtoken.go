// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "crypto/hmac"
  "encoding/base64"
  "errors"
  "fmt"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/json"
  "golang.org/x/crypto/sha3"
  "time"
)

type SrvToken struct {
  Id         string    `json:"id"`
  Expiration time.Time `json:"expiration"`
  Hash       []byte    `json:"hash"`
}

func NewSrvToken(id string, validSeconds int) *SrvToken {
  validityDuration, _ := time.ParseDuration(fmt.Sprintf("%ds", validSeconds))
  expiration := time.Now().Add(validityDuration)
  return &SrvToken{
    Id:         id,
    Expiration: expiration,
  }
}

func (srvToken SrvToken) validate(id string) error {
  if srvToken.Id != id {
    log.WithFields(log.Fields{
      "expected": id,
      "actual":   srvToken.Id,
    }).Warn("SRV token id mismatch")
    return errors.New("SRV token id mismatch")
  }
  if srvToken.Expiration.Before(time.Now()) {
    log.WithFields(log.Fields{
      "expiration": srvToken.Expiration,
    }).Warn("SRV token expired")
    return errors.New("SRV token expired")
  }
  return nil
}

func createHash(srvKey []byte, input []byte) []byte {
  mac := hmac.New(sha3.New512, srvKey)
  mac.Write(input)
  return mac.Sum(nil)
}

func GenerateSrvToken(srvKey []byte, id string, srvTokenExpSeconds int) (string, error) {
  var err error
  var encryptedToken string

  token := NewSrvToken(id, srvTokenExpSeconds)
  var tokenStr []byte
  log.Debug("Writing token into JSON format for HMAC calculation")
  tokenStr, err = json.WriteJson(token)
  if err == nil {
    token.Hash = createHash(srvKey, tokenStr)
    log.Debug("Writing token into JSON format for final token packaging")
    tokenStr, err = json.WriteJson(token)
    if err == nil {
      encryptedToken = base64.URLEncoding.EncodeToString(tokenStr)
    }
  }

  return encryptedToken, err
}

func ValidateSrvToken(srvKey []byte, id string, encryptedToken string) error {
  var token SrvToken

  decoded, err := base64.URLEncoding.DecodeString(encryptedToken)
  if err == nil {
    err = json.LoadJson(decoded, &token)
    if err == nil {
      actual := token.Hash
      token.Hash = nil
      var tokenStr []byte
      log.Debug("Writing token into JSON format for HMAC calculation and comparison")
      tokenStr, err = json.WriteJson(token)
      if err == nil {
        expected := createHash(srvKey, tokenStr)
        if !hmac.Equal(expected, actual) {
          log.WithFields(log.Fields{
            "expectedLen": len(expected),
            "actualLen":   len(actual),
          }).Warn("Provided token hash does not match expected hash")
          err = errors.New("SRV token HMAC failed validation")
        } else {
          err = token.validate(id)
        }
      }
    }
  }

  return err
}
