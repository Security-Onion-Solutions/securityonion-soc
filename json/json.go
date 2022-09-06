// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package json

import (
  "encoding/json"
  "github.com/apex/log"
  "os"
)

func WriteJsonFile(filename string, obj interface{}) error {
  bytes, err := WriteJson(obj)
  if err == nil {
    err = os.WriteFile(filename, bytes, 0644)
  }
  if err != nil {
    log.WithError(err).WithFields(log.Fields{
      "filename": filename,
    }).Errorf("Error writing json object: %T", err)
  }
  return err
}

func WriteJson(obj interface{}) ([]byte, error) {
  return json.Marshal(obj)
}

func LoadJsonFile(filename string, obj interface{}) error {
  log.WithField("filename", filename).Debug("Loading JSON object")
  content, err := os.ReadFile(filename)
  if err == nil {
    err = LoadJson(content, obj)
  }
  return err
}

func LoadJson(content []byte, obj interface{}) error {
  err := json.Unmarshal(content, &obj)
  if err != nil {
    if jsonErr, ok := err.(*json.SyntaxError); ok {
      log.WithError(err).WithFields(log.Fields{
        "offset": jsonErr.Offset,
      }).Error("Syntax error reading json object")
    } else if jsonErr, ok := err.(*json.UnmarshalTypeError); ok {
      log.WithError(err).WithFields(log.Fields{
        "offset": jsonErr.Offset,
      }).Error("Unmarshal error reading json object")
    } else {
      log.WithError(err).Errorf("Unknown error reading json object: %T", err)
    }
  }
  return err
}
