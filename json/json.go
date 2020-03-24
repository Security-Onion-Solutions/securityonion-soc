// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package json

import (
  "encoding/json"
  "io/ioutil"
  "github.com/apex/log"
)

func WriteJsonFile(filename string, obj interface{}) error {
  bytes, err := json.Marshal(obj)
  if err == nil {
    err = ioutil.WriteFile(filename, bytes, 0644)
  }
  if err != nil {
    log.WithError(err).WithFields(log.Fields{ 
      "filename": filename,
    }).Errorf("Error writing json object: %T", err)
  }
  return err
}

func LoadJsonFile(filename string, obj interface{}) error {
  log.WithField("filename", filename).Debug("Loading JSON object")
  content, err := ioutil.ReadFile(filename)
  if err == nil {
    err = json.Unmarshal(content, &obj)
    if err != nil {
      if jsonErr, ok := err.(*json.SyntaxError); ok {
        log.WithError(err).WithFields(log.Fields{ 
          "offset": jsonErr.Offset,
          "filename": filename,
        }).Error("Syntax error reading json object")
      } else if jsonErr, ok := err.(*json.UnmarshalTypeError); ok {
        log.WithError(err).WithFields(log.Fields{ 
          "offset": jsonErr.Offset,
          "filename": filename,
        }).Error("Unmarshal error reading json object")
      } else {
        log.WithError(err).WithFields(log.Fields{ 
          "filename": filename,
        }).Errorf("Unknown error reading json object: %T", err)
      }
    }
  }
  return err
}