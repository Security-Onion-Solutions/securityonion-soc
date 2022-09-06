// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type Analyzer struct {
  Id   string `json:"id"`
  Path string `json:"path"`
}

func NewAnalyzer(id string, path string) *Analyzer {
  newAnalyzer := &Analyzer{
    Id:   id,
    Path: path,
  }

  return newAnalyzer
}

func (analyzer *Analyzer) GetModule() string {
  return analyzer.Id + "." + analyzer.Id
}

func (analyzer *Analyzer) GetRequirementsPath() string {
  return analyzer.Path + "/requirements.txt"
}

func (analyzer *Analyzer) GetSitePackagesPath() string {
  return analyzer.Path + "/site-packages"
}

func (analyzer *Analyzer) GetSourcePackagesPath() string {
  return analyzer.Path + "/source-packages"
}
