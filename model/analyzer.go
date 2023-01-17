// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
