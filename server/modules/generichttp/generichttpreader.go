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
  "github.com/security-onion-solutions/securityonion-soc/model"
  "strings"
  "text/template"
)

func convertCaseToReader(source string, socCase *model.Case) (*strings.Reader, error) {
  builder := new(strings.Builder)
  parsedTemplate, err := template.New("case").Parse(source)
  if err == nil {
    err = parsedTemplate.Execute(builder, socCase)
  }
  return strings.NewReader(builder.String()), err
}
