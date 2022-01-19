// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "context"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "strings"
)

func (store *ElasticCasestore) applyTemplate(ctx context.Context, socCase *model.Case) *model.Case {
  var err error
  if socCase.Template != "" {
    err = store.validateId(socCase.Template, "templateId")
    if err == nil {
      var templateCase *model.Case
      log.WithField("templateId", socCase.Template).Info("Creating case from template case")
      templateCase, err = store.GetCase(ctx, socCase.Template)
      if err == nil {
        templateCase.Title = strings.Replace(templateCase.Title, "{}", socCase.Title, 1)
        templateCase.Description = strings.Replace(templateCase.Description, "{}", socCase.Description, 1)
        socCase = templateCase
      } else {
        log.WithField("templateId", socCase.Template).Warn("Template case ID not found; Creating blank case instead")
      }
    } else {
      log.WithField("templateId", socCase.Template).Warn("Invalid template case ID; Creating blank case instead")
    }
  }
  return socCase
}
