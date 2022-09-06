// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
