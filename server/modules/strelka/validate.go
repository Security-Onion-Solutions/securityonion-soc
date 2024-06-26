// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

type parseState int

const (
	parseStateImportsID parseState = iota
	parseStateWatchForHeader
	parseStateInSection
)

type YaraRule struct {
	IsPrivate  bool
	Imports    []string
	Identifier string
	Meta       Metadata
	Strings    []string
	Condition  string
	Src        string
}

type Metadata struct {
	ID          *string
	Author      *string
	Date        *string
	Version     *string
	Reference   *string
	Description *string
	Rest        map[string]string
}

func (md *Metadata) IsEmpty() bool {
	return md.Author == nil && md.Date == nil && md.Version == nil && md.Reference == nil && md.Description == nil && len(md.Rest) == 0
}

func (md *Metadata) Set(key, value string) {
	key = strings.ToLower(key)

	value = util.Unquote(value)

	switch key {
	case "id":
		md.ID = util.Ptr(value)
	case "author":
		md.Author = util.Ptr(value)
	case "date":
		md.Date = util.Ptr(value)
	case "version":
		md.Version = util.Ptr(value)
	case "reference":
		md.Reference = util.Ptr(value)
	case "description":
		md.Description = util.Ptr(value)
	default:
		if md.Rest == nil {
			md.Rest = make(map[string]string)
		}
		md.Rest[key] = value
	}
}

func (r *YaraRule) Validate() error {
	missing := []string{}

	if r.Identifier == "" {
		missing = append(missing, "identifier")
	}

	if r.Condition == "" {
		missing = append(missing, "condition")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	return nil
}

func (r *YaraRule) ToDetection(license string, ruleset string, isCommunity bool) *model.Detection {
	sev := model.SeverityUnknown

	metaSev, err := strconv.Atoi(r.Meta.Rest["severity"])
	if err == nil {
		metaSev = 0
	}

	switch {
	case metaSev >= 1 && metaSev < 20:
		sev = model.SeverityInformational
	case metaSev >= 20 && metaSev < 40:
		sev = model.SeverityLow
	case metaSev >= 40 && metaSev < 60:
		sev = model.SeverityMedium
	case metaSev >= 60 && metaSev < 80:
		sev = model.SeverityHigh
	case metaSev >= 80:
		sev = model.SeverityCritical
	}

	lic, ok := r.Meta.Rest["license"]
	if !ok {
		lic = license
	}

	det := &model.Detection{
		Engine:      model.EngineNameStrelka,
		PublicID:    r.Identifier,
		Title:       r.Identifier,
		Severity:    sev,
		Content:     r.Src,
		IsCommunity: isCommunity,
		Language:    model.SigLangYara,
		Ruleset:     ruleset,
		License:     lic,
	}

	if r.Meta.Author != nil {
		det.Author = *r.Meta.Author
	}

	if r.Meta.Description != nil {
		det.Description = util.Unquote(*r.Meta.Description)
	}

	return det
}
