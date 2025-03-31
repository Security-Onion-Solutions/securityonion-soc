// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type Playbook struct {
	Id                string
	Name              string
	Description       string
	Type              string
	DetectionId       string `yaml:"detection_id"`
	DetectionCategory string `yaml:"detection_category"`
	DetectionType     string `yaml:"detection_type"`
	Contributors      []string
	Created           string // date
	Modified          string // date
	Questions         []*Question
}

type Question struct {
	Question      string
	Context       string
	AnswerSources []string `yaml:"answer_sources"`
	Query         string
	OQL           string
	Range         *string
}
