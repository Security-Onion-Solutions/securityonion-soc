// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type Playbook struct {
	Id                string      `json:"id"`
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	Type              string      `json:"type"`
	DetectionId       string      `yaml:"detection_id" json:"detection_id"`
	DetectionCategory string      `yaml:"detection_category" json:"detection_category"`
	DetectionType     string      `yaml:"detection_type" json:"detection_type"`
	Contributors      []string    `yaml:"contributors" json:"contributors"`
	Created           string      `json:"created"`  // date
	Modified          string      `json:"modified"` // date
	Questions         []*Question `yaml:"questions" json:"questions"`
}

type Question struct {
	Question      string   `json:"question"`
	Context       string   `json:"context"`
	AnswerSources []string `yaml:"answer_sources" json:"answer_sources"`
	Query         string   `json:"query"`
	Range         *string  `json:"range"`
}

type ConvertedQuery struct {
	Query  string   `json:"query"`
	Fields []string `json:"fields"`
}
