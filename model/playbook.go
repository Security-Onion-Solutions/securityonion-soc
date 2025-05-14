// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type Playbook struct {
	// The Public Id of the playbook. Will be the same in every SOC installation.
	Id string `json:"id" example:"f1082c59-49bc-4a63-9155-232a17978ab5"`
	// The name of the playbook.
	Name string `json:"name" example:"Sample Playbook"`
	// The description of the playbook.
	Description string `json:"description" example:"This is a sample playbook"`
	// The type of playbook. Currently only supports "detection"
	Type string `json:"type" example:"detection"`
	// The specific Detection's public Id. May be empty if not specific to any 1 detection.
	DetectionId string `yaml:"detection_id" json:"detection_id" example:"ac5856cd-7e4c-4a61-8b15-6fc9148ff7f2"`
	// The category of detections this playbook applies to. May be empty.
	DetectionCategory string `yaml:"detection_category" json:"detection_category" example:"process_creation"`
	// The type of detection this playbook applies to. This is analogous to which detection engine the playbook is for.
	DetectionType string `yaml:"detection_type" json:"detection_type" enums:"nids,sigma,yara"`
	// Authors of the playbook.
	Contributors []string `yaml:"contributors" json:"contributors" example:"['John Doe', 'Jane Smith']"`
	// The date the playbook was first created.
	Created string `json:"created" example:"2020-01-01T00:00:00Z"`
	// The date of the most recent update to the playbook.
	Modified string `json:"modified" example:"2020-01-01T00:00:00Z"`
	// The questions of this playbook that guide the user in response to an alert.
	Questions []*Question `yaml:"questions" json:"questions"`
}

type Question struct {
	// The human readable question to be asked.
	Question string `json:"question" example:"What is the source IP address of the alert?"`
	// Some context to be provided to the user. This describes why the answer might be useful.
	Context string `json:"context" example:"Knowing if the attack comes from inside or outside the network can help determine if this is a false positive or a real attack."`
	// Where the answer to this question can be found.
	AnswerSources []string `yaml:"answer_sources" json:"answer_sources"`
	// A raw YAML Sigma query that can be used to find the answer to this question. May contain variables that will be replaced with values from the alert.
	Query string `json:"query"`
	// An indicator for what time range the query should be limited to in order to find the answer.
	Range *string `json:"range" example:"+/-3d"`
}

type ConvertedQuery struct {
	// The OQL result of the converted Sigma query.
	Query string `json:"query"`
	// Fields that the query will return that should be made visible in the UI.
	Fields []string `json:"fields"`
}
