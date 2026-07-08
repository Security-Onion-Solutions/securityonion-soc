// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "time"

type Playbook struct {
	// The name of the playbook.
	Name      string `json:"name" example:"Sample Playbook"`
	Auditable `yaml:",inline"`
	// The description of the playbook.
	Description string `json:"description" example:"This is a sample playbook"`
	// The date the playbook was created.
	SourceCreated time.Time `json:"created" yaml:"created" example:"2023-10-01T12:00:00Z"`
	// The date the playbook was last modified.
	SourceUpdated *time.Time `json:"modified,omitempty" yaml:"modified,omitempty" example:"2023-10-01T12:00:00Z"`
	// The specific Detection's public Id. May be empty if not specific to any 1 detection.
	DetectionId string `yaml:"detection_id" json:"detection_id" example:"ac5856cd-7e4c-4a61-8b15-6fc9148ff7f2"`
	// The category of detections this playbook applies to. May be empty.
	DetectionCategory string `yaml:"detection_category" json:"detection_category" example:"process_creation"`
	// The type of detection this playbook applies to. This is analogous to which detection engine the playbook is for.
	DetectionType string `yaml:"detection_type" json:"detection_type" enums:"nids,sigma,yara"`
	// Authors of the playbook.
	Contributors []string `yaml:"contributors" json:"contributors" example:"['John Doe', 'Jane Smith']"`
	// The questions of this playbook that guide the user in response to an alert.
	Questions []*Question `yaml:"questions" json:"questions"`
}

type Question struct {
	// The human readable question to be asked.
	Question string `json:"question" example:"What is the source IP address of the alert?"`
	// Some context to be provided to the user. This describes why the answer might be useful.
	Context string `json:"context" example:"Knowing if the attack comes from inside or outside the network can help determine if this is a false positive or a real attack."`
	// An indicator for what time range the query should be limited to in order to find the answer.
	Range *string `json:"range" yaml:",omitempty" example:"+/-3d"`
	// Where the answer to this question can be found.
	AnswerSources []string `yaml:"answer_sources" json:"answer_sources"`
	// A raw YAML Sigma query that can be used to find the answer to this question. May contain variables that will be replaced with values from the alert.
	Query string `json:"query"`
	// The query after LEGACY {field} variable substitution (queryVariableSubstitution) has been performed.
	FilledQuery string `json:"filledQuery,omitempty" yaml:"filledQuery,omitempty"`
	// The results after the queries have been substituted, converted, and executed.
	QueryResults []*EventRecord `json:"queryResults" yaml:"-"`

	// The fields below are populated at conversion time; the UI echoes them back
	// when executing a single question (POST /playbook/question).

	// Fields the converted query returns; used as result columns.
	QueryFields []string `json:"fields" yaml:"-"`
	// The event-specific query in OQL format
	OqlQuery string `json:"oqlQuery" yaml:"-"`
	// Whether the query is a Sigma aggregation.
	IsAggregate bool `json:"isAggregate" yaml:"-"`
}

// PlaybookStage selects how much of the query pipeline runs when fetching
// event-specific playbooks.
type PlaybookStage string

const (
	PlaybookStageSkeleton PlaybookStage = "skeleton" // questions only
	PlaybookStageConvert  PlaybookStage = "convert"  // queries converted to OQL, not executed
	PlaybookStageFull     PlaybookStage = "full"     // queries converted and executed
)

type ConvertedQuery struct {
	// The OQL result of the converted Sigma query.
	Query string `json:"query"`
	// Fields that the query will return that should be made visible in the UI.
	Fields []string `json:"fields"`
}
