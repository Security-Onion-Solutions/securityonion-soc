// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"strconv"
	"time"
)

const PLAYBOOK_RULESET_CUSTOM = "__custom__"

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
	// Whether this is a global playbook that applies to all alerts regardless of detection.
	IsGlobal bool `yaml:"is_global" json:"is_global"`
	// Authors of the playbook.
	Contributors []string `yaml:"contributors" json:"contributors" example:"['John Doe', 'Jane Smith']"`
	// The questions of this playbook that guide the user in response to an alert.
	Questions []*Question `yaml:"questions" json:"questions"`
	// Whether this playbook is from a community repository (read-only) or user-created.
	IsCommunity bool `json:"isCommunity" yaml:"-"`
	// The ruleset this playbook belongs to. Custom playbooks use "__custom__".
	Ruleset string `json:"ruleset" yaml:"-"`
}

// Validate checks that the playbook has required fields and valid structure.
func (p *Playbook) Validate() error {
	if p.Name == "" {
		return errors.New("playbook name is required")
	}
	if len(p.Name) > 200 {
		return errors.New("playbook name must be 200 characters or less")
	}
	if len(p.Description) > 2000 {
		return errors.New("playbook description must be 2000 characters or less")
	}
	// Validate detection type if provided
	if p.DetectionType != "" {
		validTypes := map[string]bool{"nids": true, "sigma": true, "yara": true}
		if !validTypes[p.DetectionType] {
			return errors.New("detection type must be one of: nids, sigma, yara")
		}
	}
	// Validate questions
	for i, q := range p.Questions {
		if err := q.Validate(); err != nil {
			return errors.New("question " + strconv.Itoa(i+1) + ": " + err.Error())
		}
	}
	return nil
}

// Validate checks that the question has required fields.
func (q *Question) Validate() error {
	if q.Question == "" {
		return errors.New("question text is required")
	}
	if len(q.Question) > 500 {
		return errors.New("question text must be 500 characters or less")
	}
	if len(q.Context) > 1000 {
		return errors.New("context must be 1000 characters or less")
	}
	return nil
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
	// The query after variable substitution has been performed.
	FilledQuery string `json:"filledQuery,omitempty" yaml:"filledQuery,omitempty"`
	// The results after the queries have been substituted, converted, and executed.
	QueryResults []*EventRecord `json:"queryResults" yaml:"-"`

	// not returned by the API, only used internally
	QueryFields []string `json:"fields" yaml:"-"`
	// The event-specific query in OQL format
	OqlQuery string `json:"oqlQuery" yaml:"-"`
}

type ConvertedQuery struct {
	// The OQL result of the converted Sigma query.
	Query string `json:"query"`
	// Fields that the query will return that should be made visible in the UI.
	Fields []string `json:"fields"`
}

// GroupedPlaybooks groups playbooks by their match level for a detection
type GroupedPlaybooks struct {
	// Playbooks that match the specific detection ID
	DetectionLevel []*Playbook `json:"detectionLevel"`
	// Playbooks that match the detection's category
	CategoryLevel []*Playbook `json:"categoryLevel"`
	// Playbooks that match the detection engine (fallback)
	EngineLevel []*Playbook `json:"engineLevel"`
	// Global playbooks that apply to all detections
	GlobalLevel []*Playbook `json:"globalLevel"`
}

// PlaybookSearchCriteria contains parameters for searching/filtering playbooks
type PlaybookSearchCriteria struct {
	// Search query to filter by name, description, detection_id, or category
	Search string `json:"search"`
	// Filter by detection type (sigma, nids, yara)
	Type string `json:"type"`
	// Filter by source (community, custom)
	Source string `json:"source"`
	// Number of playbooks to return (default 50, max 500)
	Limit int `json:"limit"`
	// Offset for pagination
	Offset int `json:"offset"`
}

// PlaybookListResponse contains paginated playbook results
type PlaybookListResponse struct {
	// The playbooks matching the search criteria
	Playbooks []*Playbook `json:"playbooks"`
	// Total number of playbooks matching the criteria (before pagination)
	Total int `json:"total"`
	// Stats about playbook counts
	Stats PlaybookStats `json:"stats"`
}

// PlaybookStats contains aggregate counts for playbooks
type PlaybookStats struct {
	// Total number of all playbooks
	Total int `json:"total"`
	// Number of community playbooks
	Community int `json:"community"`
	// Number of custom playbooks
	Custom int `json:"custom"`
	// Number of global playbooks
	Global int `json:"global"`
}
