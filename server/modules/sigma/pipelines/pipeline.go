// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package pipelines

import (
	"fmt"
	"sort"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
)

// ProcessingPipeline represents a set of transformations to apply to Sigma rules
type ProcessingPipeline struct {
	name          string
	priority      int
	transformers  []Transformer
	fieldMappings map[string]string
	logsources    []LogSourceMapping
}

// Transformer is the interface for rule transformations
type Transformer interface {
	// Transform applies the transformation to a rule
	Transform(rule *sigma.Rule) (*sigma.Rule, error)
	// GetName returns the name of the transformer
	GetName() string
}

// LogSourceMapping maps Sigma logsources to target logsources
type LogSourceMapping struct {
	From sigma.LogSource
	To   sigma.LogSource
}

// NewProcessingPipeline creates a new processing pipeline
func NewProcessingPipeline(name string, priority int) *ProcessingPipeline {
	return &ProcessingPipeline{
		name:          name,
		priority:      priority,
		transformers:  make([]Transformer, 0),
		fieldMappings: make(map[string]string),
		logsources:    make([]LogSourceMapping, 0),
	}
}

// GetName returns the pipeline name
func (p *ProcessingPipeline) GetName() string {
	return p.name
}

// GetPriority returns the pipeline priority
func (p *ProcessingPipeline) GetPriority() int {
	return p.priority
}

// AddTransformer adds a transformer to the pipeline
func (p *ProcessingPipeline) AddTransformer(transformer Transformer) {
	p.transformers = append(p.transformers, transformer)
}

// AddFieldMapping adds a field mapping
func (p *ProcessingPipeline) AddFieldMapping(from, to string) {
	p.fieldMappings[from] = to
}

// AddLogSourceMapping adds a logsource mapping
func (p *ProcessingPipeline) AddLogSourceMapping(from, to sigma.LogSource) {
	p.logsources = append(p.logsources, LogSourceMapping{From: from, To: to})
}

// Process applies all transformations in the pipeline
func (p *ProcessingPipeline) Process(rule *sigma.Rule) (*sigma.Rule, error) {
	result := rule

	// Apply logsource mappings
	result = p.applyLogSourceMappings(result)

	// Apply field mappings
	result = p.applyFieldMappings(result)

	// Apply transformers
	var err error
	for _, transformer := range p.transformers {
		result, err = transformer.Transform(result)
		if err != nil {
			return nil, fmt.Errorf("transformer %s failed: %w", transformer.GetName(), err)
		}
	}

	return result, nil
}

// applyLogSourceMappings applies logsource mappings to a rule
func (p *ProcessingPipeline) applyLogSourceMappings(rule *sigma.Rule) *sigma.Rule {
	for _, mapping := range p.logsources {
		if matchesLogSource(rule.LogSource, mapping.From) {
			// Create a copy and update logsource
			ruleCopy := *rule
			
			// Merge logsource fields
			if mapping.To.Category != "" {
				ruleCopy.LogSource.Category = mapping.To.Category
			}
			if mapping.To.Product != "" {
				ruleCopy.LogSource.Product = mapping.To.Product
			}
			if mapping.To.Service != "" {
				ruleCopy.LogSource.Service = mapping.To.Service
			}
			if mapping.To.Definition != "" {
				ruleCopy.LogSource.Definition = mapping.To.Definition
			}
			
			// Merge custom fields
			if len(mapping.To.Custom) > 0 {
				if ruleCopy.LogSource.Custom == nil {
					ruleCopy.LogSource.Custom = make(map[string]interface{})
				}
				for k, v := range mapping.To.Custom {
					ruleCopy.LogSource.Custom[k] = v
				}
			}
			
			return &ruleCopy
		}
	}
	
	return rule
}

// applyFieldMappings applies field mappings to detection selections
func (p *ProcessingPipeline) applyFieldMappings(rule *sigma.Rule) *sigma.Rule {
	if len(p.fieldMappings) == 0 {
		return rule
	}

	// Create a copy
	ruleCopy := *rule
	ruleCopy.Detection.Selections = make(map[string]interface{})

	// Apply mappings to each selection
	for selName, selection := range rule.Detection.Selections {
		ruleCopy.Detection.Selections[selName] = p.mapSelectionFields(selection)
	}

	return &ruleCopy
}

// mapSelectionFields recursively maps fields in a selection
func (p *ProcessingPipeline) mapSelectionFields(selection interface{}) interface{} {
	switch sel := selection.(type) {
	case map[string]interface{}:
		mapped := make(map[string]interface{})
		for field, value := range sel {
			// Check if field needs mapping
			mappedField := field
			
			// Handle modifiers
			baseField, modifier := sigma.ParseModifier(field)
			if newField, ok := p.fieldMappings[baseField]; ok {
				if modifier != sigma.ModifierNone {
					mappedField = newField + "|" + string(modifier)
				} else {
					mappedField = newField
				}
			}
			
			mapped[mappedField] = value
		}
		return mapped

	case []interface{}:
		// List of conditions - map each one
		mapped := make([]interface{}, len(sel))
		for i, item := range sel {
			mapped[i] = p.mapSelectionFields(item)
		}
		return mapped

	default:
		// Not a selection structure, return as-is
		return selection
	}
}

// matchesLogSource checks if a logsource matches a pattern
func matchesLogSource(source, pattern sigma.LogSource) bool {
	// Empty pattern matches everything
	if pattern.Category == "" && pattern.Product == "" && pattern.Service == "" {
		return true
	}

	// Check each field
	if pattern.Category != "" && pattern.Category != "*" && source.Category != pattern.Category {
		return false
	}
	if pattern.Product != "" && pattern.Product != "*" && source.Product != pattern.Product {
		return false
	}
	if pattern.Service != "" && pattern.Service != "*" && source.Service != pattern.Service {
		return false
	}

	return true
}

// PipelineSet manages multiple pipelines
type PipelineSet struct {
	pipelines []sigma.Pipeline
}

// NewPipelineSet creates a new pipeline set
func NewPipelineSet() *PipelineSet {
	return &PipelineSet{
		pipelines: make([]sigma.Pipeline, 0),
	}
}

// AddPipeline adds a pipeline to the set
func (ps *PipelineSet) AddPipeline(pipeline sigma.Pipeline) {
	ps.pipelines = append(ps.pipelines, pipeline)
	// Sort by priority (lower number = higher priority)
	sort.Slice(ps.pipelines, func(i, j int) bool {
		return ps.pipelines[i].GetPriority() < ps.pipelines[j].GetPriority()
	})
}

// GetPipelines returns all pipelines in priority order
func (ps *PipelineSet) GetPipelines() []sigma.Pipeline {
	return ps.pipelines
}

// ProcessRule applies all pipelines to a rule
func (ps *PipelineSet) ProcessRule(rule *sigma.Rule) (*sigma.Rule, error) {
	result := rule
	var err error

	for _, pipeline := range ps.pipelines {
		result, err = pipeline.Process(result)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}