// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package transformers

import (
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
)

// FieldMappingTransformer maps field names in detections
type FieldMappingTransformer struct {
	name     string
	mappings map[string]string
}

// NewFieldMappingTransformer creates a new field mapping transformer
func NewFieldMappingTransformer(name string, mappings map[string]string) *FieldMappingTransformer {
	return &FieldMappingTransformer{
		name:     name,
		mappings: mappings,
	}
}

// GetName returns the transformer name
func (t *FieldMappingTransformer) GetName() string {
	return t.name
}

// Transform applies field mappings to the rule
func (t *FieldMappingTransformer) Transform(rule *sigma.Rule) (*sigma.Rule, error) {
	if len(t.mappings) == 0 {
		return rule, nil
	}

	// Create a copy
	ruleCopy := *rule
	ruleCopy.Detection.Selections = make(map[string]interface{})

	// Apply mappings to each selection
	for selName, selection := range rule.Detection.Selections {
		ruleCopy.Detection.Selections[selName] = t.mapFields(selection)
	}

	return &ruleCopy, nil
}

// mapFields recursively maps fields in a selection
func (t *FieldMappingTransformer) mapFields(selection interface{}) interface{} {
	switch sel := selection.(type) {
	case map[string]interface{}:
		mapped := make(map[string]interface{})
		for field, value := range sel {
			mappedField := t.mapFieldName(field)
			mapped[mappedField] = value
		}
		return mapped

	case []interface{}:
		mapped := make([]interface{}, len(sel))
		for i, item := range sel {
			mapped[i] = t.mapFields(item)
		}
		return mapped

	default:
		return selection
	}
}

// mapFieldName maps a single field name, preserving modifiers
func (t *FieldMappingTransformer) mapFieldName(field string) string {
	baseField, modifier := sigma.ParseModifier(field)
	
	if newField, ok := t.mappings[baseField]; ok {
		if modifier != sigma.ModifierNone {
			return newField + "|" + string(modifier)
		}
		return newField
	}
	
	return field
}

// WindowsFieldMappingTransformer provides common Windows field mappings
type WindowsFieldMappingTransformer struct {
	*FieldMappingTransformer
}

// NewWindowsFieldMappingTransformer creates a transformer with common Windows mappings
func NewWindowsFieldMappingTransformer() *WindowsFieldMappingTransformer {
	mappings := map[string]string{
		// Process creation mappings
		"CommandLine":       "process.command_line",
		"Image":             "process.executable",
		"ProcessId":         "process.pid",
		"ParentProcessId":   "process.parent.pid",
		"ParentImage":       "process.parent.executable",
		"ParentCommandLine": "process.parent.command_line",
		"User":              "user.name",
		"IntegrityLevel":    "process.integrity_level",
		
		// Network mappings
		"SourceIp":          "source.ip",
		"DestinationIp":     "destination.ip",
		"SourcePort":        "source.port",
		"DestinationPort":   "destination.port",
		"Protocol":          "network.protocol",
		
		// File mappings
		"TargetFilename":    "file.path",
		"TargetObject":      "registry.path",
		
		// Common event fields
		"EventID":           "event.code",
		"Computer":          "host.name",
		"Channel":           "winlog.channel",
		"Provider":          "winlog.provider_name",
	}
	
	return &WindowsFieldMappingTransformer{
		FieldMappingTransformer: NewFieldMappingTransformer("windows-field-mapping", mappings),
	}
}

// ECSFieldMappingTransformer provides ECS (Elastic Common Schema) field mappings
type ECSFieldMappingTransformer struct {
	*FieldMappingTransformer
}

// NewECSFieldMappingTransformer creates a transformer with ECS mappings
func NewECSFieldMappingTransformer() *ECSFieldMappingTransformer {
	mappings := map[string]string{
		// Generic mappings to ECS
		"src_ip":     "source.ip",
		"dst_ip":     "destination.ip",
		"src_port":   "source.port",
		"dst_port":   "destination.port",
		"username":   "user.name",
		"hostname":   "host.name",
		"filename":   "file.name",
		"filepath":   "file.path",
		"hash":       "file.hash.sha256",
		"md5":        "file.hash.md5",
		"sha1":       "file.hash.sha1",
		"sha256":     "file.hash.sha256",
	}
	
	return &ECSFieldMappingTransformer{
		FieldMappingTransformer: NewFieldMappingTransformer("ecs-field-mapping", mappings),
	}
}