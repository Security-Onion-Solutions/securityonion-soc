// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// FlowbitOperation represents the type of flowbit operation
type FlowbitOperation int

const (
	FlowbitUnknown  FlowbitOperation = iota
	FlowbitSet                       // set
	FlowbitSetX                      // setx
	FlowbitUnset                     // unset
	FlowbitToggle                    // toggle
	FlowbitIsSet                     // isset
	FlowbitIsNotSet                  // isnotset
	FlowbitNoAlert                   // noalert
)

// IsSetter returns true if operation sets/modifies flowbits
func (op FlowbitOperation) IsSetter() bool {
	return op == FlowbitSet || op == FlowbitSetX ||
		op == FlowbitUnset || op == FlowbitToggle
}

// IsGetter returns true if operation checks flowbits
func (op FlowbitOperation) IsGetter() bool {
	return op == FlowbitIsSet || op == FlowbitIsNotSet
}

// FlowbitInfo represents a parsed flowbit option
type FlowbitInfo struct {
	Operation FlowbitOperation
	Name      string
}

// FlowbitDependency tracks why a disabled rule is needed
type FlowbitDependency struct {
	Reason      string   // "required for flowbit dependency"
	FlowbitName string   // e.g., "ET.Evil"
	RequiredBy  []string // SIDs of rules that need this flowbit
}

// FlowbitResolver handles flowbit dependency resolution
type FlowbitResolver struct {
	logger *nidsLogger
}

// NewFlowbitResolver creates a new flowbit resolver
func NewFlowbitResolver(logger *nidsLogger) *FlowbitResolver {
	return &FlowbitResolver{
		logger: logger,
	}
}

// setterInfo tracks a setter rule and which flowbit it sets
type setterInfo struct {
	det         *model.Detection
	flowbitName string
}

// ParseFlowbits extracts all flowbit operations from a rule
func (r *FlowbitResolver) ParseFlowbits(content string) ([]*FlowbitInfo, error) {
	parsed, err := ParseSuricataRule(content)
	if err != nil {
		return nil, err
	}

	var flowbits []*FlowbitInfo

	for _, opt := range parsed.Options {
		if opt.Name != "flowbits" || opt.Value == nil {
			continue
		}

		parts := strings.Split(*opt.Value, ",")
		info := &FlowbitInfo{}

		if len(parts) == 1 {
			switch parts[0] {
			case "noalert":
				info.Operation = FlowbitNoAlert
			default:
				continue // Skip unknown single-word flowbits
			}
		} else if len(parts) >= 2 {
			switch parts[0] {
			case "set":
				info.Operation = FlowbitSet
			case "setx":
				info.Operation = FlowbitSetX
			case "unset":
				info.Operation = FlowbitUnset
			case "toggle":
				info.Operation = FlowbitToggle
			case "isset":
				info.Operation = FlowbitIsSet
			case "isnotset":
				info.Operation = FlowbitIsNotSet
			default:
				continue // Skip unknown operations
			}
			info.Name = parts[1]
		}

		if info.Operation != FlowbitUnknown {
			flowbits = append(flowbits, info)
		}
	}

	return flowbits, nil
}

// getRequiredFlowbitsWithTracking gets flowbits needed by effectively enabled rules
// Also tracks which rules need which flowbits for dependency documentation
func (r *FlowbitResolver) getRequiredFlowbitsWithTracking(
	detections []*model.Detection,
	effectivelyEnabled map[string]bool,
	flowbitNeededBy map[string][]string,
) map[string]bool {
	required := make(map[string]bool)

	for _, det := range detections {
		// Check if rule is effectively enabled (user enabled OR needed for flowbits)
		if !effectivelyEnabled[det.PublicID] || det.PendingDelete {
			continue
		}

		flowbits, err := r.ParseFlowbits(det.Content)
		if err != nil {
			r.logger.WithError(err).WithField("sid", det.PublicID).
				Debug("failed to parse flowbits")
			continue
		}

		for _, fb := range flowbits {
			if fb.Operation.IsGetter() {
				required[fb.Name] = true
				flowbitNeededBy[fb.Name] = append(flowbitNeededBy[fb.Name], det.PublicID)
			}
		}
	}

	return required
}

// getDisabledSetterRulesWithFlowbitInfo finds disabled rules that set required flowbits
func (r *FlowbitResolver) getDisabledSetterRulesWithFlowbitInfo(
	detections []*model.Detection,
	requiredFlowbits map[string]bool,
	effectivelyEnabled map[string]bool,
) []*setterInfo {
	var setters []*setterInfo

	for _, det := range detections {
		// Only look at rules that are NOT already effectively enabled
		if effectivelyEnabled[det.PublicID] || det.PendingDelete {
			continue
		}

		flowbits, err := r.ParseFlowbits(det.Content)
		if err != nil {
			continue
		}

		for _, fb := range flowbits {
			if fb.Operation.IsSetter() && requiredFlowbits[fb.Name] {
				setters = append(setters, &setterInfo{
					det:         det,
					flowbitName: fb.Name,
				})
				break // Only add each rule once
			}
		}
	}

	return setters
}

// ResolveFlowbitDependencies performs multi-pass flowbit resolution
// Identifies which disabled rules are needed for flowbits
// IMPORTANT: Does NOT modify det.IsEnabled - preserves user intent
// Returns map of SID -> dependency info for disabled rules that need to run
//
// Pass 1:
//  1. Find all flowbits that enabled rules need (isset/isnotset operations)
//  2. Find all disabled rules that set those flowbits
//  3. Mark those disabled rules as "effectively enabled for flowbits"
//
// Pass 2-N:
//  4. The newly "enabled" rules might themselves need other flowbits
//  5. Find disabled rules that set those flowbits
//  6. Repeat until no new dependencies are found (or hit 100-pass limit)

func (r *FlowbitResolver) ResolveFlowbitDependencies(
	detections []*model.Detection,
) map[string]*FlowbitDependency {
	neededButDisabled := make(map[string]*FlowbitDependency)

	// Track which rules need which flowbits for dependency documentation
	flowbitNeededBy := make(map[string][]string) // flowbitName -> []SID

	const maxPasses = 100

	// Create a working map to track "effectively enabled" rules
	// (enabled rules + disabled rules that are needed for flowbits)
	effectivelyEnabled := make(map[string]bool)
	for _, det := range detections {
		if det.IsEnabled {
			effectivelyEnabled[det.PublicID] = true
		}
	}

	hitMaxPasses := true
	for pass := 1; pass <= maxPasses; pass++ {
		r.logger.WithField("pass", pass).Debug("flowbit resolution pass")

		// Get flowbits required by "effectively enabled" rules
		required := r.getRequiredFlowbitsWithTracking(detections, effectivelyEnabled, flowbitNeededBy)

		if len(required) == 0 {
			hitMaxPasses = false
			break
		}

		r.logger.WithField("requiredFlowbits", len(required)).
			Debug("found required flowbits")

		// Find disabled rules that set those flowbits
		setters := r.getDisabledSetterRulesWithFlowbitInfo(detections, required, effectivelyEnabled)

		if len(setters) == 0 {
			r.logger.Debug("all flowbit dependencies satisfied")
			hitMaxPasses = false
			break
		}

		// Mark these as "effectively enabled" and track them
		for _, setter := range setters {
			r.logger.WithFields(log.Fields{
				"sid":     setter.det.PublicID,
				"title":   setter.det.Title,
				"flowbit": setter.flowbitName,
			}).Debug("rule needed for flowbit dependency (will run with noalert)")

			effectivelyEnabled[setter.det.PublicID] = true

			neededButDisabled[setter.det.PublicID] = &FlowbitDependency{
				Reason:      "required for flowbit dependency",
				FlowbitName: setter.flowbitName,
				RequiredBy:  flowbitNeededBy[setter.flowbitName],
			}
		}
	}

	if hitMaxPasses {
		r.logger.Warn("flowbit resolution hit max passes limit")
	}

	if len(neededButDisabled) > 0 {
		r.logger.WithField("neededCount", len(neededButDisabled)).
			Info("identified disabled rules needed for flowbit dependencies")
	}

	return neededButDisabled
}

// AddNoalertToRule adds noalert option before sid (for auto-enabled rules)
func AddNoalertToRule(content string) string {
	parsed, err := ParseSuricataRule(content)
	if err != nil {
		return content
	}

	// Check if noalert already exists
	for _, opt := range parsed.Options {
		if opt.Name == "noalert" {
			return content
		}
		if opt.Name == "flowbits" && opt.Value != nil && *opt.Value == "noalert" {
			return content
		}
	}

	// Find sid option position
	sidIndex := -1
	for i, opt := range parsed.Options {
		if opt.Name == "sid" {
			sidIndex = i
			break
		}
	}

	noalertOpt := &RuleOption{Name: "noalert", Value: nil}

	if sidIndex >= 0 {
		// Insert before sid
		newOpts := make([]*RuleOption, 0, len(parsed.Options)+1)
		newOpts = append(newOpts, parsed.Options[:sidIndex]...)
		newOpts = append(newOpts, noalertOpt)
		newOpts = append(newOpts, parsed.Options[sidIndex:]...)
		parsed.Options = newOpts
	} else {
		// Add as last option
		parsed.Options = append(parsed.Options, noalertOpt)
	}

	return parsed.String()
}
