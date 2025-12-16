// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"fmt"
	"testing"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

// TestFlowbitResolver_SimpleChain tests basic flowbit dependency resolution
func TestFlowbitResolver_SimpleChain(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: false, // User disabled this setter
			Content:   "alert tcp any any -> any any (msg:\"Setter\"; flowbits:set,evil; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: true, // User enabled this getter
			Content:   "alert tcp any any -> any any (msg:\"Getter\"; flowbits:isset,evil; sid:2;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	// Verify rule 1 is identified as needed
	assert.Equal(t, 1, len(result), "Should identify 1 rule as needed")
	assert.Contains(t, result, "1", "Rule 1 should be in flowbitRequired")
	assert.Equal(t, "required for flowbit dependency", result["1"].Reason)
	assert.Equal(t, "evil", result["1"].FlowbitName)
	assert.Contains(t, result["1"].RequiredBy, "2", "Rule 1 should be required by rule 2")

	// CRITICAL: IsEnabled should NOT be modified
	assert.False(t, detections[0].IsEnabled, "Rule 1 IsEnabled should remain false (user preference)")
	assert.True(t, detections[1].IsEnabled, "Rule 2 IsEnabled should remain true")
}

// TestFlowbitResolver_TransitiveDependency tests multi-level dependency chains
func TestFlowbitResolver_TransitiveDependency(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Level 1\"; flowbits:set,bit1; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Level 2\"; flowbits:isset,bit1; flowbits:set,bit2; sid:2;)",
		},
		{
			PublicID:  "3",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"Level 3\"; flowbits:isset,bit2; sid:3;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	// Both rule 1 and rule 2 should be needed
	assert.Equal(t, 2, len(result), "Should identify 2 rules as needed")
	assert.Contains(t, result, "1", "Rule 1 should be needed")
	assert.Contains(t, result, "2", "Rule 2 should be needed")

	// Verify dependency chain
	assert.Equal(t, "bit1", result["1"].FlowbitName)
	assert.Equal(t, "bit2", result["2"].FlowbitName)

	// IsEnabled should be unchanged for all rules
	assert.False(t, detections[0].IsEnabled, "Rule 1 IsEnabled should remain false")
	assert.False(t, detections[1].IsEnabled, "Rule 2 IsEnabled should remain false")
	assert.True(t, detections[2].IsEnabled, "Rule 3 IsEnabled should remain true")
}

// TestFlowbitResolver_NoRequiredFlowbits tests scenario where no flowbits are needed
func TestFlowbitResolver_NoRequiredFlowbits(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Setter\"; flowbits:set,evil; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"No flowbits\"; sid:2;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	assert.Equal(t, 0, len(result), "No rules should be needed")
	assert.False(t, detections[0].IsEnabled, "Rule 1 should stay disabled (not needed)")
}

// TestFlowbitResolver_AllSetterTypes tests all setter operation types
func TestFlowbitResolver_AllSetterTypes(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Set\"; flowbits:set,bit1; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"SetX\"; flowbits:setx,bit2; sid:2;)",
		},
		{
			PublicID:  "3",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Unset\"; flowbits:unset,bit3; sid:3;)",
		},
		{
			PublicID:  "4",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Toggle\"; flowbits:toggle,bit4; sid:4;)",
		},
		{
			PublicID:  "5",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"Checker\"; flowbits:isset,bit1; flowbits:isset,bit2; flowbits:isset,bit3; flowbits:isset,bit4; sid:5;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	assert.Equal(t, 4, len(result), "All 4 setter rules should be needed")
	assert.Contains(t, result, "1", "set operation should be detected")
	assert.Contains(t, result, "2", "setx operation should be detected")
	assert.Contains(t, result, "3", "unset operation should be detected")
	assert.Contains(t, result, "4", "toggle operation should be detected")
}

// TestFlowbitResolver_MultipleSettersForSameFlowbit tests multiple rules setting the same flowbit
func TestFlowbitResolver_MultipleSettersForSameFlowbit(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Setter A\"; flowbits:set,evil; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Setter B\"; flowbits:set,evil; sid:2;)",
		},
		{
			PublicID:  "3",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"Getter\"; flowbits:isset,evil; sid:3;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	// Both setters should be identified (resolver doesn't prioritize, includes all)
	assert.Equal(t, 2, len(result), "Both setter rules should be needed")
	assert.Contains(t, result, "1")
	assert.Contains(t, result, "2")
}

// TestFlowbitResolver_PendingDelete tests that pending delete rules are ignored
func TestFlowbitResolver_PendingDelete(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:      "1",
			IsEnabled:     false,
			PendingDelete: true, // This rule is marked for deletion
			Content:       "alert tcp any any -> any any (msg:\"Setter\"; flowbits:set,evil; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"Getter\"; flowbits:isset,evil; sid:2;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	// Rule 1 should NOT be included (it's pending delete)
	assert.Equal(t, 0, len(result), "Pending delete rules should be ignored")
}

// TestFlowbitResolver_AlreadyEnabledSetter tests that already enabled setters are not included in result
func TestFlowbitResolver_AlreadyEnabledSetter(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: true, // Already enabled by user
			Content:   "alert tcp any any -> any any (msg:\"Setter\"; flowbits:set,evil; sid:1;)",
		},
		{
			PublicID:  "2",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"Getter\"; flowbits:isset,evil; sid:2;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	// No rules should be in result (setter is already enabled)
	assert.Equal(t, 0, len(result), "Already enabled setters should not be in flowbitRequired")
}

// TestAddNoalertToRule tests the noalert addition function
func TestAddNoalertToRule(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Add noalert before sid",
			input:    "alert tcp any any -> any any (msg:\"test\"; flowbits:set,evil; sid:1; rev:1;)",
			expected: "alert tcp any any -> any any (msg:\"test\"; flowbits:set,evil; noalert; sid:1; rev:1;)",
		},
		{
			name:     "Already has noalert - no change",
			input:    "alert tcp any any -> any any (msg:\"test\"; noalert; flowbits:set,evil; sid:1;)",
			expected: "alert tcp any any -> any any (msg:\"test\"; noalert; flowbits:set,evil; sid:1;)",
		},
		{
			name:     "Already has flowbits:noalert - no change",
			input:    "alert tcp any any -> any any (msg:\"test\"; flowbits:noalert; sid:1;)",
			expected: "alert tcp any any -> any any (msg:\"test\"; flowbits:noalert; sid:1;)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddNoalertToRule(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseFlowbits tests the flowbit parsing logic
func TestParseFlowbits(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	tests := []struct {
		name     string
		content  string
		expected []FlowbitInfo
	}{
		{
			name:    "Set operation",
			content: "alert tcp any any -> any any (msg:\"test\"; flowbits:set,evil; sid:1;)",
			expected: []FlowbitInfo{
				{Operation: FlowbitSet, Name: "evil"},
			},
		},
		{
			name:    "IsSet operation",
			content: "alert tcp any any -> any any (msg:\"test\"; flowbits:isset,evil; sid:1;)",
			expected: []FlowbitInfo{
				{Operation: FlowbitIsSet, Name: "evil"},
			},
		},
		{
			name:    "Multiple flowbits",
			content: "alert tcp any any -> any any (msg:\"test\"; flowbits:set,bit1; flowbits:isset,bit2; sid:1;)",
			expected: []FlowbitInfo{
				{Operation: FlowbitSet, Name: "bit1"},
				{Operation: FlowbitIsSet, Name: "bit2"},
			},
		},
		{
			name:    "Noalert flowbit",
			content: "alert tcp any any -> any any (msg:\"test\"; flowbits:noalert; sid:1;)",
			expected: []FlowbitInfo{
				{Operation: FlowbitNoAlert, Name: ""},
			},
		},
		{
			name:     "No flowbits",
			content:  "alert tcp any any -> any any (msg:\"test\"; sid:1;)",
			expected: []FlowbitInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolver.ParseFlowbits(tt.content)
			assert.NoError(t, err)
			assert.Equal(t, len(tt.expected), len(result))
			for i, exp := range tt.expected {
				assert.Equal(t, exp.Operation, result[i].Operation)
				assert.Equal(t, exp.Name, result[i].Name)
			}
		})
	}
}

// TestFlowbitOperation_IsSetter tests the IsSetter helper method
func TestFlowbitOperation_IsSetter(t *testing.T) {
	assert.True(t, FlowbitSet.IsSetter())
	assert.True(t, FlowbitSetX.IsSetter())
	assert.True(t, FlowbitUnset.IsSetter())
	assert.True(t, FlowbitToggle.IsSetter())
	assert.False(t, FlowbitIsSet.IsSetter())
	assert.False(t, FlowbitIsNotSet.IsSetter())
	assert.False(t, FlowbitNoAlert.IsSetter())
	assert.False(t, FlowbitUnknown.IsSetter())
}

// TestFlowbitOperation_IsGetter tests the IsGetter helper method
func TestFlowbitOperation_IsGetter(t *testing.T) {
	assert.False(t, FlowbitSet.IsGetter())
	assert.False(t, FlowbitSetX.IsGetter())
	assert.False(t, FlowbitUnset.IsGetter())
	assert.False(t, FlowbitToggle.IsGetter())
	assert.True(t, FlowbitIsSet.IsGetter())
	assert.True(t, FlowbitIsNotSet.IsGetter())
	assert.False(t, FlowbitNoAlert.IsGetter())
	assert.False(t, FlowbitUnknown.IsGetter())
}

// TestParseFlowbits_AdditionalCoverage tests edge cases for flowbit parsing
func TestParseFlowbits_AdditionalCoverage(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	t.Run("Invalid rule content", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("not a valid rule")

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Flowbits option with nil value", func(t *testing.T) {
		// A rule with flowbits keyword but no value (edge case)
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits; sid:1;)")

		assert.NoError(t, err)
		assert.Empty(t, result) // Should skip flowbits with nil value
	})

	t.Run("Unknown single-word flowbit operation", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:unknownop; sid:1;)")

		assert.NoError(t, err)
		assert.Empty(t, result) // Unknown single-word ops should be skipped
	})

	t.Run("Unknown two-part flowbit operation", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:invalidop,somename; sid:1;)")

		assert.NoError(t, err)
		assert.Empty(t, result) // Unknown operations should be skipped
	})

	t.Run("IsNotSet operation", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:isnotset,mybit; sid:1;)")

		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, FlowbitIsNotSet, result[0].Operation)
		assert.Equal(t, "mybit", result[0].Name)
	})

	t.Run("SetX operation", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:setx,mybit; sid:1;)")

		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, FlowbitSetX, result[0].Operation)
	})

	t.Run("Unset operation", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:unset,mybit; sid:1;)")

		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, FlowbitUnset, result[0].Operation)
	})

	t.Run("Toggle operation", func(t *testing.T) {
		result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:toggle,mybit; sid:1;)")

		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, FlowbitToggle, result[0].Operation)
	})
}

// TestGetRequiredFlowbitsWithTracking_AdditionalCoverage tests edge cases
func TestGetRequiredFlowbitsWithTracking_AdditionalCoverage(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	t.Run("Skip PendingDelete detections", func(t *testing.T) {
		detections := []*model.Detection{
			{
				PublicID:      "1",
				IsEnabled:     true,
				PendingDelete: true, // Should be skipped
				Content:       "alert tcp any any -> any any (msg:\"Getter\"; flowbits:isset,evil; sid:1;)",
			},
		}

		effectivelyEnabled := map[string]bool{"1": true}
		flowbitNeededBy := make(map[string][]string)

		result := resolver.getRequiredFlowbitsWithTracking(detections, effectivelyEnabled, flowbitNeededBy)

		assert.Empty(t, result)
		assert.Empty(t, flowbitNeededBy)
	})

	t.Run("Skip detections not effectively enabled", func(t *testing.T) {
		detections := []*model.Detection{
			{
				PublicID:  "1",
				IsEnabled: false,
				Content:   "alert tcp any any -> any any (msg:\"Getter\"; flowbits:isset,evil; sid:1;)",
			},
		}

		effectivelyEnabled := map[string]bool{} // Not in the map
		flowbitNeededBy := make(map[string][]string)

		result := resolver.getRequiredFlowbitsWithTracking(detections, effectivelyEnabled, flowbitNeededBy)

		assert.Empty(t, result)
	})

	t.Run("Handle ParseFlowbits error gracefully", func(t *testing.T) {
		detections := []*model.Detection{
			{
				PublicID:  "1",
				IsEnabled: true,
				Content:   "invalid rule content", // Will cause parse error
			},
		}

		effectivelyEnabled := map[string]bool{"1": true}
		flowbitNeededBy := make(map[string][]string)

		// Should not panic, just skip the rule
		result := resolver.getRequiredFlowbitsWithTracking(detections, effectivelyEnabled, flowbitNeededBy)

		assert.Empty(t, result)
	})

	t.Run("Track flowbit dependencies correctly", func(t *testing.T) {
		detections := []*model.Detection{
			{
				PublicID:  "1",
				IsEnabled: true,
				Content:   "alert tcp any any -> any any (msg:\"Getter1\"; flowbits:isset,evil; sid:1;)",
			},
			{
				PublicID:  "2",
				IsEnabled: true,
				Content:   "alert tcp any any -> any any (msg:\"Getter2\"; flowbits:isset,evil; flowbits:isnotset,good; sid:2;)",
			},
		}

		effectivelyEnabled := map[string]bool{"1": true, "2": true}
		flowbitNeededBy := make(map[string][]string)

		result := resolver.getRequiredFlowbitsWithTracking(detections, effectivelyEnabled, flowbitNeededBy)

		assert.True(t, result["evil"])
		assert.True(t, result["good"])
		assert.Contains(t, flowbitNeededBy["evil"], "1")
		assert.Contains(t, flowbitNeededBy["evil"], "2")
		assert.Contains(t, flowbitNeededBy["good"], "2")
	})
}

// TestParseFlowbits_EmptyParts tests edge case where flowbits value splits to empty
func TestParseFlowbits_EmptyParts(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	// This is a contrived case - flowbits with empty value after the colon
	// The parser handles "flowbits:" by setting Value to empty string
	// When split by comma, an empty string gives []string{""} which has len 1
	// So we need a case where len(parts) == 0, but that can't happen with strings.Split
	// Actually looking at the code: len(parts) will never be 0 from strings.Split
	// The else branch at line 113-114 is dead code - it can never be reached
	// strings.Split always returns at least one element

	// However, we can test that empty flowbit value is handled
	result, err := resolver.ParseFlowbits("alert tcp any any -> any any (msg:\"test\"; flowbits:; sid:1;)")
	assert.NoError(t, err)
	// Empty value after colon - splits to [""], which has len 1, goes into len(parts)==1 branch
	// Empty string doesn't match "noalert", so hits default case and continues
	assert.Empty(t, result)
}

// TestGetDisabledSetterRulesWithFlowbitInfo_ParseError tests error handling
func TestGetDisabledSetterRulesWithFlowbitInfo_ParseError(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		{
			PublicID:  "1",
			IsEnabled: false, // disabled setter
			Content:   "invalid rule content", // will fail to parse
		},
	}

	requiredFlowbits := map[string]bool{"evil": true}
	effectivelyEnabled := map[string]bool{} // Not effectively enabled

	result := resolver.getDisabledSetterRulesWithFlowbitInfo(detections, requiredFlowbits, effectivelyEnabled)

	assert.Empty(t, result) // Should skip invalid rules
}

// TestResolveFlowbitDependencies_MaxPasses tests the max passes limit
func TestResolveFlowbitDependencies_MaxPasses(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	// Create a chain that's longer than maxPasses (100)
	// Each pass only enables one level of the chain
	// We need 105+ levels to guarantee hitting the 100 pass limit
	detections := make([]*model.Detection, 0, 110)

	// Create 105 levels of dependency chain
	for i := 0; i < 105; i++ {
		var content string
		sid := i + 1
		if i == 0 {
			// First rule just sets a flowbit
			content = fmt.Sprintf("alert tcp any any -> any any (msg:\"Level 0\"; flowbits:set,bit0; sid:%d;)", sid)
		} else {
			// Each subsequent rule checks previous bit and sets next
			content = fmt.Sprintf("alert tcp any any -> any any (msg:\"Level %d\"; flowbits:isset,bit%d; flowbits:set,bit%d; sid:%d;)", i, i-1, i, sid)
		}
		detections = append(detections, &model.Detection{
			PublicID:  fmt.Sprintf("%d", sid),
			IsEnabled: false,
			Content:   content,
		})
	}

	// Final rule that's enabled and triggers the chain
	detections = append(detections, &model.Detection{
		PublicID:  "final",
		IsEnabled: true,
		Content:   "alert tcp any any -> any any (msg:\"Final\"; flowbits:isset,bit104; sid:999;)",
	})

	// This should hit maxPasses limit
	result := resolver.ResolveFlowbitDependencies(detections)

	// Should still return some results even if max passes hit
	assert.NotNil(t, result)
	// Should have enabled many rules but not all (because max passes hit)
	// The algorithm would need 105 passes to resolve all, but max is 100
	assert.True(t, len(result) > 0, "Should have resolved some dependencies")
}

// TestAddNoalertToRule_ParseError tests error handling for invalid rule
func TestAddNoalertToRule_ParseError(t *testing.T) {
	result := AddNoalertToRule("invalid rule content")

	// Should return original content unchanged
	assert.Equal(t, "invalid rule content", result)
}

// TestAddNoalertToRule_NoSid tests adding noalert when rule has no sid
func TestAddNoalertToRule_NoSid(t *testing.T) {
	// A rule without sid option
	input := "alert tcp any any -> any any (msg:\"test\"; flowbits:set,evil;)"
	result := AddNoalertToRule(input)

	// Should add noalert at end
	assert.Contains(t, result, "noalert")
}

// TestFlowbitResolver_ComplexChain tests a complex real-world scenario
func TestFlowbitResolver_ComplexChain(t *testing.T) {
	resolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "flowbits")})

	detections := []*model.Detection{
		// Stage 1: Initial compromise
		{
			PublicID:  "1",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"ET EXPLOIT Initial\"; flowbits:set,ET.Exploit; sid:1;)",
		},
		// Stage 2: Callback (needs stage 1)
		{
			PublicID:  "2",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"ET MALWARE Callback\"; flowbits:isset,ET.Exploit; flowbits:set,ET.Callback; sid:2;)",
		},
		// Stage 3: Data exfil (needs stage 2)
		{
			PublicID:  "3",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"ET POLICY Exfil\"; flowbits:isset,ET.Callback; flowbits:set,ET.Exfil; sid:3;)",
		},
		// Final detection (enabled by user, triggers entire chain)
		{
			PublicID:  "4",
			IsEnabled: true,
			Content:   "alert tcp any any -> any any (msg:\"ET ATTACK Confirmed\"; flowbits:isset,ET.Exfil; sid:4;)",
		},
		// Unrelated disabled setter (should NOT be included)
		{
			PublicID:  "5",
			IsEnabled: false,
			Content:   "alert tcp any any -> any any (msg:\"Unrelated\"; flowbits:set,ET.Unrelated; sid:5;)",
		},
	}

	result := resolver.ResolveFlowbitDependencies(detections)

	// Rules 1, 2, 3 should be needed; rule 5 should NOT
	assert.Equal(t, 3, len(result), "Should identify 3 rules in the chain")
	assert.Contains(t, result, "1")
	assert.Contains(t, result, "2")
	assert.Contains(t, result, "3")
	assert.NotContains(t, result, "5", "Unrelated rule should not be included")

	// All IsEnabled values should be preserved
	assert.False(t, detections[0].IsEnabled)
	assert.False(t, detections[1].IsEnabled)
	assert.False(t, detections[2].IsEnabled)
	assert.True(t, detections[3].IsEnabled)
	assert.False(t, detections[4].IsEnabled)
}
