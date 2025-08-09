// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma_test

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
	_ "github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/backends"
)

var benchmarkRule = `
title: Suspicious PowerShell Process Patterns
id: benchmark-001
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cmd:
    CommandLine|contains:
      - 'Invoke-Expression'
      - 'iex'
      - 'Invoke-Command'
      - 'icm'
      - 'Invoke-WebRequest'
      - 'iwr'
      - 'DownloadString'
      - 'DownloadFile'
      - 'EncodedCommand'
      - 'Base64'
  filter_parent:
    ParentImage|endswith:
      - '\explorer.exe'
      - '\code.exe'
  condition: selection_img and selection_cmd and not filter_parent
`

func BenchmarkParseRule(b *testing.B) {
	ruleBytes := []byte(benchmarkRule)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule, err := sigma.ParseRule(ruleBytes)
		if err != nil {
			b.Fatal(err)
		}
		_ = rule
	}
}

func BenchmarkConvertToEQL(b *testing.B) {
	rule, err := sigma.ParseRule([]byte(benchmarkRule))
	if err != nil {
		b.Fatal(err)
	}
	
	converter, err := sigma.GetConverter("eql")
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query, err := converter.Convert(rule, nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = query
	}
}

func BenchmarkEndToEnd(b *testing.B) {
	ruleBytes := []byte(benchmarkRule)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule, err := sigma.ParseRule(ruleBytes)
		if err != nil {
			b.Fatal(err)
		}
		
		query, err := sigma.ConvertRule(rule, "eql", nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = query
	}
}

// Benchmark with field mappings
func BenchmarkConvertWithFieldMappings(b *testing.B) {
	rule, err := sigma.ParseRule([]byte(benchmarkRule))
	if err != nil {
		b.Fatal(err)
	}
	
	converter, err := sigma.GetConverter("eql")
	if err != nil {
		b.Fatal(err)
	}
	
	// Set up field mappings
	mappings := []sigma.FieldMapping{
		{Source: "Image", Target: "process.executable"},
		{Source: "CommandLine", Target: "process.command_line"},
		{Source: "ParentImage", Target: "process.parent.executable"},
		{Source: "EventID", Target: "event.code"},
		{Source: "User", Target: "user.name"},
	}
	converter.SetFieldMappings(mappings)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query, err := converter.Convert(rule, nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = query
	}
}