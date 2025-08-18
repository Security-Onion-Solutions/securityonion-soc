# Native Go Sigma Converter Implementation Plan

## Executive Summary

This document outlines a comprehensive plan to implement a native Go-based Sigma converter for SecurityOnion SOC, eliminating the dependency on external Python (pySigma) calls. The converter will be integrated directly into the backend, improving performance, reliability, and deployment simplicity.

**Update**: After reviewing the codebase and pySigma implementation, this plan has been updated to include:
- Immediate switch strategy with Python fallback for safety
- Shared helper functions to avoid code duplication
- Comprehensive test strategy based on existing patterns
- Modular design matching pySigma's architecture

## Current State Analysis

### Existing Architecture
- **Sigma Integration**: Currently implemented in the ElastAlert engine module
- **Conversion Method**: External calls to Python `sigma` CLI tool via `exec.CommandContext`
- **Conversion Locations**:
  1. `elastalert.go:sigmaToElastAlert()` - Converts Sigma rules to EQL for ElastAlert
  2. `playbook.go:ConvertQuestions()` - Converts Sigma queries for playbooks
- **Dependencies**:
  - Python 3 with pySigma 0.11.20
  - sigma-cli 1.0.5
  - pysigma-backend-elasticsearch
  - Custom pysigma_backend_securityonion wheel
  - Pipeline configuration files

### Current Conversion Flow
1. Sigma YAML rule is read from detection content
2. Custom filters (overrides) are applied if present
3. Rule is passed to Python `sigma` CLI via stdin
4. Conversion uses multiple pipelines:
   - `/opt/sensoroni/sigma_final_pipeline.yaml`
   - `/opt/sensoroni/sigma_so_pipeline.yaml`
   - `windows-logsources`
   - `ecs_windows`
5. Output is parsed and returned as EQL or security_onion format

### Key Usage Patterns Identified
1. **ElastAlert Module (`elastalert.go`)**:
   - Uses `sigmaToElastAlert()` to convert Sigma rules to EQL
   - Applies custom filters (overrides) before conversion
   - Executes via `exec.CommandContext` with IOManager interface
   - Strips first line from output and trims whitespace

2. **Playbook Module (`playbook.go`)**:
   - Uses `ConvertQuestions()` to convert Sigma queries to Security Onion format
   - Joins multiple queries with `\n---\n` separator
   - Parses JSON output into `ConvertedQuery` structs
   - Uses same IOManager.ExecCommand pattern

3. **Shared Dependencies**:
   - Both modules use the same Python `sigma` CLI command
   - Both rely on the same pipeline configuration files
   - Both use IOManager interface for command execution
   - Custom `pysigma_backend_securityonion` wheel installed via Docker

## Implementation Plan

### Phase 1: Core Architecture Design

#### 1.1 Package Structure
```
server/modules/sigma/
├── converter.go           # Main converter interface and factory
├── parser.go             # Sigma rule parser
├── ast.go                # Abstract syntax tree structures
├── errors.go             # Custom error types
├── config.go             # Configuration and feature flags
├── common/
│   ├── helpers.go       # Shared helper functions
│   ├── exec.go          # Python fallback execution
│   └── validation.go    # Rule validation utilities
├── backends/
│   ├── base.go          # Base backend interface
│   ├── elasticsearch.go # Elasticsearch/EQL backend
│   ├── securityonion.go # Security Onion specific backend
│   └── python.go        # Python fallback backend wrapper
├── pipelines/
│   ├── pipeline.go      # Pipeline processor interface
│   ├── loader.go        # Pipeline configuration loader
│   ├── registry.go      # Pipeline transformation registry
│   └── transformers/    # Individual transformation implementations
├── conditions/
│   ├── parser.go        # Condition parser
│   ├── evaluator.go     # Condition evaluation logic
│   ├── operators.go     # Operator implementations
│   └── ast.go           # Condition AST structures
├── modifiers/
│   ├── base.go          # Modifier interface
│   ├── implementations.go # Built-in modifiers (contains, all, etc.)
│   └── registry.go      # Modifier registration
├── types/
│   ├── values.go        # Sigma value types
│   ├── fields.go        # Field mapping structures
│   └── logsource.go     # Log source definitions
└── tests/
    ├── fixtures/        # Test rule files
    ├── comparison/      # Python vs Go output comparison
    └── benchmarks/      # Performance benchmarks
```

#### 1.2 Core Interfaces
```go
// Rule represents a parsed Sigma rule
type Rule struct {
    Title       string
    ID          string
    Status      string
    Description string
    References  []string
    Author      string
    Date        time.Time
    Modified    time.Time
    Tags        []string
    LogSource   LogSource
    Detection   Detection
    Fields      []string
    FalsePositives []string
    Level       string
    CustomAttributes map[string]interface{}
}

// Converter interface for different backend conversions
type Converter interface {
    Convert(rule *Rule, pipelines []Pipeline) (string, error)
    GetTargetFormat() string
    SupportsCorrelation() bool
}

// Pipeline interface for rule transformations
type Pipeline interface {
    Process(rule *Rule) (*Rule, error)
    GetName() string
    GetPriority() int
}
```

### Phase 2: Parser Implementation

#### 2.1 YAML Rule Parser
- Implement comprehensive YAML parsing for Sigma rule structure
- Support all Sigma rule fields and metadata
- Handle nested detection logic with proper precedence
- Validate rule structure against Sigma specification

#### 2.2 Detection Condition Parser
- Implement recursive descent parser for Sigma conditions
- Support operators: AND, OR, NOT, 1 of, all of, 1 of them, all of them
- Handle selection references and pattern expressions
- Build abstract syntax tree (AST) for condition evaluation

#### 2.3 Value Type Handling
- String patterns with wildcards (*) and escaping
- Regular expressions
- Numeric values and ranges
- Boolean values
- Null/empty checks
- CIDR expressions for IP addresses
- Lists and expansions

### Phase 3: Backend Implementation

#### 3.1 Elasticsearch/EQL Backend
- Implement query generation for Elasticsearch Query Language (EQL)
- Map Sigma fields to Elasticsearch fields
- Handle field name transformations
- Support aggregations and correlations
- Generate proper query syntax with escaping

#### 3.2 Security Onion Backend
- Implement custom Security Onion query format
- Support specific field mappings for SO
- Handle custom detection logic
- Generate JSON output format as required

#### 3.3 Query Optimization
- Implement query optimization techniques
- Combine similar conditions
- Minimize query complexity
- Handle field existence checks efficiently

### Phase 4: Pipeline System

#### 4.1 Pipeline Framework
- Create flexible pipeline processing system
- Support pipeline chaining and ordering
- Implement pipeline configuration loading from YAML
- Handle pipeline priorities and dependencies

#### 4.2 Built-in Transformations
- Field mapping transformations
- Value transformations (case, encoding)
- Log source enrichment
- Condition modifications
- Rule metadata updates

#### 4.3 Custom Transformations
- Support for custom transformation plugins
- Transformation registration system
- Configuration validation
- Error handling and logging

### Phase 5: Immediate Switch Strategy

#### 5.1 Configuration-Based Switching
```go
// Configuration structure
type SigmaConfig struct {
    UseNativeConverter bool              `json:"useNativeConverter"`
    FallbackOnError    bool              `json:"fallbackOnError"`
    ComparisonMode     bool              `json:"comparisonMode"`
    LogMismatches      bool              `json:"logMismatches"`
    PythonTimeout      time.Duration     `json:"pythonTimeout"`
}

// Global converter interface
type SigmaConverter interface {
    ConvertToEQL(ctx context.Context, rule string, overrides []Override) (string, error)
    ConvertToSecurityOnion(ctx context.Context, queries []string) ([]*ConvertedQuery, error)
}

// Factory function for converter selection
func NewSigmaConverter(config SigmaConfig, iom IOManager) SigmaConverter {
    if config.UseNativeConverter {
        return &NativeConverter{
            config:     config,
            iom:        iom,
            fallback:   &PythonConverter{iom: iom},
        }
    }
    return &PythonConverter{iom: iom}
}
```

#### 5.2 Shared Helper Functions
```go
// common/helpers.go - Shared utilities to avoid duplication

// ApplyOverridesToRule applies custom filters to a Sigma rule
func ApplyOverridesToRule(rule string, overrides []*model.Override) (string, error) {
    if len(overrides) == 0 {
        return rule, nil
    }
    
    doc := map[string]interface{}{}
    if err := yaml.Unmarshal([]byte(rule), &doc); err != nil {
        return "", fmt.Errorf("unable to unmarshal sigma rule: %w", err)
    }
    
    detection, ok := doc["detection"].(map[string]interface{})
    if !ok {
        return "", fmt.Errorf("sigma rule does not contain a detection section")
    }
    
    // Apply override logic (shared between modules)
    for _, override := range overrides {
        if override.Type == model.OverrideTypeCustomFilter && override.IsEnabled {
            prepared, err := override.PrepareForSigma()
            if err != nil {
                return "", fmt.Errorf("unable to prepare filter: %w", err)
            }
            for k, v := range prepared {
                detection[k] = v
            }
        }
    }
    
    // Update condition
    if condition, ok := detection["condition"].(string); ok {
        detection["condition"] = fmt.Sprintf("(%s) and not 1 of sofilter*", condition)
    }
    
    result, err := yaml.Marshal(doc)
    if err != nil {
        return "", fmt.Errorf("unable to marshal sigma rule with overrides: %w", err)
    }
    
    return string(result), nil
}

// ParseSigmaOutput parses the output from sigma converter
func ParseSigmaOutput(output []byte) (string, error) {
    query := string(output)
    if firstLine := strings.Index(query, "\n"); firstLine != -1 {
        query = query[firstLine+1:]
    }
    return strings.TrimSpace(query), nil
}

// ParseConvertedQueries parses JSON lines output
func ParseConvertedQueries(output string) ([]*model.ConvertedQuery, error) {
    lines := strings.Split(strings.TrimSpace(output), "\n")
    lines = lo.Filter(lines, func(line string, _ int) bool {
        return len(line) > 0
    })
    
    queries := make([]*model.ConvertedQuery, 0, len(lines))
    for _, line := range lines {
        cq := &model.ConvertedQuery{}
        if err := json.Unmarshal([]byte(line), &cq); err != nil {
            return nil, fmt.Errorf("problem unmarshalling sigma cli output: %w", err)
        }
        queries = append(queries, cq)
    }
    return queries, nil
}
```

### Phase 6: Integration

#### 6.1 ElastAlert Module Integration
```go
// Updated sigmaToElastAlert using new converter interface
func (e *ElastAlertEngine) sigmaToElastAlert(ctx context.Context, det *model.Detection) (string, error) {
    // Apply overrides using shared helper
    ruleContent, err := sigma.ApplyOverridesToRule(det.Content, det.Overrides)
    if err != nil {
        return "", err
    }
    
    // Use converter interface (native or Python based on config)
    query, err := e.sigmaConverter.ConvertToEQL(ctx, ruleContent, det.Overrides)
    if err != nil {
        return "", fmt.Errorf("failed to convert rule: %w", err)
    }
    
    return query, nil
}
```

#### 6.2 Playbook Module Integration
```go
// Updated ConvertQuestions using new converter interface
func (pdm *PlaybookDiskManager) ConvertQuestions(ctx context.Context, queries []string) ([]*model.ConvertedQuery, error) {
    logger := log.FromContext(ctx)
    
    err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
    if err != nil {
        return nil, err
    }
    
    // Use converter interface
    converted, err := pdm.sigmaConverter.ConvertToSecurityOnion(ctx, queries)
    if err != nil {
        logger.WithError(err).Error("Failed to convert Sigma queries")
        return nil, err
    }
    
    return converted, nil
}
```

#### 6.3 Configuration Migration
```go
// Module configuration updates
type ElastAlertModuleConfig struct {
    // Existing fields...
    SigmaConverterConfig SigmaConfig `json:"sigmaConverterConfig"`
}

// Default configuration
var DefaultSigmaConfig = SigmaConfig{
    UseNativeConverter: false,  // Start with Python for safety
    FallbackOnError:    true,   // Fallback to Python on Go converter errors
    ComparisonMode:     true,   // Log differences during transition
    LogMismatches:      true,   // Help identify conversion issues
    PythonTimeout:      30 * time.Second,
}
```

### Phase 7: Testing Strategy

#### 7.1 Unit Tests
```go
// Test pattern following existing conventions
func TestSigmaParser(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *SigmaRule
        wantErr  bool
    }{
        {
            name: "valid sigma rule",
            input: validSigmaYAML,
            expected: &SigmaRule{/* expected structure */},
            wantErr: false,
        },
        // Add comprehensive test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ParseRule([]byte(tt.input))
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expected, result)
            }
        })
    }
}
```

#### 7.2 Integration Tests with Mocks
```go
// Following existing mock patterns from codebase
func TestSigmaToElastAlert(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()
    
    iom := mock.NewMockIOManager(ctrl)
    
    // Test both native and Python converters
    testCases := []struct {
        name       string
        useNative  bool
        detection  *model.Detection
        expected   string
    }{
        // Test cases for both converters
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            config := SigmaConfig{UseNativeConverter: tc.useNative}
            converter := NewSigmaConverter(config, iom)
            
            result, err := converter.ConvertToEQL(context.Background(), tc.detection.Content, tc.detection.Overrides)
            assert.NoError(t, err)
            assert.Equal(t, tc.expected, result)
        })
    }
}
```

#### 7.3 Comparison Tests
```go
// Automated comparison between Python and Go outputs
func TestConverterParity(t *testing.T) {
    // Load test rules from fixtures
    testRules := loadTestRules(t, "tests/fixtures/")
    
    pythonConverter := &PythonConverter{iom: DefaultIOManager()}
    goConverter := &NativeConverter{iom: DefaultIOManager()}
    
    mismatches := 0
    for _, rule := range testRules {
        pythonOut, err1 := pythonConverter.ConvertToEQL(context.Background(), rule.Content, nil)
        goOut, err2 := goConverter.ConvertToEQL(context.Background(), rule.Content, nil)
        
        if err1 != nil || err2 != nil {
            t.Errorf("Conversion error for %s: Python=%v, Go=%v", rule.ID, err1, err2)
            continue
        }
        
        if pythonOut != goOut {
            mismatches++
            t.Logf("Mismatch for %s:\nPython: %s\nGo: %s", rule.ID, pythonOut, goOut)
        }
    }
    
    parityRate := float64(len(testRules)-mismatches) / float64(len(testRules)) * 100
    t.Logf("Parity rate: %.2f%% (%d/%d rules match)", parityRate, len(testRules)-mismatches, len(testRules))
    
    // Require 95% parity
    assert.GreaterOrEqual(t, parityRate, 95.0)
}
```

#### 7.4 Benchmark Tests
```go
func BenchmarkSigmaConversion(b *testing.B) {
    rule := loadBenchmarkRule()
    
    b.Run("Python", func(b *testing.B) {
        converter := &PythonConverter{iom: DefaultIOManager()}
        for i := 0; i < b.N; i++ {
            _, _ = converter.ConvertToEQL(context.Background(), rule, nil)
        }
    })
    
    b.Run("Go", func(b *testing.B) {
        converter := &NativeConverter{iom: DefaultIOManager()}
        for i := 0; i < b.N; i++ {
            _, _ = converter.ConvertToEQL(context.Background(), rule, nil)
        }
    })
}
```

### Phase 7: Performance Optimization

#### 7.1 Parsing Optimization
- Implement efficient YAML parsing
- Cache parsed rules where appropriate
- Optimize AST construction

#### 7.2 Conversion Optimization
- Implement query caching for repeated conversions
- Optimize string operations and concatenations
- Use string builders for query construction

#### 7.3 Concurrency
- Support concurrent rule processing
- Implement thread-safe pipeline processing
- Optimize for multi-core systems

### Phase 9: Deployment and Migration

#### 9.1 Simplified Deployment Strategy
```yaml
# Configuration in sensoroni.json for immediate Go implementation
{
  "elastalert": {
    "sigmaConverterConfig": {
      "useNativeConverter": true,    // Use Go implementation immediately
      "fallbackOnError": false,      // No Python fallback in test env
      "comparisonMode": false,       // No comparison needed
      "logMismatches": false,
      "pythonTimeout": "30s"
    }
  }
}
```

**Note**: Since Python won't work in the testing environment, the Go implementation will be used immediately. The Python code remains in the codebase as reference only.

#### 9.2 Implementation and Testing Plan
**Phase 1: Core Implementation (Weeks 1-4)**
- Implement parser and core data structures
- Build EQL and Security Onion backends
- Create pipeline processing system
- Keep Python code as reference for logic

**Phase 2: Testing with Real Rules (Weeks 5-6)**
- Test against Security Onion rule sets
- Validate output format correctness
- Ensure override system works properly
- Performance benchmarking

**Phase 3: Integration Testing (Weeks 7-8)**
- Full integration with ElastAlert module
- Full integration with Playbook module
- End-to-end testing with real workflows
- Edge case handling

**Phase 4: Production Readiness (Week 9+)**
- Final optimization and cleanup
- Documentation completion
- Consider Python code removal in future release
- Performance tuning based on usage

#### 9.3 Monitoring and Metrics
```go
// Metrics to track during migration
type SigmaConverterMetrics struct {
    ConversionsTotal       int64
    ConversionErrors       int64
    FallbacksUsed         int64
    ConversionTimeMs      []float64
    MismatchCount         int64
    PythonTimeouts        int64
}

// Log format for comparison mode
type ConversionComparison struct {
    RuleID         string
    PythonOutput   string
    GoOutput       string
    Match          bool
    TimeDiffMs     float64
}
```

#### 9.4 Documentation Updates
- Update module configuration documentation
- Create migration guide for administrators
- Document new configuration options
- Provide troubleshooting guide for common issues

## Benefits

### Performance Improvements
- **Elimination of Process Overhead**: No more exec calls to Python
- **Faster Conversion**: Native Go execution vs Python interpreter
- **Better Resource Usage**: Reduced memory footprint
- **Concurrent Processing**: Native Go concurrency support

### Operational Benefits
- **Simplified Deployment**: No Python dependencies required
- **Better Error Handling**: Native Go error handling and logging
- **Improved Debugging**: Direct integration with Go debugging tools
- **Version Control**: Single codebase for all components

### Maintenance Benefits
- **Unified Codebase**: All code in Go
- **Better Testing**: Integrated unit and integration tests
- **Easier Updates**: No need to manage Python package versions
- **Consistent Code Style**: Single language conventions

## Risk Mitigation

### Compatibility Risks
- Maintain extensive test suite comparing outputs
- Implement gradual rollout with fallback options
- Keep Python implementation during transition

### Performance Risks
- Benchmark against current implementation
- Profile memory usage and CPU consumption
- Optimize critical paths identified in profiling

### Feature Parity Risks
- Implement all current pySigma features used
- Support all existing pipeline configurations
- Maintain backward compatibility

## Timeline Estimate

- **Phase 1-2** (Parser & Core): 3-4 weeks
- **Phase 3** (Backends): 2-3 weeks
- **Phase 4** (Pipelines): 2-3 weeks
- **Phase 5** (Integration): 1-2 weeks
- **Phase 6** (Testing): 2-3 weeks
- **Phase 7** (Optimization): 1-2 weeks
- **Phase 8** (Deployment): 1-2 weeks

**Total Estimated Duration**: 14-20 weeks

## Key Implementation Insights from pySigma Review

### Architecture Patterns to Adopt
1. **Modular Backend System**: pySigma uses a plugin-based backend system that allows easy extension
2. **Pipeline Processing**: Multi-stage transformation pipeline for field mappings and value transformations
3. **AST-based Parsing**: Condition parsing builds an AST for flexible evaluation and conversion
4. **Type System**: Strong typing for different Sigma value types (strings, numbers, CIDR, regex, etc.)

### Critical Components to Implement
1. **Condition Parser**: Must support complex boolean logic with operators like "1 of", "all of", "1 of them"
2. **Field References**: Support for referencing other detection items within conditions
3. **Modifier System**: Implement all standard modifiers (contains, all, endswith, etc.)
4. **Value Expansion**: Handle wildcard patterns and list expansions correctly
5. **Pipeline Transformations**: Field mapping, value transformation, and log source enrichment

### Security Onion Specific Requirements
1. **Custom Backend**: The `pysigma_backend_securityonion` wheel provides SO-specific output format
2. **Override System**: Custom filter application before conversion (already handled in current code)
3. **Output Formats**: Support both EQL (for ElastAlert) and JSON (for playbooks)
4. **Pipeline Files**: Must load and process YAML pipeline configurations

## Success Criteria

1. Native converter produces identical output to Python implementation for 95%+ of rules
2. Performance improvement of at least 50% in conversion time
3. Memory usage reduction of at least 30%
4. Zero regression in detection capabilities
5. Successful processing of all existing Security Onion rules
6. Smooth migration path with no service disruption

## Conclusion

Implementing a native Go Sigma converter will significantly improve the SecurityOnion SOC platform by eliminating external dependencies, improving performance, and simplifying deployment. The modular design allows for future extensions while maintaining compatibility with existing configurations and workflows.

The immediate switch strategy with configuration-based control allows for safe deployment while maintaining the Python code as reference during development and testing. Shared helper functions will reduce code duplication between the ElastAlert and Playbook modules.