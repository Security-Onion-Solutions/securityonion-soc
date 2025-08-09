# Native Go Sigma Converter Implementation Plan

## Executive Summary

This document outlines a comprehensive plan to implement a native Go-based Sigma converter for SecurityOnion SOC, eliminating the dependency on external Python (pySigma) calls. The converter will be integrated directly into the backend, improving performance, reliability, and deployment simplicity.

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

## Implementation Plan

### Phase 1: Core Architecture Design

#### 1.1 Package Structure
```
server/modules/sigma/
├── converter.go           # Main converter interface and factory
├── parser.go             # Sigma rule parser
├── ast.go                # Abstract syntax tree structures
├── backends/
│   ├── base.go          # Base backend interface
│   ├── elasticsearch.go # Elasticsearch/EQL backend
│   └── securityonion.go # Security Onion specific backend
├── pipelines/
│   ├── pipeline.go      # Pipeline processor interface
│   ├── loader.go        # Pipeline configuration loader
│   └── transformers/    # Individual transformation implementations
├── conditions/
│   ├── parser.go        # Condition parser
│   ├── evaluator.go     # Condition evaluation logic
│   └── operators.go     # Operator implementations
├── modifiers/
│   ├── base.go          # Modifier interface
│   └── implementations.go # Built-in modifiers (contains, all, etc.)
└── types/
    ├── values.go        # Sigma value types
    └── fields.go        # Field mapping structures
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

### Phase 5: Integration

#### 5.1 ElastAlert Module Integration
```go
// Replace existing sigmaToElastAlert function
func (e *ElastAlertEngine) sigmaToElastAlert(ctx context.Context, det *model.Detection) (string, error) {
    // Parse Sigma rule
    rule, err := sigma.ParseRule([]byte(det.Content))
    if err != nil {
        return "", fmt.Errorf("failed to parse sigma rule: %w", err)
    }
    
    // Apply overrides
    if len(det.Overrides) > 0 {
        rule = applyOverrides(rule, det.Overrides)
    }
    
    // Load pipelines
    pipelines, err := sigma.LoadPipelines(e.sigmaPipelineFiles)
    if err != nil {
        return "", fmt.Errorf("failed to load pipelines: %w", err)
    }
    
    // Convert to EQL
    converter := sigma.NewEQLConverter()
    query, err := converter.Convert(rule, pipelines)
    if err != nil {
        return "", fmt.Errorf("failed to convert rule: %w", err)
    }
    
    return query, nil
}
```

#### 5.2 Playbook Module Integration
- Update ConvertQuestions to use native converter
- Maintain backward compatibility with existing format
- Handle batch conversions efficiently

#### 5.3 Configuration Migration
- Convert existing pipeline YAML files to Go structures
- Maintain compatibility with existing configurations
- Provide migration utilities if needed

### Phase 6: Testing Strategy

#### 6.1 Unit Tests
- Parser tests for all Sigma rule components
- Converter tests for each backend
- Pipeline transformation tests
- Edge case and error handling tests

#### 6.2 Integration Tests
- End-to-end conversion tests
- Comparison with Python sigma CLI output
- Performance benchmarks
- Memory usage profiling

#### 6.3 Compatibility Tests
- Test against official Sigma rule repository
- Verify output matches existing Python implementation
- Test with Security Onion specific rules
- Validate custom override functionality

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

### Phase 8: Deployment and Migration

#### 8.1 Gradual Rollout
- Implement feature flag for native converter
- Support fallback to Python implementation
- Provide comparison mode for validation

#### 8.2 Migration Process
1. Deploy with feature flag disabled
2. Enable for testing/staging environments
3. Run in comparison mode to validate output
4. Gradually enable for production
5. Remove Python dependency after validation

#### 8.3 Documentation
- API documentation for converter interfaces
- Pipeline configuration documentation
- Migration guide for existing installations
- Performance tuning guidelines

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

## Success Criteria

1. Native converter produces identical output to Python implementation for 95%+ of rules
2. Performance improvement of at least 50% in conversion time
3. Memory usage reduction of at least 30%
4. Zero regression in detection capabilities
5. Successful processing of all existing Security Onion rules
6. Smooth migration path with no service disruption

## Conclusion

Implementing a native Go Sigma converter will significantly improve the SecurityOnion SOC platform by eliminating external dependencies, improving performance, and simplifying deployment. The modular design allows for future extensions while maintaining compatibility with existing configurations and workflows.