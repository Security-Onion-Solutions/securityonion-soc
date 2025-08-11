# Sigma Rule Converter Module

This module provides a native Go implementation of Sigma rule conversion for Security Onion Console.

## Overview

The Sigma converter translates Sigma detection rules into various query languages:
- Elasticsearch Query Language (EQL)
- Security Onion format
- Elasticsearch DSL (planned)

## Architecture

### Core Components

- `converter.go` - Main converter interface and registry
- `parser.go` - Sigma rule parser and AST builder
- `types.go` - Data structures and interfaces
- `utils.go` - Centralized utility functions

### Backends

- `backends/base.go` - Base backend with common functionality
- `backends/elasticsearch.go` - EQL/DSL converter
- `backends/securityonion.go` - Security Onion specific format

### Utilities

The `utils.go` file provides centralized utilities to reduce code duplication:

#### StringUtils
- `EscapeSpecialChars()` - Escape special characters in strings
- `FormatValue()` - Format values for query output
- `EscapeWildcard()` - Escape wildcard characters

#### QueryUtils
- `BuildComparison()` - Build comparison expressions
- `BuildLikeComparison()` - Build LIKE/wildcard comparisons
- `CombineExpressions()` - Combine multiple expressions with operators
- `WrapExpression()` - Wrap expressions with parentheses when needed

#### ValidationUtils
- `IsValidField()` - Validate field names
- `IsValidLevel()` - Validate Sigma rule levels
- `IsValidStatus()` - Validate Sigma rule status
- `SanitizeField()` - Sanitize field names for queries

#### ErrorUtils
- `NewParseError()` - Create parsing errors
- `NewValidationError()` - Create validation errors
- `NewConversionError()` - Create conversion errors
- `WrapError()` - Wrap errors with context

### Global Instances

For convenience, global utility instances are available:
```go
sigma.StringUtil     // String manipulation utilities
sigma.QueryUtil      // Query building utilities
sigma.ValidationUtil // Validation utilities
sigma.ErrorUtil      // Error handling utilities
```

## Usage

### Basic Conversion

```go
import "github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"

// Parse a Sigma rule
rule, err := sigma.ParseRule(yamlContent)
if err != nil {
    return sigma.ErrorUtil.WrapError(err, "failed to parse rule")
}

// Get a converter
converter := sigma.GetConverter("eql")

// Convert to EQL
query, err := converter.Convert(rule, pipelines)
```

### Using Utilities

```go
// Escape special characters
escaped := sigma.StringUtil.EscapeSpecialChars(input)

// Build a comparison
expr, err := sigma.QueryUtil.BuildComparison(field, values, "==")

// Validate a field name
if sigma.ValidationUtil.IsValidField(fieldName) {
    // Process field
}

// Create an error with context
err := sigma.ErrorUtil.NewConversionError("eql", "invalid condition", err)
```

## Testing

Run tests with:
```bash
go test ./server/modules/sigma/...
```

Run benchmarks:
```bash
go test ./server/modules/sigma -bench=. -benchmem
```

## Performance

The native Go implementation provides:
- ~35μs end-to-end conversion time
- 50-100x faster than Python subprocess calls
- Minimal memory allocation
- Concurrent processing support

## Contributing

When adding new features:
1. Use existing utilities from `utils.go` instead of duplicating code
2. Add comprehensive tests
3. Ensure benchmarks don't regress
4. Follow existing patterns for error handling