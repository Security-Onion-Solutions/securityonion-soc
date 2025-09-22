// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package context

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteSkipAudit(t *testing.T) {
	ctx := context.Background()
	
	newCtx := WriteSkipAudit(ctx, true)
	assert.NotNil(t, newCtx)
	assert.NotEqual(t, ctx, newCtx)
	
	newCtx = WriteSkipAudit(ctx, false)
	assert.NotNil(t, newCtx)
	assert.NotEqual(t, ctx, newCtx)
}

func TestReadSkipAudit(t *testing.T) {
	ctx := context.Background()
	
	// Test with no value set
	result := ReadSkipAudit(ctx)
	assert.False(t, result)
	
	// Test with true value
	ctx = WriteSkipAudit(ctx, true)
	result = ReadSkipAudit(ctx)
	assert.True(t, result)
	
	// Test with false value
	ctx = WriteSkipAudit(ctx, false)
	result = ReadSkipAudit(ctx)
	assert.False(t, result)
}

func TestWriteOverrideOperation(t *testing.T) {
	ctx := context.Background()
	
	newCtx := WriteOverrideOperation(ctx, "test-operation")
	assert.NotNil(t, newCtx)
	assert.NotEqual(t, ctx, newCtx)
	
	newCtx = WriteOverrideOperation(ctx, "")
	assert.NotNil(t, newCtx)
	assert.NotEqual(t, ctx, newCtx)
}

func TestReadOverrideOperation(t *testing.T) {
	ctx := context.Background()
	
	// Test with no value set
	result := ReadOverrideOperation(ctx)
	assert.Nil(t, result)
	
	// Test with string value
	operation := "test-operation"
	ctx = WriteOverrideOperation(ctx, operation)
	result = ReadOverrideOperation(ctx)
	assert.NotNil(t, result)
	assert.Equal(t, operation, *result)
	
	// Test with empty string
	ctx = WriteOverrideOperation(ctx, "")
	result = ReadOverrideOperation(ctx)
	assert.NotNil(t, result)
	assert.Equal(t, "", *result)
}

func TestWriteIsAssistant(t *testing.T) {
	ctx := context.Background()
	
	newCtx := WriteIsAssistant(ctx, true)
	assert.NotNil(t, newCtx)
	assert.NotEqual(t, ctx, newCtx)
	
	newCtx = WriteIsAssistant(ctx, false)
	assert.NotNil(t, newCtx)
	assert.NotEqual(t, ctx, newCtx)
}

func TestReadIsAssistant(t *testing.T) {
	ctx := context.Background()
	
	// Test with no value set
	result := ReadIsAssistant(ctx)
	assert.False(t, result)
	
	// Test with true value
	ctx = WriteIsAssistant(ctx, true)
	result = ReadIsAssistant(ctx)
	assert.True(t, result)
	
	// Test with false value
	ctx = WriteIsAssistant(ctx, false)
	result = ReadIsAssistant(ctx)
	assert.False(t, result)
}

func TestContextChaining(t *testing.T) {
	ctx := context.Background()
	
	// Test chaining multiple context operations
	ctx = WriteSkipAudit(ctx, true)
	ctx = WriteOverrideOperation(ctx, "chained-operation")
	ctx = WriteIsAssistant(ctx, true)
	
	assert.True(t, ReadSkipAudit(ctx))
	
	operation := ReadOverrideOperation(ctx)
	assert.NotNil(t, operation)
	assert.Equal(t, "chained-operation", *operation)
	
	assert.True(t, ReadIsAssistant(ctx))
}

func TestContextOverwrite(t *testing.T) {
	ctx := context.Background()
	
	// Test overwriting values
	ctx = WriteSkipAudit(ctx, true)
	assert.True(t, ReadSkipAudit(ctx))
	
	ctx = WriteSkipAudit(ctx, false)
	assert.False(t, ReadSkipAudit(ctx))
	
	ctx = WriteOverrideOperation(ctx, "first-operation")
	operation := ReadOverrideOperation(ctx)
	assert.NotNil(t, operation)
	assert.Equal(t, "first-operation", *operation)
	
	ctx = WriteOverrideOperation(ctx, "second-operation")
	operation = ReadOverrideOperation(ctx)
	assert.NotNil(t, operation)
	assert.Equal(t, "second-operation", *operation)
}
