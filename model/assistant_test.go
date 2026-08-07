// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
)

func TestMemoryOperationsValidate(t *testing.T) {
	t.Parallel()

	neighbors := []MemoryNeighbor{
		{Id: "n1"},
		{Id: "n2"},
	}

	tests := []struct {
		Name        string
		Ops         []*MemoryOp
		Neighbors   []MemoryNeighbor
		ExpectedErr string
	}{
		{
			Name:      "empty operations",
			Ops:       []*MemoryOp{},
			Neighbors: neighbors,
		},
		{
			Name:      "nil operations",
			Ops:       nil,
			Neighbors: neighbors,
		},
		{
			Name:      "single ADD",
			Ops:       []*MemoryOp{{Op: "ADD"}},
			Neighbors: neighbors,
		},
		{
			Name: "ADD with no neighbors",
			Ops:  []*MemoryOp{{Op: "ADD"}},
		},
		{
			Name:      "lowercase op accepted",
			Ops:       []*MemoryOp{{Op: "add"}},
			Neighbors: neighbors,
		},
		{
			Name:      "mixed-case UPDATE with existing TargetId",
			Ops:       []*MemoryOp{{Op: "Update", TargetId: util.Ptr("n1")}},
			Neighbors: neighbors,
		},
		{
			Name:      "single NOOP",
			Ops:       []*MemoryOp{{Op: "NOOP"}},
			Neighbors: neighbors,
		},
		{
			Name:      "single DELETE with existing TargetId",
			Ops:       []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("n2")}},
			Neighbors: neighbors,
		},
		{
			Name: "multiple DELETEs plus one UPDATE",
			Ops: []*MemoryOp{
				{Op: "DELETE", TargetId: util.Ptr("n1")},
				{Op: "DELETE", TargetId: util.Ptr("n2")},
				{Op: "UPDATE", TargetId: util.Ptr("n1")},
			},
			Neighbors: neighbors,
		},
		{
			Name: "ADD plus DELETEs allowed",
			Ops: []*MemoryOp{
				{Op: "ADD"},
				{Op: "DELETE", TargetId: util.Ptr("n1")},
				{Op: "DELETE", TargetId: util.Ptr("n2")},
			},
			Neighbors: neighbors,
		},
		{
			Name:        "invalid op reported upper-cased",
			Ops:         []*MemoryOp{{Op: "merge"}},
			Neighbors:   neighbors,
			ExpectedErr: "invalid op: MERGE",
		},
		{
			Name:        "ADD with TargetId",
			Ops:         []*MemoryOp{{Op: "ADD", TargetId: util.Ptr("n1")}},
			Neighbors:   neighbors,
			ExpectedErr: "ADD with TargetId",
		},
		{
			Name:        "UPDATE without TargetId",
			Ops:         []*MemoryOp{{Op: "UPDATE"}},
			Neighbors:   neighbors,
			ExpectedErr: "UPDATE without TargetId",
		},
		{
			Name:        "UPDATE with unknown TargetId",
			Ops:         []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("missing")}},
			Neighbors:   neighbors,
			ExpectedErr: "UPDATE with non-existing TargetId",
		},
		{
			Name:        "UPDATE with no neighbors",
			Ops:         []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("n1")}},
			ExpectedErr: "UPDATE with non-existing TargetId",
		},
		{
			Name:        "DELETE without TargetId",
			Ops:         []*MemoryOp{{Op: "DELETE"}},
			Neighbors:   neighbors,
			ExpectedErr: "DELETE without TargetId",
		},
		{
			Name:        "DELETE with unknown TargetId",
			Ops:         []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("missing")}},
			Neighbors:   neighbors,
			ExpectedErr: "DELETE with non-existing TargetId",
		},
		{
			Name:        "DELETE with no neighbors",
			Ops:         []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("n1")}},
			ExpectedErr: "DELETE with non-existing TargetId",
		},
		{
			Name:        "ADD and UPDATE",
			Ops:         []*MemoryOp{{Op: "ADD"}, {Op: "UPDATE", TargetId: util.Ptr("n1")}},
			Neighbors:   neighbors,
			ExpectedErr: "expected at most 1 ADD, UPDATE, and/or NOOP operation, got ADD: 1, UPDATE: 1, NOOP: 0",
		},
		{
			Name:        "ADD and NOOP",
			Ops:         []*MemoryOp{{Op: "ADD"}, {Op: "NOOP"}},
			Neighbors:   neighbors,
			ExpectedErr: "expected at most 1 ADD, UPDATE, and/or NOOP operation, got ADD: 1, UPDATE: 0, NOOP: 1",
		},
		{
			Name:        "two NOOPs",
			Ops:         []*MemoryOp{{Op: "NOOP"}, {Op: "NOOP"}},
			Neighbors:   neighbors,
			ExpectedErr: "expected at most 1 ADD, UPDATE, and/or NOOP operation, got ADD: 0, UPDATE: 0, NOOP: 2",
		},
		{
			Name:        "UPDATE and NOOP",
			Ops:         []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("n1")}, {Op: "NOOP"}},
			Neighbors:   neighbors,
			ExpectedErr: "expected at most 1 ADD, UPDATE, and/or NOOP operation, got ADD: 0, UPDATE: 1, NOOP: 1",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			memOps := &MemoryOperations{Operations: test.Ops}

			err := memOps.Validate(test.Neighbors)

			if test.ExpectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.ExpectedErr)
			}
		})
	}
}
