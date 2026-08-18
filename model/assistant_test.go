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

func TestApplyChatOptsWithMemories(t *testing.T) {
	t.Parallel()

	assert.True(t, ApplyChatOpts(WithMemories()).IncludeMemories)
	assert.False(t, ApplyChatOpts().IncludeMemories)
}

func TestMemoryOperationsRemoveInvalid(t *testing.T) {
	t.Parallel()

	neighbors := []MemoryNeighbor{
		{Id: "n1"},
		{Id: "n2"},
		{Id: "n3", UserDefined: true},
	}

	tests := []struct {
		Name      string
		Ops       []*MemoryOp
		Neighbors []MemoryNeighbor
		Kept      []int // indices into Ops that survive
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
			Kept:      []int{0},
		},
		{
			Name: "ADD with no neighbors",
			Ops:  []*MemoryOp{{Op: "ADD"}},
			Kept: []int{0},
		},
		{
			Name:      "lowercase op accepted",
			Ops:       []*MemoryOp{{Op: "add"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "mixed-case UPDATE with existing TargetId",
			Ops:       []*MemoryOp{{Op: "Update", TargetId: util.Ptr("n1")}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "single NOOP",
			Ops:       []*MemoryOp{{Op: "NOOP"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "single DELETE with existing TargetId",
			Ops:       []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("n2")}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name: "second operation on the same TargetId removed",
			Ops: []*MemoryOp{
				{Op: "DELETE", TargetId: util.Ptr("n1")},
				{Op: "DELETE", TargetId: util.Ptr("n2")},
				{Op: "UPDATE", TargetId: util.Ptr("n1")},
			},
			Neighbors: neighbors,
			Kept:      []int{0, 1},
		},
		{
			Name: "ADD plus DELETEs allowed",
			Ops: []*MemoryOp{
				{Op: "ADD"},
				{Op: "DELETE", TargetId: util.Ptr("n1")},
				{Op: "DELETE", TargetId: util.Ptr("n2")},
			},
			Neighbors: neighbors,
			Kept:      []int{0, 1, 2},
		},
		{
			Name:      "invalid op removed",
			Ops:       []*MemoryOp{{Op: "merge"}},
			Neighbors: neighbors,
		},
		{
			Name:      "invalid op removed, valid op kept",
			Ops:       []*MemoryOp{{Op: "merge"}, {Op: "ADD"}},
			Neighbors: neighbors,
			Kept:      []int{1},
		},
		{
			Name:      "ADD with TargetId removed",
			Ops:       []*MemoryOp{{Op: "ADD", TargetId: util.Ptr("n1")}},
			Neighbors: neighbors,
		},
		{
			Name:      "ADD with TargetId removed, later DELETE kept",
			Ops:       []*MemoryOp{{Op: "ADD", TargetId: util.Ptr("n1")}, {Op: "DELETE", TargetId: util.Ptr("n1")}},
			Neighbors: neighbors,
			Kept:      []int{1},
		},
		{
			Name:      "UPDATE without TargetId removed",
			Ops:       []*MemoryOp{{Op: "UPDATE"}},
			Neighbors: neighbors,
		},
		{
			Name:      "UPDATE with unknown TargetId removed",
			Ops:       []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("missing")}},
			Neighbors: neighbors,
		},
		{
			Name: "UPDATE with no neighbors removed",
			Ops:  []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("n1")}},
		},
		{
			Name:      "UPDATE of user defined memory removed",
			Ops:       []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("n3")}},
			Neighbors: neighbors,
		},
		{
			Name:      "DELETE without TargetId removed",
			Ops:       []*MemoryOp{{Op: "DELETE"}},
			Neighbors: neighbors,
		},
		{
			Name:      "DELETE with unknown TargetId removed",
			Ops:       []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("missing")}},
			Neighbors: neighbors,
		},
		{
			Name: "DELETE with no neighbors removed",
			Ops:  []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("n1")}},
		},
		{
			Name:      "DELETE of user defined memory removed, ADD kept",
			Ops:       []*MemoryOp{{Op: "DELETE", TargetId: util.Ptr("n3")}, {Op: "ADD"}},
			Neighbors: neighbors,
			Kept:      []int{1},
		},
		{
			Name:      "ADD and UPDATE keeps first",
			Ops:       []*MemoryOp{{Op: "ADD"}, {Op: "UPDATE", TargetId: util.Ptr("n1")}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "NOOP and ADD keeps first",
			Ops:       []*MemoryOp{{Op: "NOOP"}, {Op: "ADD"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "UPDATE and ADD keeps first",
			Ops:       []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("n1")}, {Op: "ADD"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "ADD and NOOP keeps first",
			Ops:       []*MemoryOp{{Op: "ADD"}, {Op: "NOOP"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "two NOOPs keeps first",
			Ops:       []*MemoryOp{{Op: "NOOP"}, {Op: "NOOP"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
		{
			Name:      "UPDATE and NOOP keeps first",
			Ops:       []*MemoryOp{{Op: "UPDATE", TargetId: util.Ptr("n1")}, {Op: "NOOP"}},
			Neighbors: neighbors,
			Kept:      []int{0},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			memOps := &MemoryOperations{Operations: test.Ops}

			memOps.RemoveInvalid(test.Neighbors)

			expected := make([]*MemoryOp, 0, len(test.Kept))
			for _, i := range test.Kept {
				expected = append(expected, test.Ops[i])
			}

			assert.Equal(t, expected, memOps.Operations)
		})
	}
}
