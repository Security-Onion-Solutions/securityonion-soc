// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"context"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/model"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
)

const (
	RULESET_CUSTOM           = "__custom__"
	MAX_OVERRIDE_NOTE_LENGTH = 150
)

type Detectionstore interface {
	GetDetection(ctx context.Context, detectId string) (*model.Detection, error)
	UpdateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error)
}

func UpdateOverrideNote(ctx context.Context, store Detectionstore, detectId string, overrideIndex int, note string) (valid bool, err error) {
	if len(note) > MAX_OVERRIDE_NOTE_LENGTH {
		return false, fmt.Errorf("note exceeds maximum length: %d", MAX_OVERRIDE_NOTE_LENGTH)
	}

	det, err := store.GetDetection(ctx, detectId)
	if err != nil {
		return true, err
	}

	if overrideIndex >= len(det.Overrides) {
		return false, fmt.Errorf("override index out of range, this detection has %d override(s) and you are trying to update override %d", len(det.Overrides), overrideIndex)
	}

	det.Overrides[overrideIndex].Note = note
	det.Kind = ""

	skipCtx := modcontext.WriteSkipAudit(ctx, true)

	_, err = store.UpdateDetection(skipCtx, det)

	return true, err
}
