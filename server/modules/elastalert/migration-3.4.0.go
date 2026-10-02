// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"github.com/apex/log"
)

// Migration340 stores the rule type on Sigma detections saved before it existed.
func (e *ElastAlertEngine) Migration340(statePath string) error {
	shouldMigrate, err := detections.ReadMigrationState(e.IOManager, statePath)
	if err != nil {
		return err
	}

	if !shouldMigrate {
		log.Info("state file indicates that the migration to 3.4.0 has already been performed")
		return nil
	}

	log.Info("elastalert is now migrating to 3.4.0") // for support

	untyped, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameElastAlert), model.WithoutRuleType())
	if err != nil {
		return err
	}

	// derived from the rule's own content, not a user change, so no history entry
	ctx := modcontext.WriteSkipAudit(e.srv.Context, true)

	migrated := 0
	skipped := 0

	for _, det := range untyped {
		err = e.ExtractDetails(det)
		if err != nil {
			log.WithError(err).WithField("publicId", det.PublicID).Warn("unable to read the rule type of a detection, skipping it")
			skipped++

			continue
		}

		// read-only fields, which the store rejects on update
		det.Kind = ""
		det.Operation = ""

		_, err = e.srv.Detectionstore.UpdateDetection(ctx, det)
		if err != nil {
			return err
		}

		migrated++
	}

	err = detections.MarkMigrationDone(e.IOManager, statePath)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"migratedCount": migrated,
		"skippedCount":  skipped,
	}).Info("elastalert has successfully migrated to 3.4.0") // for support

	return nil
}
