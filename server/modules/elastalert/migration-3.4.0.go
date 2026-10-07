// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
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

	ctx := e.srv.Context

	untyped, err := e.srv.Detectionstore.GetAllDetections(ctx, model.WithEngine(model.EngineNameElastAlert), model.WithoutRuleType())
	if err != nil {
		return err
	}

	bulk, err := e.srv.Detectionstore.BuildBulkIndexer(ctx, log.WithField("migrationVersion", "3.4.0"))
	if err != nil {
		return err
	}

	var failedMut sync.Mutex
	failed := map[string]error{}

	migrated := 0
	skipped := 0

	for _, det := range untyped {
		err = e.ExtractDetails(det)
		if err != nil {
			log.WithError(err).WithField("publicId", det.PublicID).Warn("unable to read the rule type of a detection, skipping it")
			skipped++

			continue
		}

		// only the new fields, so changes made while this runs are kept
		fields := map[string]any{"ruleType": det.RuleType}
		if det.CorrelationType != "" {
			fields["correlationType"] = det.CorrelationType
			fields["correlationTimespan"] = det.CorrelationTimespan
		}

		doc, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", fields, &det.Auditable, true, nil, nil)
		if err != nil {
			return err
		}

		err = bulk.Add(ctx, esutil.BulkIndexerItem{
			Index:      index,
			Action:     "update",
			DocumentID: det.Id,
			Body:       bytes.NewReader(doc),
			OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
				failedMut.Lock()
				defer failedMut.Unlock()

				if err == nil {
					err = errors.New(resp.Error.Reason)
				}

				failed[det.PublicID] = err
			},
		})
		if err != nil {
			return err
		}

		migrated++
	}

	err = bulk.Close(ctx)
	if err != nil {
		return err
	}

	if len(failed) > 0 {
		// not marked done, so the next start retries
		log.WithFields(log.Fields{
			"migration340FailedCount": len(failed),
			"migration340Failed":      util.TruncateMap(failed, 5),
		}).Warn("unable to store the rule type of some detections; the migration to 3.4.0 will retry on the next start")

		return nil
	}

	err = detections.MarkMigrationDone(e.IOManager, statePath)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"migration340MigratedCount": migrated,
		"migration340SkippedCount":  skipped,
	}).Info("elastalert has successfully migrated to 3.4.0") // for support

	return nil
}
