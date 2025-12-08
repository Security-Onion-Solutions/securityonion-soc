// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

var (
	ErrSyncFailed    = errors.New("failed to sync community rules")
	ErrSyncBlocked   = errors.New("sync blocked by block file")
	ErrModuleStopped = errors.New("module stopped")
)

type DetailedDetectionEngine interface {
	ResumeIntegrityChecker()
	PauseIntegrityChecker()
	Sync(*log.Entry, bool) error
	IOManager
}

//go:generate mockgen -destination mock/mock_detaileddetectionengine.go -package mock . DetailedDetectionEngine

type SyncSchedulerParams struct {
	SyncThread                           *sync.WaitGroup
	InterruptChan                        chan bool
	StateFilePath                        string
	SyncBlockFilePath                    string
	CommunityRulesImportFrequencySeconds int
	CommunityRulesImportErrorSeconds     int
	FirstImportDelaySeconds              int
}

func SyncScheduler(ctx context.Context, detStore TemplateChecker, e DetailedDetectionEngine, syncParams *SyncSchedulerParams, engineState *model.EngineState, engName model.EngineName, isRunning *bool) {
	syncParams.SyncThread.Add(1)
	defer func() {
		syncParams.SyncThread.Done()
		*isRunning = false
	}()

	var lastSyncSuccess *bool
	lastImport, timerDur := DetermineWaitTime(e, syncParams.StateFilePath, time.Duration(syncParams.CommunityRulesImportFrequencySeconds)*time.Second, time.Duration(syncParams.FirstImportDelaySeconds)*time.Second)

	for *isRunning {
		if lastImport == nil && lastSyncSuccess != nil && *lastSyncSuccess {
			lastImport = util.Ptr(uint64(time.Now().UnixMilli()))
		}

		// Check block status and update engine state
		blocked := IsSyncBlocked(e, syncParams.SyncBlockFilePath)
		engineState.Blocked = blocked

		engineState.Syncing = false
		engineState.Importing = lastImport == nil
		engineState.Migrating = false
		engineState.SyncFailure = lastSyncSuccess != nil && !*lastSyncSuccess

		forceSync := false

		if lastSyncSuccess != nil {
			if *lastSyncSuccess {
				timerDur = time.Second * time.Duration(syncParams.CommunityRulesImportFrequencySeconds)
			} else {
				timerDur = time.Second * time.Duration(syncParams.CommunityRulesImportErrorSeconds)
				forceSync = true
			}
		}

		timer := time.NewTimer(timerDur)

		lastSyncStatus := "nil"
		if lastSyncSuccess != nil {
			lastSyncStatus = strconv.FormatBool(*lastSyncSuccess)
		}

		log.WithFields(log.Fields{
			"detectionEngine":   engName,
			"waitTimeSeconds":   timerDur.Seconds(),
			"forceSync":         forceSync,
			"lastSyncSuccess":   lastSyncStatus,
			"expectedStartTime": time.Now().Add(timerDur).Format(time.RFC3339),
		}).Info("waiting for next community rules sync")

		// Only resume integrity checker if sync isn't blocked
		// (no point checking integrity when rules haven't been synced)
		if !blocked {
			e.ResumeIntegrityChecker()
		}

		select {
		case <-timer.C:
		case typ := <-syncParams.InterruptChan:
			forceSync = forceSync || typ
		}

		haveTemplate := CheckTemplate(ctx, detStore)
		if !haveTemplate {
			lastSyncSuccess = util.Ptr(false)
			log.WithField("detectionEngine", engName).Error("no template found, failing sync")

			continue
		}

		// Re-check block status after wait (may have changed while waiting)
		blocked = IsSyncBlocked(e, syncParams.SyncBlockFilePath)
		engineState.Blocked = blocked

		if blocked {
			log.WithFields(log.Fields{
				"detectionEngine": engName,
				"blockFilePath":   syncParams.SyncBlockFilePath,
			}).Info("sync blocked by block file")

			// Use error interval so we check again soon for unblock
			lastSyncSuccess = util.Ptr(false)
			continue
		}

		e.PauseIntegrityChecker()

		if !*isRunning {
			break
		}

		if lastImport == nil {
			forceSync = true
		}

		lastSyncSuccess = util.Ptr(false)

		syncId := uuid.New().String()
		logger := log.WithFields(log.Fields{
			"detectionEngine": engName,
			"syncId":          syncId,
		})

		startTime := time.Now()
		logger.WithField("forceSync", forceSync).Info("starting sync")

		err := e.Sync(logger, forceSync)

		logger.WithField("syncDuration", time.Since(startTime).Seconds()).WithError(err).Info("sync completed")

		if err != nil {
			if strings.Contains(err.Error(), "module stopped") {
				logger.Info("module stopped, exiting sync scheduler loop")
				return
			}
			logger.WithError(err).Error("failed to sync community rules")
		} else {
			logger.Info("sync successful")
			*lastSyncSuccess = true
		}
	}
}

// IsSyncBlocked checks if the sync block file exists and returns block status
func IsSyncBlocked(iom IOManager, blockFilePath string) bool {
	if blockFilePath == "" {
		return false
	}

	_, err := iom.ReadFile(blockFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		// Error reading - block to be safe
		log.WithError(err).WithField("blockFilePath", blockFilePath).
			Warn("error reading sync block file, blocking operation")
		return true
	}

	// File exists - sync is blocked
	return true
}
