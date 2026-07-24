// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"golang.org/x/mod/semver"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/samber/lo"
)

// Constants and package variables

var sidExtracter = regexp.MustCompile(`(?i)\bsid: ?['"]?(.*?)['"]?;`)
var categoryExtractor = regexp.MustCompile(`^(\w+)\s+(\w+)`)

var licenseBySource = map[string]string{
	"etopen": model.LicenseBSD,
	"etpro":  model.LicenseCommercial,
}

const (
	DEFAULT_ALL_RULES_FILE                        = "/opt/sensoroni/suricata/rules/all-rulesets.rules"
	DEFAULT_THRESHOLD_FILE                        = "/opt/sensoroni/suricata/threshold/threshold.conf"
	DEFAULT_CONFIG_FINGERPRINT_FILE               = "/opt/sensoroni/fingerprints/suricata-config.fingerprint"
	DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECS = 86400
	DEFAULT_STATE_FILE_PATH                       = "/opt/sensoroni/fingerprints/suricataengine.state"
	DEFAULT_SYNC_BLOCK_FILE_PATH                  = "/opt/sensoroni/fingerprints/suricataengine.syncBlock"
	DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS     = 300
	DEFAULT_FIRST_IMPORT_DELAY_SECONDS            = 60
	DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS     = 600
	DEFAULT_CONFIG_CHANGE_SYNC_DELAY_SECONDS      = 15
	DEFAULT_AI_REPO                               = "https://github.com/Security-Onion-Solutions/securityonion-resources"
	DEFAULT_AI_REPO_BRANCH                        = "generated-summaries-published"
	DEFAULT_AI_REPO_PATH                          = "/opt/sensoroni/ai_summary_repos"
	DEFAULT_SHOW_AI_SUMMARIES                     = true
	DEFAULT_AUTO_UPDATE_ENABLED                   = false
	DEFAULT_MIGRATIONS_DIR                        = "/opt/so/conf/soc/migrations/"
	DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT    = 10
)

var ( // treat as constants
	DEFAULT_ENABLE_REGEX  = []string{}
	DEFAULT_DISABLE_REGEX = []string{}
)

var (
	// pcrePattern matches pcre:"..." sections to exclude from backref checking
	pcrePattern = regexp.MustCompile(`pcre:"[^"]*"`)
	// backrefPattern matches Python-style backreferences \1 through \9
	backrefPattern = regexp.MustCompile(`\\[1-9]`)
)

// Types

// DuplicateInfo tracks duplicate SID information
type DuplicateInfo struct {
	KeptRuleset    string
	SkippedRuleset string
}

// MergeResult holds the results of merging rulesets
type MergeResult struct {
	Detections []*model.Detection
	Duplicates map[string]DuplicateInfo
	Stats      map[string]int // ruleset -> accepted count
}

// StateStats tracks user state application statistics
type StateStats struct {
	ExistingRules      int
	NewRules           int
	UserModified       int
	PreservedUserPrefs int
}

// RulesetStats tracks per-ruleset sync statistics
type RulesetStats struct {
	Added     int
	Updated   int
	Unchanged int
	Deleted   int
}

// nidsLogger wraps log.Entry to automatically prefix fields with "nids."
type nidsLogger struct {
	*log.Entry
}

// WithField adds "nids." prefix appropriately
func (l *nidsLogger) WithField(key string, value interface{}) *nidsLogger {
	return l.WithFields(log.Fields{key: value})
}

// WithFields adds "nids." prefix to Suricata-specific fields
func (l *nidsLogger) WithFields(fields log.Fields) *nidsLogger {
	prefixed := make(log.Fields)
	for k, v := range fields {
		// Keep existing prefixed fields and special fields as-is
		if strings.Contains(k, ".") ||
			k == "detectionEngine" ||
			k == "error" ||
			k == "component" ||
			k == "operation" ||
			k == "migrationVersion" {
			prefixed[k] = v
		} else {
			// Add nids. prefix to Suricata-specific fields
			prefixed["nids."+k] = v
		}
	}
	return &nidsLogger{l.Entry.WithFields(prefixed)}
}

// WithError passes through without prefix
func (l *nidsLogger) WithError(err error) *nidsLogger {
	return &nidsLogger{l.Entry.WithError(err)}
}

// Constructors

type SuricataEngine struct {
	srv                            *server.Server
	allRulesFile                   string
	thresholdFile                  string
	configFingerprintFile          string
	failAfterConsecutiveErrorCount int
	configChangeSyncDelaySeconds   int
	isRunning                      bool
	interm                         sync.Mutex
	notify                         bool
	migrations                     map[string]func(string) error
	rulesetSources                 []*RulesetSource
	writeNoRead                    *string
	checkMigrationsOnce            func()
	rulesetManager                 *RulesetManager
	enableRegex                    []*regexp.Regexp
	disableRegex                   []*regexp.Regexp
	aiSummaries                    *sync.Map // map[string]*detections.AiSummary{}
	aiSummaryCount                 int
	showAiSummaries                bool
	aiRepoUrl                      string
	aiRepoBranch                   string
	aiRepoPath                     string
	autoUpdateEnabled              bool
	flowbitResolver                *FlowbitResolver
	flowbitRequired                map[string]*FlowbitDependency
	detections.SyncSchedulerParams
	detections.IntegrityCheckerData
	detections.IOManager
	model.EngineState
}

func NewSuricataEngine(srv *server.Server) *SuricataEngine {
	e := &SuricataEngine{
		srv:       srv,
		IOManager: &detections.ResourceManager{Config: srv.Config},
	}

	e.checkMigrationsOnce = sync.OnceFunc(e.checkForMigrations)

	e.migrations = map[string]func(string) error{
		"2.4.70": e.Migration2470,
	}

	return e
}

// Module interface implementation

func (e *SuricataEngine) PrerequisiteModules() []string {
	return nil
}

// logger returns a nidsLogger with the detectionEngine field set
func (e *SuricataEngine) logger() *nidsLogger {
	return &nidsLogger{log.WithField("detectionEngine", model.EngineNameSuricata)}
}

func (e *SuricataEngine) GetState() *model.EngineState {
	return &e.EngineState
}

func (e *SuricataEngine) Init(config module.ModuleConfig) (err error) {
	e.SyncThread = &sync.WaitGroup{}
	e.InterruptChan = make(chan bool, 1)
	e.IntegrityCheckerData.Thread = &sync.WaitGroup{}
	e.IntegrityCheckerData.Interrupt = make(chan bool, 1)
	e.aiSummaries = &sync.Map{}
	e.flowbitResolver = NewFlowbitResolver(e.logger())
	e.flowbitRequired = make(map[string]*FlowbitDependency)

	e.allRulesFile = module.GetStringDefault(config, "allRulesFile", DEFAULT_ALL_RULES_FILE)
	e.thresholdFile = module.GetStringDefault(config, "thresholdFile", DEFAULT_THRESHOLD_FILE)
	e.configFingerprintFile = module.GetStringDefault(config, "configFingerprintFile", DEFAULT_CONFIG_FINGERPRINT_FILE)
	e.CommunityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECS)
	e.CommunityRulesImportErrorSeconds = module.GetIntDefault(config, "communityRulesImportErrorSeconds", DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS)
	e.FirstImportDelaySeconds = module.GetIntDefault(config, "firstImportDelaySeconds", DEFAULT_FIRST_IMPORT_DELAY_SECONDS)
	e.failAfterConsecutiveErrorCount = module.GetIntDefault(config, "failAfterConsecutiveErrorCount", DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT)
	e.IntegrityCheckerData.FrequencySeconds = module.GetIntDefault(config, "integrityCheckFrequencySeconds", DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS)
	e.configChangeSyncDelaySeconds = module.GetIntDefault(config, "configChangeSyncDelaySeconds", DEFAULT_CONFIG_CHANGE_SYNC_DELAY_SECONDS)
	e.autoUpdateEnabled = module.GetBoolDefault(config, "autoUpdateEnabled", DEFAULT_AUTO_UPDATE_ENABLED)

	enable := module.GetStringArrayDefault(config, "enableRegex", DEFAULT_ENABLE_REGEX)
	disable := module.GetStringArrayDefault(config, "disableRegex", DEFAULT_DISABLE_REGEX)

	if len(enable) != 0 {
		e.enableRegex = make([]*regexp.Regexp, 0, len(enable))
		for _, str := range enable {
			re, err := regexp.Compile(str)
			if err != nil {
				return fmt.Errorf("unable to compile Suricata's enableRegex: %s - %w", str, err)
			}

			e.enableRegex = append(e.enableRegex, re)
		}
	}

	if len(disable) != 0 {
		e.disableRegex = make([]*regexp.Regexp, 0, len(disable))
		for _, str := range disable {
			re, err := regexp.Compile(str)
			if err != nil {
				return fmt.Errorf("unable to compile Suricata's disableRegex: %s - %w", str, err)
			}

			e.disableRegex = append(e.disableRegex, re)
		}
	}

	e.StateFilePath = module.GetStringDefault(config, "stateFilePath", DEFAULT_STATE_FILE_PATH)
	e.SyncBlockFilePath = module.GetStringDefault(config, "syncBlockFilePath", DEFAULT_SYNC_BLOCK_FILE_PATH)

	e.showAiSummaries = module.GetBoolDefault(config, "showAiSummaries", DEFAULT_SHOW_AI_SUMMARIES)
	e.aiRepoUrl = module.GetStringDefault(config, "aiRepoUrl", DEFAULT_AI_REPO)
	e.aiRepoBranch = module.GetStringDefault(config, "aiRepoBranch", DEFAULT_AI_REPO_BRANCH)
	e.aiRepoPath = module.GetStringDefault(config, "aiRepoPath", DEFAULT_AI_REPO_PATH)

	e.rulesetSources, err = GetRulesetSourcesFromConfig(config, "rulesetSources", nil)
	if err != nil {
		return fmt.Errorf("unable to get ruleset sources: %w", err)
	}

	// Filter for enabled sources
	enabledSources := lo.Filter(e.rulesetSources, func(s *RulesetSource, _ int) bool {
		return s.Enabled != nil && *s.Enabled
	})

	// Initialize RulesetManager with enabled sources
	e.rulesetManager = NewRulesetManager(e.IOManager, e.logger(), enabledSources...)

	return nil
}

func (e *SuricataEngine) Start() error {
	e.srv.DetectionEngines.Store(model.EngineNameSuricata, e)
	e.isRunning = true
	e.IntegrityCheckerData.IsRunning = true

	// Check if configuration changed and schedule immediate sync if so
	configChanged, err := e.hasConfigChanged()
	if err != nil {
		e.logger().WithError(err).Warn("failed to check config changes, proceeding normally")
	}

	// start long running processes
	go detections.SyncScheduler(e.srv.Context, e.srv.Detectionstore, e, &e.SyncSchedulerParams, &e.EngineState, model.EngineNameSuricata, &e.isRunning)
	go detections.IntegrityChecker(model.EngineNameSuricata, e, &e.IntegrityCheckerData, &e.EngineState.IntegrityFailure)

	// If config changed, trigger immediate sync after startup (unless first import)
	if configChanged {
		_, hasState, _ := e.readFingerprint(e.StateFilePath)
		if hasState {
			e.logger().Info("ruleset configuration changed since last startup, scheduling immediate sync")
			go func() {
				time.Sleep(time.Duration(e.configChangeSyncDelaySeconds) * time.Second)
				e.InterruptSync(true, true)
			}()
		} else {
			e.logger().Info("ruleset configuration changed, but deferring to initial startup delay")
		}
	}

	// Write current config fingerprint for next startup
	currentFingerprint := e.generateConfigFingerprint()
	err = e.IOManager.WriteFile(e.configFingerprintFile, []byte(currentFingerprint), 0644)
	if err != nil {
		e.logger().WithError(err).Error("failed to write config fingerprint")
	} else {
		e.logger().WithField("configFingerprint", currentFingerprint).Debug("wrote config fingerprint")
	}

	// update Ai Summaries once and don't block
	if e.showAiSummaries {
		go func() {
			logger := e.logger()

			err := detections.RefreshAiSummaries(e, model.SigLangSuricata, &e.isRunning, e.aiRepoPath, e.aiRepoUrl, e.aiRepoBranch, logger.Entry, e.IOManager)
			if err != nil {
				if errors.Is(err, detections.ErrModuleStopped) {
					return
				}

				logger.WithError(err).Error("unable to refresh AI summaries")
			} else {
				logger.Info("successfully refreshed AI summaries")
			}
		}()
	}

	return nil
}

func (e *SuricataEngine) Stop() error {
	e.isRunning = false
	e.InterruptSync(false, false)
	e.SyncThread.Wait()
	e.PauseIntegrityChecker()
	e.interruptIntegrityCheck()
	e.IntegrityCheckerData.Thread.Wait()

	return nil
}

func (e *SuricataEngine) InterruptSync(fullUpgrade bool, notify bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = notify

	if len(e.InterruptChan) == 0 {
		e.InterruptChan <- fullUpgrade
	}
}

func (e *SuricataEngine) resetInterruptSync() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.InterruptChan) != 0 {
		<-e.InterruptChan
	}
}

func (e *SuricataEngine) interruptIntegrityCheck() {
	e.interm.Lock()
	defer e.interm.Unlock()

	if len(e.IntegrityCheckerData.Interrupt) == 0 {
		e.IntegrityCheckerData.Interrupt <- true
	}
}

func (e *SuricataEngine) PauseIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = false
}

func (e *SuricataEngine) ResumeIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = true
}

func checkAndExtractCategory(title string) string {
	matches := categoryExtractor.FindStringSubmatch(title)
	if len(matches) > 1 {
		firstWord := matches[1]
		secondWord := matches[2]

		// Check if the first word is one of the keywords
		switch firstWord {
		case "ET", "ETPRO", "GPL":
			return firstWord + " " + secondWord // Return both words if the first is a keyword
		}
	}

	return "" // Return empty string if no matches or keyword doesn't match
}

func (e *SuricataEngine) IsRunning() bool {
	return e.isRunning
}

// Rule file operations

// SyncLocalDetections - DEPRECATED: Use RegenerateRuleFiles instead
// This is called when a rule is changed (eg. via the UI)
func (e *SuricataEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	e.logger().
		Debug("SyncLocalDetections called - delegating to RegenerateRuleFiles")
	return e.RegenerateRuleFiles(ctx, detections)
}

// RegenerateRuleFiles regenerates all rule files from current Elasticsearch state.
func (e *SuricataEngine) RegenerateRuleFiles(ctx context.Context, changedDetections []*model.Detection) (errMap map[string]string, err error) {
	logger := e.logger().WithFields(log.Fields{
		"changedCount": len(changedDetections),
		"operation":    "regenerateRuleFiles",
	})

	// Check for sync block
	if blocked := detections.IsSyncBlocked(e.IOManager, e.SyncBlockFilePath); blocked {
		logger.WithFields(log.Fields{
			"blockFilePath": e.SyncBlockFilePath,
		}).Warn("regenerate rule files blocked by block file")

		return map[string]string{"blocked": "sync operations blocked"},
			fmt.Errorf("rule file regeneration blocked")
	}

	// Log what triggered this regeneration (if provided)
	if len(changedDetections) > 0 {
		changedSIDs := []string{}
		for i, det := range changedDetections {
			if i < 5 {
				changedSIDs = append(changedSIDs, det.PublicID)
			} else {
				changedSIDs = append(changedSIDs, "...")
				break
			}
		}
		logger.WithField("changedSIDs", changedSIDs).Info("regenerating rule files after detection changes")
	} else {
		logger.Info("regenerating rule files")
	}

	// Get ALL detections from Elasticsearch (source of truth) - needed for flowbits handling
	allDetectionsMap, err := e.getAllSuricataDetections(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to fetch detections from store")
		return map[string]string{"fetch": err.Error()}, err
	}

	// Filter out pending delete
	allDetections := make([]*model.Detection, 0, len(allDetectionsMap))
	for _, det := range allDetectionsMap {
		if !det.PendingDelete {
			allDetections = append(allDetections, det)
		}
	}

	logger.WithField("totalDetections", len(allDetections)).Debug("fetched detections")

	// Resolve flowbit dependencies
	e.flowbitRequired = e.flowbitResolver.ResolveFlowbitDependencies(allDetections)

	if len(e.flowbitRequired) > 0 {
		logger.WithField("requiredCount", len(e.flowbitRequired)).
			Debug("identified disabled rules needed for flowbit dependencies")
	}

	// Write the rules file
	if err := e.writeAllRulesFile(allDetections); err != nil {
		logger.WithError(err).Error("failed to write all.rules file")
		return map[string]string{"write_rules": err.Error()}, err
	}

	// Count enabled rules for logging
	enabledCount := 0
	for _, det := range allDetections {
		if det.IsEnabled {
			enabledCount++
		}
	}

	logger.WithFields(log.Fields{
		"enabledRules": enabledCount,
		"totalRules":   len(allDetections),
		"filePath":     e.allRulesFile,
	}).Info("wrote all.rules file")

	// Write threshold file using the same detections (for overrides)
	if err := e.writeThresholdFile(allDetections); err != nil {
		logger.WithError(err).Error("failed to write threshold file")
		return map[string]string{"write_threshold": err.Error()}, err
	}

	// Count overrides for logging
	rulesWithOverrides := 0
	suppressCount := 0
	thresholdCount := 0
	for _, det := range allDetections {
		if len(det.Overrides) > 0 {
			rulesWithOverrides++
			for _, override := range det.Overrides {
				if override.IsEnabled {
					if override.Type == model.OverrideTypeSuppress {
						suppressCount++
					} else if override.Type == model.OverrideTypeThreshold {
						thresholdCount++
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"totalDetections": len(allDetections),
		"withOverrides":   rulesWithOverrides,
		"suppressRules":   suppressCount,
		"thresholdRules":  thresholdCount,
		"filePath":        e.thresholdFile,
	}).Info("wrote threshold configuration")

	logger.WithFields(log.Fields{
		"totalRules": len(allDetections),
		"operation":  "regenerateRuleFiles",
	}).Info("successfully regenerated rule files")
	return nil, nil
}

// Rule processing

func (e *SuricataEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (e *SuricataEngine) ExtractDetails(detect *model.Detection) error {
	rule, err := ParseSuricataRule(detect.Content)
	if err != nil {
		return err
	}

	for _, opt := range rule.Options {
		if strings.EqualFold(opt.Name, "sid") && opt.Value != nil {
			detect.PublicID = *opt.Value
			continue
		}

		if strings.EqualFold(opt.Name, "msg") && opt.Value != nil {
			detect.Title = util.Unquote(*opt.Value)
			detect.Category = checkAndExtractCategory(detect.Title)

			continue
		}
	}

	if detect.PublicID == "" {
		return fmt.Errorf("rule does not contain a public Id")
	}

	if detect.Title == "" {
		detect.Title = "Detection title not yet provided - click here to update this title"
	}

	detect.Severity = model.SeverityUnknown

	formats := []string{"2006-01-02", "2006/01/02", "2006_01_02"}

	md := rule.ParseMetaData()
	for _, meta := range md {
		if strings.EqualFold(meta.Key, "signature_severity") {
			switch strings.ToLower(meta.Value) {
			case "informational":
				detect.Severity = model.SeverityInformational
			case "minor":
				detect.Severity = model.SeverityLow
			case "major":
				detect.Severity = model.SeverityHigh
			case "critical":
				detect.Severity = model.SeverityCritical
			}
		} else if strings.EqualFold(meta.Key, "created_at") {
			t, err := util.ParseDate(meta.Value, formats)
			if err == nil {
				detect.SourceCreated = &t
			} else {
				e.logger().WithField("created_at", meta.Value).WithError(err).Warn("unable to parse date")
			}
		} else if strings.EqualFold(meta.Key, "updated_at") {
			t, err := util.ParseDate(meta.Value, formats)
			if err == nil {
				detect.SourceUpdated = &t
			} else {
				e.logger().WithField("updated_at", meta.Value).WithError(err).Warn("unable to parse date")
			}
		}
	}

	return nil
}

// Core sync operations

func (e *SuricataEngine) Sync(logger *log.Entry, forceSync bool) error {
	defer func() {
		e.resetInterruptSync()
	}()

	// Check for sync block at the very start
	if blocked := detections.IsSyncBlocked(e.IOManager, e.SyncBlockFilePath); blocked {
		logger.WithFields(log.Fields{
			"blockFilePath": e.SyncBlockFilePath,
		}).Warn("sync blocked by block file")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "blocked",
			})
		}

		return fmt.Errorf("sync blocked")
	}

	// Validate ruleset configuration before starting sync
	if err := e.validateRulesetNames(); err != nil {
		return e.handleSyncError(err, "sync aborted due to configuration error", logger)
	}

	if detections.CheckWriteNoRead(e.srv.Context, e.srv.Detectionstore, e.writeNoRead) {
		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "error",
			})
		}
		return detections.ErrSyncFailed
	}

	e.writeNoRead = nil

	if !e.autoUpdateEnabled && !forceSync {
		logger.WithFields(log.Fields{
			"autoUpdateEnabled": e.autoUpdateEnabled,
			"forceSync":         forceSync,
		}).Info("skipping sync")
		return nil
	}

	// Refresh AI summaries if enabled
	if e.showAiSummaries {
		err := detections.RefreshAiSummaries(e, model.SigLangSuricata, &e.isRunning, e.aiRepoPath, e.aiRepoUrl, e.aiRepoBranch, logger, e.IOManager)
		if err != nil {
			if errors.Is(err, detections.ErrModuleStopped) {
				return err
			}
			logger.WithError(err).Error("unable to refresh AI summaries")
		} else {
			logger.Info("successfully refreshed AI summaries")
		}
	}

	logger.Info("starting detection sync")
	e.EngineState.Syncing = true

	// Build map of configured rulesets for deletion logic
	configuredRulesets := e.buildConfiguredRulesetsMap()

	// Sync all configured rulesets using RulesetManager
	rulesetResults := e.rulesetManager.SyncAll(e.srv.Context, e.srv.Detectionstore)

	// Check if ANY ruleset failed - abort entire sync if so
	for rulesetName, result := range rulesetResults {
		if !result.Success {
			e.logger().WithError(result.Error).WithField("failedRuleset", rulesetName).
				Error("aborting sync due to ruleset failure")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "error",
				})
			}
			return e.handleSyncError(result.Error, "ruleset sync failed", logger)
		}
	}

	// Merge all rulesets
	mergeResult := e.mergeRulesetResults(rulesetResults)
	e.logDuplicates(mergeResult.Duplicates)
	logger.WithField("totalDetections", len(mergeResult.Detections)).Info("merged all rulesets")

	allDetections := mergeResult.Detections

	// Apply user state from Elasticsearch (enable/disable, overrides)
	if err := e.applyUserState(e.srv.Context, allDetections); err != nil {
		return e.handleSyncError(err, "failed to apply user state", logger)
	}

	// Resolve flowbit dependencies
	// This identifies disabled rules that need to be active for flowbits
	// IMPORTANT: Does NOT modify det.IsEnabled - that preserves user intent
	e.flowbitRequired = e.flowbitResolver.ResolveFlowbitDependencies(allDetections)

	if len(e.flowbitRequired) > 0 {
		sampleSIDs := make([]string, 0, min(10, len(e.flowbitRequired)))
		for sid := range e.flowbitRequired {
			if len(sampleSIDs) >= 10 {
				break
			}
			sampleSIDs = append(sampleSIDs, sid)
		}
		logger.WithFields(log.Fields{
			"requiredCount": len(e.flowbitRequired),
			"sampleSIDs":    sampleSIDs,
		}).Info("identified disabled rules needed for flowbit dependencies")
	}

	// Write rules directly to Suricata format
	if err := e.writeAllRulesFile(allDetections); err != nil {
		return e.handleSyncError(err, "failed to write all-rulesets.rules file", logger)
	}

	// Write threshold configuration
	if err := e.writeThresholdFile(allDetections); err != nil {
		return e.handleSyncError(err, "failed to write threshold file", logger)
	}

	// Update detection store with bulk indexer
	if err := e.updateDetectionStore(e.srv.Context, allDetections, configuredRulesets, rulesetResults); err != nil {
		return e.handleSyncError(err, "failed to update detection store", logger)
	}

	// Write state file
	detections.WriteStateFile(e.IOManager, e.StateFilePath)

	// Run post-sync integrity check
	_, _, err := e.IntegrityCheck(false, logger)
	e.EngineState.IntegrityFailure = err != nil
	if err != nil {
		logger.WithError(err).Error("post-sync integrity check failed")
	} else {
		logger.Info("post-sync integrity check passed")
	}

	// Broadcast success
	if e.notify {
		e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
			Engine: model.EngineNameSuricata,
			Status: "success",
		})
	}

	// Calculate final sync summary
	enabledCount := 0
	disabledCount := 0
	overrideCount := 0
	for _, det := range allDetections {
		if det.IsEnabled {
			enabledCount++
		} else {
			disabledCount++
		}
		overrideCount += len(det.Overrides)
	}

	logger.WithFields(log.Fields{
		"totalRules":     len(allDetections),
		"enabledRules":   enabledCount,
		"disabledRules":  disabledCount,
		"totalOverrides": overrideCount,
		"operation":      "sync",
	}).Info("detection sync completed successfully")

	// Check for migrations
	e.checkMigrationsOnce()

	return nil
}

// mergeRulesetResults combines detections from multiple rulesets with duplicate handling
func (e *SuricataEngine) mergeRulesetResults(results map[string]*RulesetSyncResult) *MergeResult {
	// Process rulesets in deterministic order for consistency
	rulesets := lo.Keys(results)
	sort.Strings(rulesets)

	seen := make(map[string]string) // SID -> first ruleset that had it
	var allDetections []*model.Detection
	duplicates := make(map[string]DuplicateInfo)
	stats := make(map[string]int)

	for _, rulesetName := range rulesets {
		result := results[rulesetName]
		unique := e.partitionDetectionsBySID(result.Detections, rulesetName, seen, duplicates)

		allDetections = append(allDetections, unique...)
		stats[rulesetName] = len(unique)

		// Log processing info
		e.logger().WithFields(log.Fields{
			"ruleset":        rulesetName,
			"ruleCount":      len(unique),
			"duplicateCount": len(result.Detections) - len(unique),
		}).Info("processed ruleset")
	}

	return &MergeResult{
		Detections: allDetections,
		Duplicates: duplicates,
		Stats:      stats,
	}
}

// partitionDetectionsBySID separates unique detections from duplicates and builds duplicate info
func (e *SuricataEngine) partitionDetectionsBySID(detections []*model.Detection, rulesetName string, seen map[string]string, duplicates map[string]DuplicateInfo) []*model.Detection {
	unique := make([]*model.Detection, 0, len(detections))

	for _, det := range detections {
		if keptRuleset, exists := seen[det.PublicID]; exists {
			// Build duplicate info directly
			duplicates[det.PublicID] = DuplicateInfo{
				KeptRuleset:    keptRuleset,
				SkippedRuleset: rulesetName,
			}
		} else {
			seen[det.PublicID] = rulesetName
			unique = append(unique, det)
		}
	}

	return unique
}

// logDuplicates logs duplicate SID information in a structured way
func (e *SuricataEngine) logDuplicates(duplicates map[string]DuplicateInfo) {
	if len(duplicates) == 0 {
		return
	}

	logger := e.logger()

	// Count duplicates by skipped ruleset
	byRuleset := make(map[string]int)
	for _, info := range duplicates {
		byRuleset[info.SkippedRuleset]++
	}

	// Log summary per ruleset
	for ruleset, count := range byRuleset {
		logger.WithFields(log.Fields{
			"ruleset":        ruleset,
			"duplicateCount": count,
			"resolution":     "kept_first",
		}).Warn("ruleset contained duplicate SIDs")
	}

	// Log individual duplicates at debug level
	for sid, info := range duplicates {
		logger.WithFields(log.Fields{
			"duplicateSID":    sid,
			"skippedRuleset":  info.SkippedRuleset,
			"acceptedRuleset": info.KeptRuleset,
			"resolution":      "kept_first",
		}).Debug("duplicate SID details")
	}
}

// applyUserState applies user preferences from Elasticsearch to detections
func (e *SuricataEngine) applyUserState(ctx context.Context, dets []*model.Detection) error {
	existingDetections, err := e.getAllSuricataDetections(ctx)
	if err != nil {
		return fmt.Errorf("failed to get existing detections: %w", err)
	}

	if err := e.checkExistingDetectionsPlausible(existingDetections, dets); err != nil {
		return err
	}

	stats := &StateStats{}

	for _, det := range dets {
		if existing, exists := existingDetections[det.PublicID]; exists {
			e.applyExistingRuleState(det, existing, stats)
		} else {
			e.applyNewRuleState(det, stats)
		}
		e.ApplyFilters(det)
	}

	e.logStateApplication(stats, len(dets))
	return nil
}

// checkExistingDetectionsPlausible guards against a silently empty read of the
// detection store: a cross-cluster search with an unavailable remote returns
// zero hits and no error. If the state file shows a prior import but the store
// is empty, fail the sync rather than redeploy every rule at vendor defaults.
// Mirrors the guards in the ElastAlert and Strelka engines.
func (e *SuricataEngine) checkExistingDetectionsPlausible(existing map[string]*model.Detection, parsed []*model.Detection) error {
	if len(existing) != 0 || len(parsed) == 0 {
		return nil
	}

	state, err := detections.ReadStateFile(e.IOManager, e.StateFilePath)
	if err != nil {
		e.logger().WithError(err).Error("unable to read state file while validating detection store read")
		return detections.ErrStateFileNoCommunity
	}

	if state == nil || *state == 0 {
		// first import, empty store expected
		return nil
	}

	e.logger().WithFields(log.Fields{
		"parsedRules":   len(parsed),
		"existingRules": 0,
		"stateFilePath": e.StateFilePath,
	}).Error("state file present but detection store returned 0 detections, aborting sync to avoid redeploying rules at vendor defaults")

	return detections.ErrStateFileNoCommunity
}

// applyExistingRuleState applies state from existing ES detection
func (e *SuricataEngine) applyExistingRuleState(det *model.Detection, existing *model.Detection, stats *StateStats) {
	stats.ExistingRules++

	originalEnabled := det.IsEnabled

	// Copy user preferences
	det.IsEnabled = existing.IsEnabled
	det.Overrides = existing.Overrides
	det.PendingDelete = existing.PendingDelete

	// Copy ES metadata
	det.Id = existing.Id
	det.CreateTime = existing.CreateTime

	// Track modifications
	hasEnabledChange := originalEnabled != existing.IsEnabled
	hasOverrides := len(existing.Overrides) > 0

	if hasEnabledChange || hasOverrides {
		stats.UserModified++
	}
	if hasEnabledChange {
		stats.PreservedUserPrefs++
	}
}

// applyNewRuleState sets up state for new detection
func (e *SuricataEngine) applyNewRuleState(det *model.Detection, stats *StateStats) {
	stats.NewRules++
	det.Id = util.ToUUID(det.PublicID)
	det.CreateTime = util.Ptr(time.Now())
	// det.IsEnabled is already set correctly from parsing the rule content
}

// logStateApplication logs the statistics from state application
func (e *SuricataEngine) logStateApplication(stats *StateStats, totalProcessed int) {
	e.logger().WithFields(log.Fields{
		"existingRules":      stats.ExistingRules,
		"newRules":           stats.NewRules,
		"userModifiedRules":  stats.UserModified,
		"preservedUserPrefs": stats.PreservedUserPrefs,
		"totalProcessed":     totalProcessed,
	}).Info("applied user state to rules")
}

// Detection merging and state application helpers

// writeAllRulesFile writes the consolidated rules file in Suricata format
func (e *SuricataEngine) writeAllRulesFile(detections []*model.Detection) error {
	var rules bytes.Buffer

	// Group rules by ruleset for organization
	rulesByRuleset := make(map[string][]*model.Detection)
	for _, det := range detections {
		if det.PendingDelete {
			continue
		}

		// Include rule if:
		// 1. User has enabled it (det.IsEnabled = true), OR
		// 2. User disabled it BUT it's needed for flowbits
		includeRule := det.IsEnabled || e.flowbitRequired[det.PublicID] != nil

		if includeRule {
			rulesByRuleset[det.Ruleset] = append(rulesByRuleset[det.Ruleset], det)
		}
	}

	// Write rules grouped by ruleset
	for rulesetName, rulesetDetections := range rulesByRuleset {
		rules.WriteString(fmt.Sprintf("# Ruleset: %s\n", rulesetName))

		for _, det := range rulesetDetections {
			content := det.Content

			// Apply user-defined modify overrides first
			for _, override := range det.Overrides {
				if override.Type == model.OverrideTypeModify && override.IsEnabled {
					if override.Regex != nil && override.Value != nil {
						re, err := regexp.Compile(*override.Regex)
						if err != nil {
							return fmt.Errorf("invalid modify override regex for SID %s: %w", det.PublicID, err)
						}

						// Check for unsupported Python-style backreferences in replacement
						// Exclude pcre:"..." sections which may legitimately contain \1-\9
						stripped := pcrePattern.ReplaceAllString(*override.Value, "")
						if backrefPattern.MatchString(stripped) {
							return fmt.Errorf("modify override for SID %s contains unsupported backreference (\\1-\\9); use literal replacement instead", det.PublicID)
						}

						content = re.ReplaceAllLiteralString(content, *override.Value)
					}
				}
			}

			// Handle disabled rules that are needed for flowbits
			if !det.IsEnabled && e.flowbitRequired[det.PublicID] != nil {
				dep := e.flowbitRequired[det.PublicID]
				// Add explanatory comment
				rules.WriteString(fmt.Sprintf(
					"# AUTO-ENABLED (flowbit: %s, required by %d rule(s)): This disabled rule runs with noalert\n",
					dep.FlowbitName,
					len(dep.RequiredBy),
				))

				// Add noalert to the rule itself
				content = AddNoalertToRule(content)
			}

			rules.WriteString(content)
			rules.WriteString("\n")
		}

		rules.WriteString("\n")
	}

	return e.IOManager.WriteFile(e.allRulesFile, rules.Bytes(), 0644)
}

// writeThresholdFile writes threshold configuration in Suricata format.
// Output is sorted by SID, then by override fields, so the file content is
// stable across runs even when callers pass detections in map-iteration order.
// Note: Override validation happens at creation time in model.Override.Validate()
func (e *SuricataEngine) writeThresholdFile(detections []*model.Detection) error {
	var thresholds bytes.Buffer

	thresholds.WriteString("# Threshold configuration generated by Security Onion\n")
	thresholds.WriteString("# This file is automatically generated - do not edit manually\n\n")

	sorted := make([]*model.Detection, 0, len(detections))
	for _, det := range detections {
		if det.PendingDelete {
			continue
		}
		sorted = append(sorted, det)
	}
	slices.SortFunc(sorted, func(a, b *model.Detection) int {
		return cmp.Compare(a.PublicID, b.PublicID)
	})

	for _, det := range sorted {
		overrides := slices.Clone(det.Overrides)
		slices.SortStableFunc(overrides, compareOverrides)

		for _, override := range overrides {
			if !override.IsEnabled {
				continue
			}

			switch override.Type {
			case model.OverrideTypeThreshold:
				// Format: threshold gen_id <gid>, sig_id <sid>, type <type>, track <track>, count <count>, seconds <seconds>
				if override.ThresholdType == nil || override.Track == nil || override.Count == nil || override.Seconds == nil {
					return fmt.Errorf("invalid threshold override for SID %s: missing required fields", det.PublicID)
				}
				thresholds.WriteString(fmt.Sprintf("threshold gen_id 1, sig_id %s, type %s, track %s, count %d, seconds %d\n",
					det.PublicID, *override.ThresholdType, *override.Track, *override.Count, *override.Seconds))
			case model.OverrideTypeSuppress:
				// Format: suppress gen_id <gid>, sig_id <sid>, track <track_by>, ip <ip_address>
				if override.Track == nil || override.IP == nil {
					return fmt.Errorf("invalid suppress override for SID %s: missing required fields", det.PublicID)
				}
				thresholds.WriteString(fmt.Sprintf("suppress gen_id 1, sig_id %s, track %s, ip %s\n",
					det.PublicID, *override.Track, *override.IP))
			}
		}
	}

	return e.IOManager.WriteFile(e.thresholdFile, thresholds.Bytes(), 0644)
}

// compareOverrides orders overrides by their semantic fields so two equivalent
// overrides always sort identically. Nil pointers are treated as zero values.
func compareOverrides(a, b *model.Override) int {
	derefStr := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	derefInt := func(n *int) int {
		if n == nil {
			return 0
		}
		return *n
	}
	return cmp.Or(
		cmp.Compare(a.Type, b.Type),
		cmp.Compare(derefStr(a.ThresholdType), derefStr(b.ThresholdType)),
		cmp.Compare(derefStr(a.Track), derefStr(b.Track)),
		cmp.Compare(derefStr(a.IP), derefStr(b.IP)),
		cmp.Compare(derefInt(a.Count), derefInt(b.Count)),
		cmp.Compare(derefInt(a.Seconds), derefInt(b.Seconds)),
	)
}

// updateDetectionStore updates Elasticsearch with the synced detections
func (e *SuricataEngine) updateDetectionStore(
	ctx context.Context,
	detects []*model.Detection,
	configuredRulesets map[string]*RulesetSource,
	_ map[string]*RulesetSyncResult,
) error {
	// Get all existing detections
	existingDetections, err := e.getAllSuricataDetections(ctx)
	if err != nil {
		return fmt.Errorf("failed to get existing detections: %w", err)
	}

	// Build bulk indexer for efficient updates
	bulk, err := e.createBulkIndexer(ctx, e.logger().Entry)
	if err != nil {
		return err
	}

	// Set up audit and error tracking (thread-safe for concurrent bulk operations)
	createAudit := make([]model.AuditInfo, 0, len(detects))
	auditMut := sync.Mutex{}
	errMut := sync.Mutex{}
	errMap := make(map[string]string)

	// Error tracker to abort sync if too many consecutive errors occur
	et := detections.NewErrorTracker(e.failAfterConsecutiveErrorCount)

	// Track which detections we're keeping
	processedSIDs := make(map[string]bool)

	// Track stats per ruleset
	rulesetStats := make(map[string]*RulesetStats)
	for name := range configuredRulesets {
		rulesetStats[name] = &RulesetStats{}
	}

	// PHASE 1: UPDATE/CREATE - Process new detections
	for _, det := range detects {
		processedSIDs[det.PublicID] = true

		existing, exists := existingDetections[det.PublicID]

		// Prepare document
		document, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx,
			"detection", det, &det.Auditable, exists, nil, nil)
		if err != nil {
			e.logger().WithError(err).WithField("sid", det.PublicID).Error("failed to convert detection")
			continue
		}

		// Track per-ruleset stats based on actual changes
		if stats := rulesetStats[det.Ruleset]; stats != nil {
			if exists {
				if e.hasDetectionChanged(existing, det) {
					stats.Updated++
				} else {
					stats.Unchanged++
				}
			} else {
				stats.Added++
			}
		}

		if exists {
			// Update existing detection if changed
			if e.hasDetectionChanged(existing, det) {
				err = bulk.Add(ctx, esutil.BulkIndexerItem{
					Index:      index,
					Action:     "update",
					DocumentID: existing.Id,
					Body:       bytes.NewReader(document),
					OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
						auditMut.Lock()
						defer auditMut.Unlock()
						createAudit = append(createAudit, model.AuditInfo{
							Object: det,
							DocId:  resp.DocumentID,
							Op:     "update",
						})
					},
					OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
						errMut.Lock()
						defer errMut.Unlock()
						if err != nil {
							errMap[det.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
						} else {
							errMap[det.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", resp.Error.Reason)
						}
					},
				})
				if err != nil {
					errMut.Lock()
					errMap[det.PublicID] = fmt.Sprintf("unable to add update to bulk indexer; reason=%s", err.Error())
					errMut.Unlock()
				}

				// Track consecutive errors - abort if too many failures in a row
				if eterr := et.AddError(err); eterr != nil {
					return eterr
				}
			}
		} else {
			// Create new detection
			err = bulk.Add(ctx, esutil.BulkIndexerItem{
				Index:      index,
				Action:     "create",
				DocumentID: det.Id,
				Body:       bytes.NewReader(document),
				OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
					auditMut.Lock()
					defer auditMut.Unlock()
					createAudit = append(createAudit, model.AuditInfo{
						Object: det,
						DocId:  resp.DocumentID,
						Op:     "create",
					})
				},
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()
					if err != nil {
						errMap[det.PublicID] = fmt.Sprintf("unable to create detection; reason=%s", err.Error())
					} else {
						errMap[det.PublicID] = fmt.Sprintf("unable to create detection; reason=%s", resp.Error.Reason)
					}
				},
			})
			if err != nil {
				errMut.Lock()
				errMap[det.PublicID] = fmt.Sprintf("unable to add create to bulk indexer; reason=%s", err.Error())
				errMut.Unlock()
			}

			// Track consecutive errors - abort if too many failures in a row
			if eterr := et.AddError(err); eterr != nil {
				return eterr
			}
		}
	}

	// PHASE 2: DELETE - Simple deletion logic
	toDelete := map[string]struct{}{}
	for sid := range existingDetections {
		if !processedSIDs[sid] {
			toDelete[sid] = struct{}{}
		}
	}

	// Delete rules based on source status and rule type
	deletedCount := 0
	for sid := range toDelete {
		rule := existingDetections[sid]
		sourceConfig := configuredRulesets[rule.Ruleset]

		var reason string
		if sourceConfig == nil {
			// Case 1: Ruleset removed from configuration - user removed the source
			reason = "ruleset_removed"
		} else if sourceConfig.DeleteUnreferenced {
			// Case 2: Ruleset configured with DeleteUnreferenced = true
			reason = "unreferenced_rule"
		} else {
			// Case 3: Preserve (DeleteUnreferenced = false)
			continue
		}

		e.logger().WithFields(log.Fields{
			"sid":     sid,
			"ruleset": rule.Ruleset,
			"reason":  reason,
		}).Debug("deleting rule")

		// Track deletion stats (create entry for orphaned rulesets if needed)
		if rulesetStats[rule.Ruleset] == nil {
			rulesetStats[rule.Ruleset] = &RulesetStats{}
		}
		rulesetStats[rule.Ruleset].Deleted++

		err := e.executeRuleDeletion(ctx, bulk, rule, reason, &createAudit, &auditMut, &errMap, &errMut)
		if err != nil {
			e.logger().WithError(err).WithFields(log.Fields{
				"sid":     sid,
				"ruleset": rule.Ruleset,
			}).Error("failed to delete rule")
		}

		// Track consecutive errors - abort if too many failures in a row
		if eterr := et.AddError(err); eterr != nil {
			return eterr
		}

		if err == nil {
			deletedCount++
		}
	}

	e.logger().WithField("deletedCount", deletedCount).Info("completed rule deletions")

	// Close first bulk indexer - this must complete before audit records can be created
	err = bulk.Close(ctx)
	if err != nil {
		return fmt.Errorf("failed to close detection bulk indexer: %w", err)
	}

	// PHASE 3: Create audit records (only if there are any to create)
	if len(createAudit) > 0 {
		auditBulk, err := e.createBulkIndexer(ctx, e.logger().Entry)
		if err != nil {
			return fmt.Errorf("failed to create audit bulk indexer: %w", err)
		}

		for _, audit := range createAudit {
			det := audit.Object.(*model.Detection)
			// Prepare audit document
			document, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx,
				"detection", audit.Object, &det.Auditable, false, &audit.DocId, &audit.Op)
			if err != nil {
				errMut.Lock()
				errMap[det.PublicID] = fmt.Sprintf("unable to convert detection to document map for creating an audit doc; reason=%s", err.Error())
				errMut.Unlock()
				continue
			}

			// Create audit document
			err = auditBulk.Add(ctx, esutil.BulkIndexerItem{
				Index:  index,
				Action: "create",
				Body:   bytes.NewReader(document),
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()
					if err != nil {
						errMap[det.PublicID] = fmt.Sprintf("unable to create audit doc; reason=%s", err.Error())
					} else {
						errMap[det.PublicID] = fmt.Sprintf("unable to create audit doc; reason=%s", resp.Error.Reason)
					}
				},
			})
			if err != nil {
				errMut.Lock()
				errMap[det.PublicID] = fmt.Sprintf("unable to add audit doc to bulk indexer; reason=%s", err.Error())
				errMut.Unlock()
				continue
			}
		}

		// Close audit bulk indexer
		err = auditBulk.Close(ctx)
		if err != nil {
			return fmt.Errorf("failed to close audit bulk indexer: %w", err)
		}

		e.logger().WithField("auditCount", len(createAudit)).Info("completed audit record creation")
	}

	// Log any errors that occurred
	// No mutex needed - all bulk operations are complete at this point
	if len(errMap) > 0 {
		for sid, errMsg := range errMap {
			e.logger().WithField("sid", sid).Error(errMsg)
		}
	}

	// Log per-ruleset stats
	for name, stats := range rulesetStats {
		if stats.Added > 0 || stats.Updated > 0 || stats.Unchanged > 0 || stats.Deleted > 0 {
			e.logger().WithFields(log.Fields{
				"ruleset":   name,
				"added":     stats.Added,
				"updated":   stats.Updated,
				"unchanged": stats.Unchanged,
				"deleted":   stats.Deleted,
			}).Info("ruleset sync summary")
		}
	}

	return nil
}

// hasDetectionChanged checks if a detection needs to be updated
func (e *SuricataEngine) hasDetectionChanged(existing, new *model.Detection) bool {
	return existing.Content != new.Content ||
		existing.Title != new.Title ||
		existing.Severity != new.Severity ||
		existing.Ruleset != new.Ruleset ||
		existing.License != new.License ||
		existing.IsCommunity != new.IsCommunity ||
		existing.IsEnabled != new.IsEnabled
}

// Helper methods

// getAllSuricataDetections gets all Suricata detections with optional filters
func (e *SuricataEngine) getAllSuricataDetections(ctx context.Context, filters ...model.GetAllOption) (map[string]*model.Detection, error) {
	queryFilters := []model.GetAllOption{model.WithEngine(model.EngineNameSuricata)}
	queryFilters = append(queryFilters, filters...)
	return e.srv.Detectionstore.GetAllDetections(ctx, queryFilters...)
}

// handleSyncError handles sync errors with consistent logging and broadcasting
func (e *SuricataEngine) handleSyncError(err error, message string, logger *log.Entry) error {
	logger.WithError(err).Error(message)
	if e.notify {
		e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
			Engine: model.EngineNameSuricata,
			Status: "error",
		})
	}
	return detections.ErrSyncFailed
}

// createBulkIndexer creates and returns a bulk indexer with consistent error handling
func (e *SuricataEngine) createBulkIndexer(ctx context.Context, logger *log.Entry) (esutil.BulkIndexer, error) {
	bulk, err := e.srv.Detectionstore.BuildBulkIndexer(ctx, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build bulk indexer: %w", err)
	}
	return bulk, nil
}

// buildConfiguredRulesetsMap builds a map of configured ruleset sources
func (e *SuricataEngine) buildConfiguredRulesetsMap() map[string]*RulesetSource {
	configured := make(map[string]*RulesetSource)

	// Get sources from RulesetManager
	if e.rulesetManager != nil {
		for _, source := range e.rulesetManager.GetSources() {
			if source.Enabled != nil && *source.Enabled {
				configured[source.Name] = source
			}
		}
	}

	return configured
}

// executeRuleDeletion performs the actual deletion of a rule
func (e *SuricataEngine) executeRuleDeletion(
	ctx context.Context,
	bulk esutil.BulkIndexer,
	rule *model.Detection,
	reason string,
	createAudit *[]model.AuditInfo,
	auditMut *sync.Mutex,
	errMap *map[string]string,
	errMut *sync.Mutex,
) error {
	e.logger().WithFields(log.Fields{
		"sid":     rule.PublicID,
		"ruleset": rule.Ruleset,
		"reason":  reason,
	}).Debug("deleting rule")

	_, index, _ := e.srv.Detectionstore.ConvertObjectToDocument(
		ctx, "detection", rule, &rule.Auditable, false, nil, nil)

	err := bulk.Add(ctx, esutil.BulkIndexerItem{
		Action:     "delete",
		Index:      index,
		DocumentID: rule.Id,
		OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
			auditMut.Lock()
			defer auditMut.Unlock()
			*createAudit = append(*createAudit, model.AuditInfo{
				Object: rule,
				DocId:  resp.DocumentID,
				Op:     "delete",
			})
		},
		OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
			errMut.Lock()
			defer errMut.Unlock()
			if err != nil {
				(*errMap)[rule.PublicID] = fmt.Sprintf("unable to delete detection; reason=%s", err.Error())
			} else {
				(*errMap)[rule.PublicID] = fmt.Sprintf("unable to delete detection; reason=%s", resp.Error.Reason)
			}
		},
	})
	if err != nil {
		errMut.Lock()
		defer errMut.Unlock()
		(*errMap)[rule.PublicID] = fmt.Sprintf("unable to add delete to bulk indexer; reason=%s", err.Error())
		return err
	}

	return nil
}

func (e *SuricataEngine) checkForMigrations() {
	e.logger().Info("checking for suricata migrations")

	migrationFinder := regexp.MustCompile(`^suricata-migration-(.*)$`)

	migDir := DEFAULT_MIGRATIONS_DIR

	items, err := e.ReadDir(migDir)
	if err != nil {
		e.logger().WithError(err).Error("unable to read directory")
		return
	}

	migStates := map[string]string{} // map[semver]stateFilePath
	versions := []string{}

	// discover and read the state files
	for _, item := range items {
		if item.IsDir() {
			continue
		}

		matches := migrationFinder.FindStringSubmatch(item.Name())
		if matches == nil {
			continue
		}

		ver := matches[1]

		path := filepath.Join(migDir, item.Name())
		migStates[ver] = path
		versions = append(versions, ver)
	}

	// attempt to apply migrations in order
	semver.Sort(versions)

	if len(versions) == 0 {
		e.logger().Info("no suricata migrations found")
	} else {
		e.logger().WithField("migrationCount", len(versions)).Info("found suricata migrations")
	}

	for _, key := range versions {
		e.EngineState.Migrating = true

		state := migStates[key]

		migFunc, ok := e.migrations[key]
		if !ok {
			e.logger().WithField("migrationVersion", key).Error("migration function not found")
			continue
		}

		e.logger().WithField("migrationVersion", key).Info("attempting migration")

		err := migFunc(state)
		if err != nil {
			e.logger().WithError(err).WithField("migrationVersion", key).Error("unable to apply migration, halting migrations")
			e.EngineState.MigrationFailure = true
			break
		}
	}

	e.EngineState.Migrating = false

	e.logger().Info("done checking for suricata migrations")
}

func (e *SuricataEngine) readFingerprint(path string) (fingerprint *string, ok bool, err error) {
	raw, err := e.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}

		return nil, false, err
	}

	fingerprint = util.Ptr(strings.TrimSpace(string(raw)))

	return fingerprint, true, nil
}

func (e *SuricataEngine) ValidateRule(rule string) (string, error) {
	lines := strings.Split(rule, "\n")
	nonEmpty := lo.Filter(lines, func(line string, _ int) bool {
		return strings.TrimSpace(line) != ""
	})

	if len(nonEmpty) != 1 {
		return "", fmt.Errorf("suricata rules must be a single line")
	}

	parsed, err := ParseSuricataRule(rule)
	if err != nil {
		return rule, err
	}

	_, ok := parsed.GetOption("sid")
	if !ok {
		return rule, fmt.Errorf("rule does not contain a SID")
	}

	return parsed.String(), nil
}

func (e *SuricataEngine) ApplyFilters(detect *model.Detection) (bool, error) {
	return e.applyStatusRegexes(detect), nil
}

// ParseSuricataRules parses Suricata rules from content string
func ParseSuricataRules(ctx context.Context, content string, ruleset string) ([]*model.Detection, error) {
	// expecting one rule per line
	lines := strings.Split(content, "\n")
	dets := []*model.Detection{}

	for i, line := range lines {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			// empty line, ignore
			continue
		}

		wasCommented := false
		if strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(strings.TrimLeft(line, "#"))

			lower := strings.ToLower(line)
			// Check if this is a commented rule (vs an actual comment)
			// Valid Suricata rule actions: alert, pass, drop, reject*, config
			if strings.HasPrefix(lower, "alert") ||
				strings.HasPrefix(lower, "pass") ||
				strings.HasPrefix(lower, "drop") ||
				strings.HasPrefix(lower, "reject") || // covers reject, rejectsrc, rejectdst, rejectboth
				strings.HasPrefix(lower, "config") {
				wasCommented = true
			} else {
				// actual comment, skip line
				continue
			}
		}

		parsed, err := ParseSuricataRule(line)
		if err != nil {
			return nil, fmt.Errorf("unable to parse line %d: %w", i+1, err)
		}

		// extract details
		sidOpt, ok := parsed.GetOption("sid")
		if !ok || sidOpt == nil || len(*sidOpt) == 0 {
			return nil, fmt.Errorf("unable to parse line %d: rule does not contain a SID", i+1)
		}

		sid, err := strconv.Unquote(*sidOpt)
		if err != nil {
			sid = *sidOpt
		}

		msg := sid

		msgOpt, ok := parsed.GetOption("msg")
		if ok && msgOpt != nil && len(*msgOpt) != 0 {
			msg = *msgOpt
		}

		msg = strings.ReplaceAll(msg, `\;`, `;`)

		title := util.Unquote(msg)

		title = strings.ReplaceAll(title, `\"`, `"`)
		title = strings.ReplaceAll(title, `\\`, `\`)

		category := checkAndExtractCategory(title)

		var srcCreated, srcUpdated *time.Time
		severity := model.SeverityUnknown // TODO: Default severity?

		md := parsed.ParseMetaData()
		if md != nil {
			sigsev, ok := lo.Find(md, func(m *MetaData) bool {
				return strings.EqualFold(m.Key, "signature_severity")
			})
			if ok {
				switch strings.ToUpper(sigsev.Value) {
				case "INFORMATIONAL":
					severity = model.SeverityInformational
				case "MINOR":
					severity = model.SeverityLow
				case "MAJOR":
					severity = model.SeverityHigh
				case "CRITICAL":
					severity = model.SeverityCritical
				}
			}

			formats := []string{"2006-01-02", "2006/01/02", "2006_01_02"}

			sourceCreated, ok := lo.Find(md, func(m *MetaData) bool {
				return strings.EqualFold(m.Key, "created_at")
			})
			if ok {
				t, err := util.ParseDate(sourceCreated.Value, formats)
				if err == nil {
					srcCreated = &t
				}
			}

			sourceUpdated, ok := lo.Find(md, func(m *MetaData) bool {
				return strings.EqualFold(m.Key, "updated_at")
			})
			if ok {
				t, err := util.ParseDate(sourceUpdated.Value, formats)
				if err == nil {
					srcUpdated = &t
				}
			}
		}

		d := &model.Detection{
			IsEnabled:     !wasCommented,
			Author:        ruleset,
			Category:      category,
			PublicID:      sid,
			Title:         title,
			Severity:      severity,
			Content:       line,
			Engine:        model.EngineNameSuricata,
			Language:      model.SigLangSuricata,
			Ruleset:       ruleset,
			License:       lookupLicense(ruleset),
			SourceCreated: srcCreated,
			SourceUpdated: srcUpdated,
		}

		dets = append(dets, d)
	}

	return dets, nil
}

// Package-level utilities

func settingByID(all []*model.Setting, id string) *model.Setting {
	found, ok := lo.Find(all, func(s *model.Setting) bool {
		return s.Id == id
	})
	if !ok {
		return nil
	}

	return found
}

func extractSID(rule string) *string {
	sids := sidExtracter.FindAllStringSubmatch(rule, 2)
	if len(sids) != 1 { // 1 match = 1 sid
		return nil
	}

	return util.Ptr(strings.TrimSpace(sids[0][1]))
}

func (e *SuricataEngine) applyStatusRegexes(detect *model.Detection) (affectedByFilter bool) {
	for _, enable := range e.enableRegex {
		if enable.MatchString(detect.Content) && !detect.IsEnabled {
			detect.IsEnabled = true
			return true
		}
	}

	for _, disable := range e.disableRegex {
		if disable.MatchString(detect.Content) && detect.IsEnabled {
			detect.IsEnabled = false
			return true
		}
	}

	return false
}

func indexRules(lines []string, ignoreComments bool) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		if strings.HasPrefix(line, "#") && ignoreComments {
			continue
		}

		sid := extractSID(line)
		if sid == nil {
			continue
		}

		index[*sid] = i
	}

	return index

}

func lookupLicense(ruleset string) string {
	license, ok := licenseBySource[strings.ToLower(ruleset)]
	if !ok {
		license = model.LicenseUnknown
	}

	return license
}

func (e *SuricataEngine) GenerateUnusedPublicId(ctx context.Context) (string, error) {
	id := strconv.Itoa(rand.IntN(1000000) + 1000000) // [1000000, 2000000)

	i := 0
	for ; i < 10; i++ {
		detect, err := e.srv.Detectionstore.GetDetectionByPublicId(ctx, id)
		if err != nil {
			return "", err
		}

		if detect == nil {
			// no detection with this publicId, we're good
			break
		}

		id = strconv.Itoa(rand.IntN(1000000) + 1000000)
	}

	if i >= 10 {
		return "", fmt.Errorf("unable to generate a unique publicId")
	}

	return id, nil
}

func (e *SuricataEngine) DuplicateDetection(ctx context.Context, detection *model.Detection) (*model.Detection, error) {
	id, err := e.GenerateUnusedPublicId(ctx)
	if err != nil {
		return nil, err
	}

	rule, err := ParseSuricataRule(detection.Content)
	if err != nil {
		return nil, err
	}

	rule.UpdateForDuplication(id)

	dets, err := ParseSuricataRules(ctx, rule.String(), detections.RULESET_CUSTOM)
	if err != nil {
		return nil, err
	}

	if len(dets) == 0 {
		return nil, fmt.Errorf("unable to parse detection")
	}

	det := dets[0]

	err = e.ExtractDetails(det)
	if err != nil {
		return nil, err
	}

	// Preserve the original license and author
	det.Author = detection.Author
	det.License = detection.License

	user, err := e.srv.TryGetUser(ctx)
	if err != nil {
		return nil, err
	}

	det.Author = detections.AddUser(det.Author, user, ", ")
	det.IsEnabled = false

	return det, nil
}

func (e *SuricataEngine) IsAirgapped() bool {
	return e.srv.Config.AirgapEnabled
}

func (e *SuricataEngine) LoadAuxiliaryData(summaries []*model.AiSummary) error {
	sum := &sync.Map{}
	for _, summary := range summaries {
		sum.Store(summary.PublicId, summary)
	}

	e.aiSummaries = sum
	e.aiSummaryCount = len(summaries)

	e.logger().WithFields(log.Fields{
		"aiSummaryCount": len(summaries),
	}).Info("loaded AI summaries")

	return nil
}

func (e *SuricataEngine) MergeAuxiliaryData(detect *model.Detection) error {
	if e.showAiSummaries {
		obj, ok := e.aiSummaries.Load(detect.PublicID)
		if ok {
			sig := md5.Sum([]byte(detect.Content))
			hexSig := hex.EncodeToString(sig[:])

			summary := obj.(*model.AiSummary)
			detect.AiFields = &model.AiFields{
				AiSummary:         summary.Summary,
				AiSummaryReviewed: summary.Reviewed,
				IsAiSummaryStale:  !strings.EqualFold(summary.RuleBodyHash, hexSig),
			}

			e.logger().WithFields(log.Fields{
				"publicId":      detect.PublicID,
				"summaryLength": len(summary.Summary),
			}).Info("merged AI summary")
		} else {
			e.logger().WithFields(log.Fields{
				"publicId":       detect.PublicID,
				"aiSummaryCount": e.aiSummaryCount,
			}).Info("no AI summary found")
		}
	}

	return nil
}

// Integrity checking

func (e *SuricataEngine) IntegrityCheck(canInterrupt bool, logger *log.Entry) (deployedButNotEnabled []string, enabledButNotDeployed []string, err error) {
	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	if logger == nil {
		logger = log.WithFields(log.Fields{
			"detectionEngine": model.EngineNameSuricata,
		})
	}

	logger = logger.WithField("intCheckId", uuid.New().String())

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return nil, nil, detections.ErrIntCheckerStopped
	}

	// Read the deployed rules file
	allRules, err := e.ReadFile(e.allRulesFile)
	if err != nil {
		logger.WithError(err).WithField("path", e.allRulesFile).Error("unable to read rules file")
		return nil, nil, err
	}

	// Get ignored SID ranges setting
	allSettings, err := e.srv.Configstore.GetSettings(e.srv.Context, true)
	if err != nil {
		return nil, nil, err
	}

	ignored := settingByID(allSettings, "soc.config.server.modules.suricataengine.ignoredSidRanges")
	if ignored == nil {
		return nil, nil, fmt.Errorf("unable to find ignored setting")
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	// Parse deployed rules from rules file (only uncommented rules are deployed)
	rulesLines := strings.Split(string(allRules), "\n")
	rulesIndex := indexRules(rulesLines, true) // ignore comments

	deployed := make([]string, 0, len(rulesIndex))
	for sid := range rulesIndex {
		deployed = append(deployed, sid)
	}

	logger.WithField("deployedPublicIdsCount", len(deployed)).Debug("deployed sids")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	// Get ALL detections from Elasticsearch
	allDetections, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameSuricata))
	if err != nil {
		logger.WithError(err).Error("unable to query for all detections")
		return nil, nil, detections.ErrIntCheckFailed
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	// Build "expected enabled" list:
	// - User-enabled rules (IsEnabled=true)
	// - Disabled rules that are needed for flowbits
	expectedEnabled := make([]string, 0, len(allDetections))

	for pid, det := range allDetections {
		if det.PendingDelete {
			continue
		}

		// Include if user enabled OR needed for flowbits
		if det.IsEnabled || e.flowbitRequired[pid] != nil {
			expectedEnabled = append(expectedEnabled, pid)
		}
	}

	logger.WithField("expectedEnabledCount", len(expectedEnabled)).Debug("expected enabled detections")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return nil, nil, detections.ErrIntCheckerStopped
	}

	// Apply ignored SID ranges to both lists
	sidRangesToIgnore := parseIgnoredSidRanges(ignored.Value)

	deployedBefore := len(deployed)
	expectedBefore := len(expectedEnabled)

	deployed = filterOutSIDsInRanges(deployed, sidRangesToIgnore)
	expectedEnabled = filterOutSIDsInRanges(expectedEnabled, sidRangesToIgnore)

	logger.WithFields(log.Fields{
		"deployedFilteredOutCount": deployedBefore - len(deployed),
		"expectedFilteredOutCount": expectedBefore - len(expectedEnabled),
		"rangesToIgnore":           sidRangesToIgnore,
	}).Info("ignoring SIDs")

	// Compare deployed vs expected enabled to find discrepancies
	deployedButNotEnabled, enabledButNotDeployed, _ = detections.DiffLists(deployed, expectedEnabled)

	intCheckReport := logger.WithFields(log.Fields{
		"deployedButNotEnabled":      util.TruncateList(deployedButNotEnabled, 20),
		"enabledButNotDeployed":      util.TruncateList(enabledButNotDeployed, 20),
		"deployedButNotEnabledCount": len(deployedButNotEnabled),
		"enabledButNotDeployedCount": len(enabledButNotDeployed),
	})

	if len(deployedButNotEnabled) > 0 || len(enabledButNotDeployed) > 0 {
		intCheckReport.Warn("integrity check failed")
		return deployedButNotEnabled, enabledButNotDeployed, detections.ErrIntCheckFailed
	}

	intCheckReport.Info("integrity check passed")

	return deployedButNotEnabled, enabledButNotDeployed, nil
}

// Removed consolidateEnabled - no longer needed with new architecture

type Range struct {
	LowerLimit uint64
	UpperLimit uint64
}

func (r *Range) Contains(val uint64) bool {
	return val >= r.LowerLimit && val <= r.UpperLimit
}

func (r Range) String() string {
	return fmt.Sprintf("[%d, %d]", r.LowerLimit, r.UpperLimit)
}

func parseIgnoredSidRanges(settingValue string) []Range {
	ranges := []Range{}

	for _, line := range strings.Split(settingValue, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "-")
		if len(parts) != 2 {
			log.WithField("ignoredSidLine", line).Warn("invalid SID range to ignore, expected format is 'lower-upper', skipping this range")
			continue
		}

		num := strings.TrimSpace(parts[0])

		lower, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"lowerLimit":     num,
				"ignoredSidLine": line,
			}).Warn("invalid SID range to ignore, lower limit is not a valid number, skipping this range")

			continue
		}

		num = strings.TrimSpace(parts[1])

		upper, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"upperLimit":     num,
				"ignoredSidLine": line,
			}).Warn("invalid SID range to ignore, upper limit is not a valid number, skipping this range")

			continue
		}

		if lower > upper {
			log.WithFields(log.Fields{
				"lowerLimit":     lower,
				"upperLimit":     upper,
				"ignoredSidLine": line,
			}).Warn("invalid SID range to ignore, lowerLimit is greater than upperLimit, skipping this range")

			continue
		}

		ranges = append(ranges, Range{
			LowerLimit: lower,
			UpperLimit: upper,
		})
	}

	return ranges
}

func filterOutSIDsInRanges(sids []string, ranges []Range) []string {
	filtered := []string{}

	for _, sid := range sids {
		num, err := strconv.ParseUint(sid, 10, 64)
		if err != nil {
			log.WithField("unparsedSid", sid).Warn("unable to parse SID, skipping")
			continue
		}

		keep := true
		for _, r := range ranges {
			if r.Contains(num) {
				keep = false
				break
			}
		}

		if keep {
			filtered = append(filtered, sid)
		}
	}

	return filtered
}

// Configuration change detection

// generateConfigFingerprint creates a hash of the ruleset configuration
func (e *SuricataEngine) generateConfigFingerprint() string {
	// Create a normalized config structure for fingerprinting
	// Only include settings that affect which rules are deployed
	type fingerprintConfig struct {
		Rulesets     []*RulesetSource `json:"rulesets"`
		EnableRegex  []string         `json:"enableRegex"`
		DisableRegex []string         `json:"disableRegex"`
	}

	// Sort rulesets by name for consistent hashing
	sortedSources := make([]*RulesetSource, len(e.rulesetSources))
	copy(sortedSources, e.rulesetSources)
	sort.Slice(sortedSources, func(i, j int) bool {
		return sortedSources[i].Name < sortedSources[j].Name
	})

	// Sort each ruleset's exclude patterns for consistency
	for _, source := range sortedSources {
		if len(source.ExcludeFiles) > 0 {
			excludeFiles := make([]string, len(source.ExcludeFiles))
			copy(excludeFiles, source.ExcludeFiles)
			sort.Strings(excludeFiles)
			source.ExcludeFiles = excludeFiles
		}
	}

	// Extract regex strings
	enableRegexStrs := make([]string, 0, len(e.enableRegex))
	for _, re := range e.enableRegex {
		enableRegexStrs = append(enableRegexStrs, re.String())
	}

	disableRegexStrs := make([]string, 0, len(e.disableRegex))
	for _, re := range e.disableRegex {
		disableRegexStrs = append(disableRegexStrs, re.String())
	}

	config := fingerprintConfig{
		Rulesets:     sortedSources,
		EnableRegex:  enableRegexStrs,
		DisableRegex: disableRegexStrs,
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		e.logger().WithError(err).Error("failed to marshal config for fingerprinting")
		return ""
	}

	// Hash the JSON
	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// validateRulesetNames checks for duplicate ruleset names
func (e *SuricataEngine) validateRulesetNames() error {
	namesSeen := make(map[string]bool)
	for _, source := range e.rulesetSources {
		if namesSeen[source.Name] {
			return fmt.Errorf("duplicate ruleset name '%s' - each ruleset must have a unique name", source.Name)
		}
		namesSeen[source.Name] = true
	}
	return nil
}

// hasConfigChanged checks if ruleset configuration changed since last startup
func (e *SuricataEngine) hasConfigChanged() (bool, error) {
	currentFingerprint := e.generateConfigFingerprint()

	// Read previous config fingerprint
	previousFingerprint, havePrevious, err := e.readFingerprint(e.configFingerprintFile)
	if err != nil {
		e.logger().WithError(err).Warn("unable to read config fingerprint file")
		return true, nil // Assume changed if can't read previous
	}

	if !havePrevious {
		e.logger().Info("no previous config fingerprint found, assuming configuration changed")
		return true, nil
	}

	changed := !strings.EqualFold(*previousFingerprint, currentFingerprint)

	e.logger().WithFields(log.Fields{
		"configChanged":       changed,
		"currentFingerprint":  currentFingerprint,
		"previousFingerprint": *previousFingerprint,
	}).Debug("configuration change detection completed")

	return changed, nil
}
