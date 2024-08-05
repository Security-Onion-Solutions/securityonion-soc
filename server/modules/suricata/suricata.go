// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"golang.org/x/mod/semver"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

var sidExtracter = regexp.MustCompile(`(?i)\bsid: ?['"]?(.*?)['"]?;`)

const modifyFromTo = `"flowbits" "noalert; flowbits"`

var licenseBySource = map[string]string{
	"etopen": model.LicenseBSD,
	"etpro":  model.LicenseCommercial,
}

const (
	DEFAULT_COMMUNITY_RULES_FILE                  = "/nsm/rules/suricata/emerging-all.rules"
	DEFAULT_ALL_RULES_FILE                        = "/opt/sensoroni/nids/all.rules"
	DEFAULT_RULES_FINGERPRINT_FILE                = "/opt/sensoroni/fingerprints/emerging-all.fingerprint"
	DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECS = 86400
	DEFAULT_STATE_FILE_PATH                       = "/opt/sensoroni/fingerprints/suricataengine.state"
	DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS     = 300
	DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT    = 10
	DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS     = 600
	DEFAULT_AI_REPO                               = "https://github.com/Security-Onion-Solutions/securityonion-resources"
	DEFAULT_AI_REPO_LOC                           = "/opt/sensoroni/repos"

	CUSTOM_RULE_LOC = "/nsm/rules/detect-suricata/custom_temp"
)

var ( // treat as constants
	DEFAULT_ENABLE_REGEX  = []string{}
	DEFAULT_DISABLE_REGEX = []string{}
)

type SuricataEngine struct {
	srv                            *server.Server
	communityRulesFile             string
	allRulesFile                   string
	rulesFingerprintFile           string
	failAfterConsecutiveErrorCount int
	isRunning                      bool
	interm                         sync.Mutex
	notify                         bool
	migrations                     map[string]func(string) error
	customRulesets                 []*model.CustomRuleset
	writeNoRead                    *string
	checkMigrationsOnce            func()
	enableRegex                    []*regexp.Regexp
	disableRegex                   []*regexp.Regexp
	aiSummaries                    *sync.Map // map[string]*detections.AiSummary{}
	aiRepoUrl                      string
	aiRepoPath                     string
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

func (e *SuricataEngine) PrerequisiteModules() []string {
	return nil
}

func (e *SuricataEngine) GetState() *model.EngineState {
	return util.Ptr(e.EngineState)
}

func (e *SuricataEngine) Init(config module.ModuleConfig) (err error) {
	e.SyncThread = &sync.WaitGroup{}
	e.InterruptChan = make(chan bool, 1)
	e.IntegrityCheckerData.Thread = &sync.WaitGroup{}
	e.IntegrityCheckerData.Interrupt = make(chan bool, 1)
	e.aiSummaries = &sync.Map{}

	e.communityRulesFile = module.GetStringDefault(config, "communityRulesFile", DEFAULT_COMMUNITY_RULES_FILE)
	e.allRulesFile = module.GetStringDefault(config, "allRulesFile", DEFAULT_ALL_RULES_FILE)
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", DEFAULT_RULES_FINGERPRINT_FILE)
	e.CommunityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECS)
	e.CommunityRulesImportErrorSeconds = module.GetIntDefault(config, "communityRulesImportErrorSeconds", DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS)
	e.failAfterConsecutiveErrorCount = module.GetIntDefault(config, "failAfterConsecutiveErrorCount", DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT)
	e.IntegrityCheckerData.FrequencySeconds = module.GetIntDefault(config, "integrityCheckFrequencySeconds", DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS)

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
	e.customRulesets, err = model.GetCustomRulesetsDefault(config, "customRulesets", []*model.CustomRuleset{})
	if err != nil {
		return fmt.Errorf("unable to get custom rulesets: %w", err)
	}

	e.aiRepoUrl = module.GetStringDefault(config, "aiRepoUrl", DEFAULT_AI_REPO)
	e.aiRepoPath = module.GetStringDefault(config, "aiRepoPath", DEFAULT_AI_REPO_LOC)

	return nil
}

func (e *SuricataEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameSuricata] = e
	e.isRunning = true
	e.IntegrityCheckerData.IsRunning = true

	// start long running processes
	go detections.SyncScheduler(e, &e.SyncSchedulerParams, &e.EngineState, model.EngineNameSuricata, &e.isRunning, e.IOManager)
	go detections.IntegrityChecker(model.EngineNameSuricata, e, &e.IntegrityCheckerData, &e.EngineState.IntegrityFailure)

	// update Ai Summaries once and don't block
	go func() {
		logger := log.WithField("detectionEngine", model.EngineNameSuricata)

		err := detections.RefreshAiSummaries(e, model.SigLangSuricata, &e.isRunning, e.aiRepoPath, e.aiRepoUrl, e.IOManager, logger)
		if err != nil {
			if errors.Is(err, detections.ErrModuleStopped) {
				return
			}

			logger.WithError(err).Error("unable to refresh AI summaries")
		} else {
			logger.Info("successfully refreshed AI summaries")
		}
	}()

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
	// Regex to extract the first two words from the title
	regex, err := regexp.Compile(`^(\w+)\s+(\w+)`)
	if err != nil {
		log.WithError(err).Error("unable to compile suricata category extraction regex")
	}

	matches := regex.FindStringSubmatch(title)
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

			break
		}
	}

	return nil
}

func (e *SuricataEngine) Sync(logger *log.Entry, forceSync bool) error {
	defer func() {
		e.resetInterruptSync()
	}()

	if detections.CheckWriteNoRead(e.srv.Context, e.srv.Detectionstore, e.writeNoRead) {
		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameStrelka,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	e.writeNoRead = nil

	err := detections.RefreshAiSummaries(e, model.SigLangSuricata, &e.isRunning, e.aiRepoPath, e.aiRepoUrl, e.IOManager, logger)
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			return err
		}

		logger.WithError(err).Error("unable to refresh AI summaries")
	} else {
		logger.Info("successfully refreshed AI summaries")
	}

	e.EngineState.Syncing = true

	rules, hash, err := e.readAndHash(e.communityRulesFile)
	if err != nil {
		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "error",
			})
		}

		logger.WithError(err).Error("unable to read community rules file")

		return detections.ErrSyncFailed
	}

	if !forceSync {
		fingerprint, haveFP, err := e.readFingerprint(e.rulesFingerprintFile)
		if err != nil {
			logger.WithError(err).Error("unable to read rules fingerprint file")
			return detections.ErrSyncFailed
		}

		if haveFP && strings.EqualFold(*fingerprint, hash) {
			// if we have a fingerprint and the hashes are equal, there's nothing to do
			logger.Info("community rule sync found no changes")

			detections.WriteStateFile(e.IOManager, e.StateFilePath)

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "success",
				})
			}

			e.checkMigrationsOnce()

			_, _, err = e.IntegrityCheck(false, logger)

			e.EngineState.IntegrityFailure = err != nil

			if err != nil {
				logger.WithError(err).Error("post-sync integrity check failed")
			} else {
				logger.Info("post-sync integrity check passed")
			}

			// a non-forceSync sync that found no changes is a success
			return nil
		}
	}

	allSettings, err := e.srv.Configstore.GetSettings(e.srv.Context, true)
	if err != nil {
		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "error",
			})
		}

		logger.WithError(err).Error("unable to get settings")

		return detections.ErrSyncFailed
	}

	if !e.isRunning {
		return detections.ErrModuleStopped
	}

	ruleset := settingByID(allSettings, "idstools.config.ruleset")

	commDetections, err := e.ParseRules(rules, ruleset.Value)
	if err != nil {
		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "error",
			})
		}

		logger.WithError(err).Error("unable to parse community rules")

		return detections.ErrSyncFailed
	}

	for _, d := range commDetections {
		d.IsCommunity = true
	}

	dets, err := e.ReadCustomRulesets()
	if err != nil {
		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "error",
			})
		}

		logger.WithError(err).Error("unable to parse custom rulesets")

		return detections.ErrSyncFailed
	}

	commDetections = append(commDetections, dets...)

	commDetections = detections.DeduplicateByPublicId(commDetections)

	errMap, err := e.syncCommunityDetections(e.srv.Context, logger, commDetections, true, allSettings)
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			logger.Info("incomplete sync of suricata community detections due to module stopping")
			return err
		}

		if err.Error() == "Object not found" {
			// errMap contains exactly 1 error: the publicId of the detection that
			// was written to but not read back
			for publicId := range errMap {
				e.writeNoRead = util.Ptr(publicId)
			}
		}

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "error",
			})
		}

		logger.WithError(err).Error("unable to sync suricata community detections")

		return detections.ErrSyncFailed
	}

	detections.WriteStateFile(e.IOManager, e.StateFilePath)

	if len(errMap) > 0 {
		// there were errors, don't save the fingerprint.
		// idempotency means we might fix it if we try again later.
		logger.WithField("suricataSyncErrors", errMap).Error("unable to sync all community detections")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "partial",
			})
		}
	} else {
		err = e.WriteFile(e.rulesFingerprintFile, []byte(hash), 0644)
		if err != nil {
			logger.WithError(err).WithField("repoPath", e.rulesFingerprintFile).Error("unable to write rules fingerprint file")
		}

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameSuricata,
				Status: "success",
			})
		}

		_, _, err = e.IntegrityCheck(false, logger)

		e.EngineState.IntegrityFailure = err != nil

		if err != nil {
			logger.WithError(err).Error("post-sync integrity check failed")
		} else {
			logger.Info("post-sync integrity check passed")
		}
	}

	e.checkMigrationsOnce()

	return nil
}

func (e *SuricataEngine) checkForMigrations() {
	log.Info("checking for suricata migrations")

	migrationFinder := regexp.MustCompile(`^suricata-migration-(.*)$`)

	migDir := "/opt/so/conf/soc/migrations/"

	items, err := e.ReadDir(migDir)
	if err != nil {
		log.WithError(err).Error("unable to read directory")
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
		log.Info("no suricata migrations found")
	} else {
		log.WithField("migrationCount", len(versions)).Info("found suricata migrations")
	}

	for _, key := range versions {
		e.EngineState.Migrating = true

		state := migStates[key]

		migFunc, ok := e.migrations[key]
		if !ok {
			log.WithField("migrationVersion", key).Error("migration function not found")
			continue
		}

		log.WithField("migrationVersion", key).Info("attempting migration")

		err := migFunc(state)
		if err != nil {
			log.WithError(err).WithField("migrationVersion", key).Error("unable to apply migration, halting migrations")
			e.EngineState.MigrationFailure = true
			break
		}
	}

	e.EngineState.Migrating = false

	log.Info("done checking for suricata migrations")
}

func (e *SuricataEngine) readAndHash(path string) (content string, sha256Hash string, err error) {
	raw, err := e.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	rawHash := sha256.Sum256(raw)
	hexHash := hex.EncodeToString(rawHash[:])

	return string(raw), hexHash, nil
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

	return parsed.String(), nil
}

func (e *SuricataEngine) ApplyFilters(detect *model.Detection) (bool, error) {
	modified := e.applyStatusRegexes(detect)

	return modified, nil
}

func (e *SuricataEngine) ParseRules(content string, ruleset string) ([]*model.Detection, error) {
	// expecting one rule per line
	lines := strings.Split(content, "\n")
	dets := []*model.Detection{}

	for i, line := range lines {
		if !e.isRunning {
			return nil, detections.ErrModuleStopped
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
			if strings.HasPrefix(lower, "alert") ||
				strings.HasPrefix(lower, "drop") ||
				strings.HasPrefix(lower, "reject") ||
				strings.HasPrefix(lower, "pass") {
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
		}

		d := &model.Detection{
			IsEnabled: !wasCommented,
			Author:    ruleset,
			Category:  category,
			PublicID:  sid,
			Title:     title,
			Severity:  severity,
			Content:   line,
			Engine:    model.EngineNameSuricata,
			Language:  model.SigLangSuricata,
			Ruleset:   ruleset,
			License:   lookupLicense(ruleset),
		}

		dets = append(dets, d)
	}

	return dets, nil
}

func (e *SuricataEngine) SyncLocalDetections(ctx context.Context, detects []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	allSettings, err := e.srv.Configstore.GetSettings(ctx, true)
	if err != nil {
		return nil, err
	}

	localDets := []*model.Detection{}
	communityDets := []*model.Detection{}

	for _, detect := range detects {
		if detect.IsCommunity {
			communityDets = append(communityDets, detect)
		} else {
			localDets = append(localDets, detect)
		}
	}

	errMap = map[string]string{} // map[sid]error

	if len(communityDets) != 0 {
		eMap, err := e.syncCommunityDetections(ctx, nil, communityDets, false, allSettings)
		if err != nil {
			return eMap, err
		}

		for sid, e := range eMap {
			errMap[sid] = e
		}
	}

	if len(localDets) == 0 {
		return errMap, nil
	}

	local := settingByID(allSettings, "idstools.rules.local__rules")
	if local == nil {
		return nil, fmt.Errorf("unable to find local rules setting")
	}

	enabled := settingByID(allSettings, "idstools.sids.enabled")
	if enabled == nil {
		return nil, fmt.Errorf("unable to find enabled setting")
	}

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	if disabled == nil {
		return nil, fmt.Errorf("unable to find disabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return nil, fmt.Errorf("unable to find modify setting")
	}

	threshold := settingByID(allSettings, "suricata.thresholding.sids__yaml")

	localLines := strings.Split(local.Value, "\n")
	enabledLines := strings.Split(enabled.Value, "\n")
	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")

	localIndex := indexLocal(localLines)
	enabledIndex := indexEnabled(enabledLines, false)
	disabledIndex := indexEnabled(disabledLines, false)
	modifyIndex := indexModify(modifyLines, false, false)

	thresholdIndex, err := indexThreshold(threshold.Value)
	if err != nil {
		return nil, err
	}

	for _, detect := range localDets {
		if !e.isRunning {
			return nil, detections.ErrModuleStopped
		}

		_, err = e.ApplyFilters(detect)
		if err != nil {
			errMap[detect.PublicID] = fmt.Sprintf("unable to apply filters; reason=%s", err.Error())
			continue
		}

		parsedRule, err := ParseSuricataRule(detect.Content)
		if err != nil {
			errMap[detect.PublicID] = fmt.Sprintf("unable to parse rule; reason=%s", err.Error())
			continue
		}

		opt, ok := parsedRule.GetOption("sid")
		if !ok || opt == nil {
			errMap[detect.PublicID] = fmt.Sprintf("rule does not contain a SID; rule=%s", detect.Content)
			continue
		}

		sid := *opt
		_, isFlowbits := parsedRule.GetOption("flowbits")

		// update local
		localLines = updateLocal(localLines, localIndex, sid, isFlowbits, detect)

		// update enabled
		enabledLines = updateEnabled(enabledLines, enabledIndex, sid, isFlowbits, detect)

		// update disabled
		disabledLines = updateDisabled(disabledLines, disabledIndex, sid, isFlowbits, detect)

		// update overrides
		modifyLines = updateModify(modifyLines, modifyIndex, sid, detect)

		if isFlowbits && !detect.IsEnabled {
			modifyLines = updateModifyForDisabledFlowbits(modifyLines, modifyIndex, sid, detect)
		}

		updateThreshold(thresholdIndex, parsedRule.GetGenId(), detect)
	}

	localLines = removeBlankLines(localLines)
	enabledLines = removeBlankLines(enabledLines)
	disabledLines = removeBlankLines(disabledLines)
	modifyLines = removeBlankLines(modifyLines)

	local.Value = strings.Join(localLines, "\n")
	enabled.Value = strings.Join(enabledLines, "\n")
	disabled.Value = strings.Join(disabledLines, "\n")
	modify.Value = strings.Join(modifyLines, "\n")

	yamlThreshold, err := yaml.Marshal(thresholdIndex)
	if err != nil {
		return errMap, err
	}

	threshold.Value = string(yamlThreshold)

	err = e.srv.Configstore.UpdateSetting(ctx, local, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, enabled, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, disabled, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, modify, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, threshold, false)
	if err != nil {
		return errMap, err
	}

	return errMap, nil
}

func removeBlankLines(lines []string) []string {
	return lo.Filter(lines, func(line string, _ int) bool {
		return strings.TrimSpace(line) != ""
	})
}

func updateLocal(localLines []string, localIndex map[string]int, sid string, isFlowbits bool, detect *model.Detection) []string {
	lineNum, inLocal := localIndex[sid]
	if !inLocal && !detect.PendingDelete {
		if detect.IsEnabled || isFlowbits {
			// not in local, but should be
			localLines = append(localLines, detect.Content)
			lineNum = len(localLines) - 1
			localIndex[sid] = lineNum
		}
	} else {
		// in local...
		if (detect.IsEnabled || isFlowbits) && !detect.PendingDelete {
			// and should be, update it
			localLines[lineNum] = detect.Content
		} else {
			// and shouldn't be, remove it
			localLines[lineNum] = ""
			delete(localIndex, sid)
		}
	}

	return localLines
}

func updateEnabled(enabledLines []string, enabledIndex map[string]int, sid string, isFlowbits bool, detect *model.Detection) []string {
	lineNum, inEnabled := enabledIndex[sid]
	remove := (!detect.IsEnabled && !isFlowbits) || detect.PendingDelete

	line := detect.PublicID
	if remove {
		line = ""
	}

	if !inEnabled {
		if !remove {
			enabledLines = append(enabledLines, line)
			lineNum = len(enabledLines) - 1
			enabledIndex[sid] = lineNum
		}
	} else {
		enabledLines[lineNum] = line
		if remove {
			delete(enabledIndex, sid)
		}
	}

	return enabledLines
}

func updateModify(modifyLines []string, modifyIndex map[string]int, sid string, detect *model.Detection) []string {
	// find active modify override, if it exists
	var override *model.Override
	if detect.IsEnabled && !detect.PendingDelete {
		for _, o := range detect.Overrides {
			if o.Type == model.OverrideTypeModify && o.IsEnabled {
				override = o
				break
			}
		}
	}

	if override == nil {
		// no active override, remove any that are present
		lineNum, inModify := modifyIndex[sid]
		if inModify {
			modifyLines[lineNum] = ""
			delete(modifyIndex, sid)
		}

		return modifyLines
	}

	find := detections.EscapeDoubleQuotes(*override.Regex)
	replace := detections.EscapeDoubleQuotes(*override.Value)

	line := fmt.Sprintf(`%s "%s" "%s"`, detect.PublicID, find, replace)

	lineNum, inModify := modifyIndex[sid]
	if !inModify {
		modifyLines = append(modifyLines, line)
		lineNum = len(modifyLines) - 1
		modifyIndex[sid] = lineNum
	} else {
		modifyLines[lineNum] = line
	}

	return modifyLines
}

func updateDisabled(disabledLines []string, disabledIndex map[string]int, sid string, isFlowbits bool, detect *model.Detection) []string {
	if !isFlowbits || detect.PendingDelete {
		lineNum, inDisabled := disabledIndex[sid]

		line := detect.PublicID
		if detect.IsEnabled || detect.PendingDelete {
			line = ""
		}

		if !inDisabled {
			if !detect.PendingDelete && !detect.IsEnabled {
				disabledLines = append(disabledLines, line)
				lineNum = len(disabledLines) - 1
				disabledIndex[sid] = lineNum
			}
		} else {
			disabledLines[lineNum] = line
			if detect.IsEnabled || detect.PendingDelete {
				delete(disabledIndex, sid)
			}
		}
	}

	return disabledLines
}

// updateModifyForDisabledFlowbits updates the modify file for disabled flowbits rules so the rules stay enabled but don't alert
func updateModifyForDisabledFlowbits(modifyLines []string, modifyIndex map[string]int, sid string, detect *model.Detection) []string {
	lineNum, inModify := modifyIndex[sid]
	line := fmt.Sprintf("%s %s", detect.PublicID, modifyFromTo)

	if detect.PendingDelete {
		line = ""
		delete(modifyIndex, sid)
	}

	if !inModify {
		// not in the modify file, but should be
		if !detect.PendingDelete {
			modifyLines = append(modifyLines, line)
			lineNum = len(modifyLines) - 1
			modifyIndex[sid] = lineNum
		}
	} else {
		// in modify, but should be updated
		modifyLines[lineNum] = line
	}

	return modifyLines
}

func updateThreshold(thresholdIndex map[string][]*model.Override, genID int, detect *model.Detection) {
	delete(thresholdIndex, detect.PublicID)
	if detect.PendingDelete {
		return
	}

	detOverrides := lo.Filter(detect.Overrides, func(o *model.Override, _ int) bool {
		return o.IsEnabled && (o.Type == model.OverrideTypeThreshold || o.Type == model.OverrideTypeSuppress)
	})

	if len(detOverrides) > 0 {
		for _, o := range detOverrides {
			if o.Type == model.OverrideTypeSuppress || o.Type == model.OverrideTypeThreshold {
				o.GenID = util.Ptr(genID)
			}
		}

		thresholdIndex[detect.PublicID] = detOverrides
	}
}

func removeFromIndex(lines []string, index map[string]int, sid string) {
	lineNum, inIndex := index[sid]
	if inIndex {
		delete(index, sid)
		lines[lineNum] = ""
	}
}

func (e *SuricataEngine) syncCommunityDetections(ctx context.Context, logger *log.Entry, detects []*model.Detection, deleteUnreferenced bool, allSettings []*model.Setting) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()
	errMap = map[string]string{}

	changedByUser := web.IsChangedByUser(ctx)

	if logger == nil {
		logger = log.WithField("detectionEngine", model.EngineNameSuricata)
	}

	results := struct {
		Added     int32
		Updated   int32
		Removed   int32
		Unchanged int32
		Audited   int32
	}{}

	enabled := settingByID(allSettings, "idstools.sids.enabled")
	if enabled == nil {
		return nil, fmt.Errorf("unable to find enabled setting")
	}

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	if disabled == nil {
		return nil, fmt.Errorf("unable to find disabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return nil, fmt.Errorf("unable to find modify setting")
	}

	threshold := settingByID(allSettings, "suricata.thresholding.sids__yaml")
	if threshold == nil {
		return nil, fmt.Errorf("unable to find threshold setting")
	}

	// unpack settings into lines/indices
	enabledLines := strings.Split(enabled.Value, "\n")
	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")

	enabledIndex := indexEnabled(enabledLines, false)
	disabledIndex := indexEnabled(disabledLines, false)
	modifyIndex := indexModify(modifyLines, false, false)

	thresholdIndex, err := indexThreshold(threshold.Value)
	if err != nil {
		return nil, err
	}

	commSIDs, err := e.srv.Detectionstore.GetAllDetections(ctx, model.WithEngine(model.EngineNameSuricata), model.WithCommunity(true))
	if err != nil {
		return nil, err
	}

	toDelete := map[string]struct{}{}
	for sid := range commSIDs {
		toDelete[sid] = struct{}{}
	}

	et := detections.NewErrorTracker(e.failAfterConsecutiveErrorCount)

	bulk, err := e.srv.Detectionstore.BuildBulkIndexer(e.srv.Context, logger)
	if err != nil {
		return nil, err
	}

	createAudit := make([]model.AuditInfo, 0, len(detects))
	auditMut := sync.Mutex{}
	errMut := sync.Mutex{}

	for i := range detects {
		detect := detects[i]

		if !e.isRunning {
			return nil, detections.ErrModuleStopped
		}

		delete(toDelete, detect.PublicID)

		logger.WithFields(log.Fields{
			"rule.uuid": detect.PublicID,
			"rule.name": detect.Title,
		}).Info("syncing rule")

		orig, exists := commSIDs[detect.PublicID]
		if exists {
			_, isSpecificallyEnabled := enabledIndex[detect.PublicID]
			_, isSpecificallyDisabled := disabledIndex[detect.PublicID]
			if isSpecificallyDisabled || isSpecificallyEnabled {
				detect.IsEnabled = orig.IsEnabled
			}
			detect.Id = orig.Id
			detect.Overrides = orig.Overrides
			detect.CreateTime = orig.CreateTime
		} else {
			detect.CreateTime = util.Ptr(time.Now())
		}

		parsedRule, err := ParseSuricataRule(detect.Content)
		if err != nil {
			errMap[detect.PublicID] = fmt.Sprintf("unable to parse rule; reason=%s", err.Error())
			continue
		}

		opt, ok := parsedRule.GetOption("sid")
		if !ok || opt == nil {
			errMap[detect.PublicID] = fmt.Sprintf("rule does not contain a SID; rule=%s", detect.Content)
			continue
		}

		sid := *opt
		_, isFlowbits := parsedRule.GetOption("flowbits")

		modifiedByFilter := e.applyStatusRegexes(detect)

		_, inEnabled := enabledIndex[sid]
		_, inDisabled := disabledIndex[sid]

		if changedByUser || inEnabled || inDisabled || modifiedByFilter {
			// update enabled
			enabledLines = updateEnabled(enabledLines, enabledIndex, sid, isFlowbits, detect)

			// update disabled
			disabledLines = updateDisabled(disabledLines, disabledIndex, sid, isFlowbits, detect)
		}

		// update overrides
		modifyLines = updateModify(modifyLines, modifyIndex, sid, detect)
		updateThreshold(thresholdIndex, parsedRule.GetGenId(), detect)

		if isFlowbits && !detect.IsEnabled {
			modifyLines = updateModifyForDisabledFlowbits(modifyLines, modifyIndex, sid, detect)
		}

		detect.Kind = ""

		document, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", detect, &detect.Auditable, exists, nil, nil)
		if err != nil {
			errMap[detect.PublicID] = fmt.Sprintf("unable to convert detection to document map; reason=%s", err.Error())
			continue
		}

		if exists {
			if orig.Content != detect.Content || orig.Ruleset != detect.Ruleset || len(detect.Overrides) != 0 || orig.IsEnabled != detect.IsEnabled {
				logger.WithFields(log.Fields{
					"rule.uuid": detect.PublicID,
					"rule.name": detect.Title,
				}).Info("updating Suricata detection")

				err = bulk.Add(ctx, esutil.BulkIndexerItem{
					Index:      index,
					Action:     "update",
					DocumentID: orig.Id,
					Body:       bytes.NewReader(document),
					OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
						auditMut.Lock()
						defer auditMut.Unlock()

						results.Updated++

						createAudit = append(createAudit, model.AuditInfo{
							Detection: detect,
							DocId:     resp.DocumentID,
							Op:        "update",
						})
					},
					OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
						errMut.Lock()
						defer errMut.Unlock()

						if err != nil {
							errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
						} else {
							errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", resp.Error.Reason)
						}
					},
				})
				if err != nil {
					if err.Error() == "Object not found" {
						errMap = map[string]string{
							detect.PublicID: "Object not found",
						}

						return errMap, err
					}

					errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
				}

				err = et.AddError(err)
				if err != nil {
					return errMap, err
				}
			} else {
				results.Unchanged++
			}
		} else {
			logger.WithFields(log.Fields{
				"rule.uuid": detect.PublicID,
				"rule.name": detect.Title,
			}).Info("creating new Suricata detection")

			err = bulk.Add(ctx, esutil.BulkIndexerItem{
				Index:  index,
				Action: "create",
				Body:   bytes.NewReader(document),
				OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
					auditMut.Lock()
					defer auditMut.Unlock()

					results.Added++

					createAudit = append(createAudit, model.AuditInfo{
						Detection: detect,
						DocId:     resp.DocumentID,
						Op:        "create",
					})
				},
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()

					if err != nil {
						errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
					} else {
						errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", resp.Error.Reason)
					}
				},
			})
			if err != nil {
				if err.Error() == "Object not found" {
					errMap = map[string]string{
						detect.PublicID: err.Error(),
					}

					return errMap, err
				}

				errMap[detect.PublicID] = fmt.Sprintf("unable to create detection; reason=%s", err.Error())
			}

			err = et.AddError(err)
			if err != nil {
				return errMap, err
			}
		}
	}

	if deleteUnreferenced {
		for sid := range toDelete {
			if !e.isRunning {
				return nil, detections.ErrModuleStopped
			}

			removeFromIndex(enabledLines, enabledIndex, sid)
			removeFromIndex(disabledLines, disabledIndex, sid)
			removeFromIndex(modifyLines, modifyIndex, sid)
			delete(thresholdIndex, sid)

			id := commSIDs[sid].Id

			_, index, _ := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", commSIDs[sid], &commSIDs[sid].Auditable, false, nil, nil)

			err = bulk.Add(ctx, esutil.BulkIndexerItem{
				Action:     "delete",
				Index:      index,
				DocumentID: id,
				OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
					auditMut.Lock()
					defer auditMut.Unlock()

					results.Removed++

					createAudit = append(createAudit, model.AuditInfo{
						Detection: commSIDs[sid],
						DocId:     resp.DocumentID,
						Op:        "delete",
					})
				},
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()

					if err != nil {
						errMap[commSIDs[sid].PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
					} else {
						errMap[commSIDs[sid].PublicID] = fmt.Sprintf("unable to update detection; reason=%s", resp.Error.Reason)
					}
				},
			})
			if err != nil {
				errMap[sid] = fmt.Sprintf("unable to add to bulk indexer; reason=%s", err.Error())
			}
		}
	}

	err = bulk.Close(ctx)
	if err != nil {
		return nil, err
	}

	stats := bulk.Stats()
	logger.WithFields(log.Fields{
		"NumAdded":    stats.NumAdded,
		"NumCreated":  stats.NumCreated,
		"NumDeleted":  stats.NumDeleted,
		"NumFailed":   stats.NumFailed,
		"NumFlushed":  stats.NumFlushed,
		"NumIndexed":  stats.NumIndexed,
		"NumRequests": stats.NumRequests,
		"NumUpdated":  stats.NumUpdated,
	}).Debug("detections bulk audit sync stats")

	if len(createAudit) != 0 {
		bulk, err = e.srv.Detectionstore.BuildBulkIndexer(e.srv.Context, logger)
		if err != nil {
			return nil, err
		}

		for _, audit := range createAudit {
			// prepare audit doc
			document, index, err := e.srv.Detectionstore.ConvertObjectToDocument(ctx, "detection", audit.Detection, &audit.Detection.Auditable, false, &audit.DocId, &audit.Op)
			if err != nil {
				errMap[audit.Detection.PublicID] = fmt.Sprintf("unable to convert detection to document map for creating an audit doc; reason=%s", err.Error())
				continue
			}

			// create audit doc
			err = bulk.Add(ctx, esutil.BulkIndexerItem{
				Index:  index,
				Action: "create",
				Body:   bytes.NewReader(document),
				OnSuccess: func(ctx context.Context, bii esutil.BulkIndexerItem, biri esutil.BulkIndexerResponseItem) {
					atomic.AddInt32(&results.Audited, 1)
				},
				OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
					errMut.Lock()
					defer errMut.Unlock()

					if err != nil {
						errMap[audit.Detection.PublicID] = fmt.Sprintf("unable to create audit doc; reason=%s", err.Error())
					} else {
						errMap[audit.Detection.PublicID] = fmt.Sprintf("unable to create audit doc; reason=%s", resp.Error.Reason)
					}
				},
			})
			if err != nil {
				errMap[audit.Detection.PublicID] = fmt.Sprintf("unable to add audit doc to bulk indexer; reason=%s", err.Error())
				continue
			}
		}

		err = bulk.Close(ctx)
		if err != nil {
			return nil, err
		}

		stats := bulk.Stats()
		logger.WithFields(log.Fields{
			"NumAdded":    stats.NumAdded,
			"NumCreated":  stats.NumCreated,
			"NumDeleted":  stats.NumDeleted,
			"NumFailed":   stats.NumFailed,
			"NumFlushed":  stats.NumFlushed,
			"NumIndexed":  stats.NumIndexed,
			"NumRequests": stats.NumRequests,
			"NumUpdated":  stats.NumUpdated,
		}).Debug("detections bulk audit sync stats")
	}

	enabledLines = removeBlankLines(enabledLines)
	disabledLines = removeBlankLines(disabledLines)
	modifyLines = removeBlankLines(modifyLines)

	// re-pack indices back to settings
	enabled.Value = strings.Join(enabledLines, "\n")
	disabled.Value = strings.Join(disabledLines, "\n")
	modify.Value = strings.Join(modifyLines, "\n")

	yamlThreshold, err := yaml.Marshal(thresholdIndex)
	if err != nil {
		return errMap, err
	}

	threshold.Value = string(yamlThreshold)

	err = e.srv.Configstore.UpdateSetting(ctx, enabled, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, disabled, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, modify, false)
	if err != nil {
		return errMap, err
	}

	err = e.srv.Configstore.UpdateSetting(ctx, threshold, false)
	if err != nil {
		return errMap, err
	}

	logger.WithFields(log.Fields{
		"syncAudited":            results.Audited,
		"syncAdded":              results.Added,
		"syncUpdated":            results.Updated,
		"syncRemoved":            results.Removed,
		"syncUnchanged":          results.Unchanged,
		"syncErrors":             errMap,
		"syncDeleteUnreferenced": deleteUnreferenced,
	}).Info("suricata community diff")

	return errMap, nil
}

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
		if enable.MatchString(detect.Content) {
			detect.IsEnabled = true
			return true
		}
	}

	for _, disable := range e.disableRegex {
		if disable.MatchString(detect.Content) {
			detect.IsEnabled = false
			return true
		}
	}

	return false
}

func indexLocal(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		sid := extractSID(line)
		if sid == nil {
			continue
		}

		index[*sid] = i
	}

	return index
}

func indexEnabled(lines []string, ignoreComments bool) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") && ignoreComments {
			continue
		}

		line = strings.TrimLeft(line, "# \t")
		if line != "" {
			index[line] = i
		}
	}

	return index
}

func indexModify(lines []string, ignoreComments bool, onlyFlowBits bool) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		if ignoreComments && strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimSpace(strings.TrimLeft(line, "# \t"))

		if onlyFlowBits && !strings.Contains(line, modifyFromTo) {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if parts[0] != "" {
			index[parts[0]] = i
		}
	}

	return index
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

func indexThreshold(content string) (map[string][]*model.Override, error) {
	index := map[string][]*model.Override{}

	err := yaml.Unmarshal([]byte(content), &index)
	if err != nil {
		return nil, err
	}

	return index, nil
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

	dets, err := e.ParseRules(rule.String(), detections.RULESET_CUSTOM)
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

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	user, err := e.srv.Userstore.GetUserById(ctx, userID)
	if err != nil {
		return nil, err
	}

	det.Author = detections.AddUser(det.Author, user, ", ")
	det.IsEnabled = false

	return det, nil
}

func (e *SuricataEngine) LoadAuxilleryData(summaries []*model.AiSummary) error {
	sum := &sync.Map{}
	for _, summary := range summaries {
		sum.Store(summary.PublicId, summary)
	}

	e.aiSummaries = sum

	return nil
}

func (e *SuricataEngine) MergeAuxilleryData(detect *model.Detection) error {
	obj, ok := e.aiSummaries.Load(detect.PublicID)
	if ok {
		summary := obj.(*model.AiSummary)
		detect.AiFields = &model.AiFields{
			AiSummary:         summary.Summary,
			AiSummaryReviewed: summary.Reviewed,
		}
	}

	return nil
}

func (e *SuricataEngine) ReadCustomRulesets() (detects []*model.Detection, err error) {
	detects = []*model.Detection{}

	for _, custom := range e.customRulesets {
		var content []byte

		if custom.File != "" {
			content, err = e.ReadFile(custom.File)
			if err != nil {
				log.WithError(err).WithField("customRulesetFilePath", custom.File).Error("unable to read custom ruleset File, skipping")

				return nil, err
			}
		} else if custom.Url != "" && custom.TargetFile != "" {
			path := filepath.Join(CUSTOM_RULE_LOC, custom.TargetFile)

			content, err = e.ReadFile(path)
			if err != nil {
				log.WithError(err).WithField("customRulesetTargetFilePath", path).Error("unable to read custom ruleset TargetFile, skipping")

				return nil, err
			}
		} else {
			log.WithFields(log.Fields{
				"rulesetName": custom.Ruleset,
			}).Error("invalid custom ruleset, skipping")

			return nil, errors.New("invalid custom ruleset")
		}

		dets, err := e.ParseRules(string(content), custom.Ruleset)
		if err != nil {
			log.WithError(err).WithField("customRulesetName", custom.Ruleset).Error("unable to parse custom ruleset, skipping")

			return nil, err
		}

		for _, detect := range dets {
			detect.IsCommunity = custom.Community
			detect.License = custom.License

			detects = append(detects, detect)
		}
	}

	return detects, nil
}

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

	allSettings, err := e.srv.Configstore.GetSettings(e.srv.Context, true)
	if err != nil {
		return nil, nil, err
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return nil, nil, detections.ErrIntCheckerStopped
	}

	allRules, err := e.ReadFile(e.allRulesFile)
	if err != nil {
		logger.WithError(err).WithField("path", e.allRulesFile).Error("unable to read all.rules file")
		return nil, nil, err
	}

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	if disabled == nil {
		return nil, nil, fmt.Errorf("unable to find disabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return nil, nil, fmt.Errorf("unable to find modify setting")
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	// unpack settings into lines/indices
	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")
	rulesLines := strings.Split(string(allRules), "\n")

	disabledIndex := indexEnabled(disabledLines, true)
	modifyIndex := indexModify(modifyLines, true, true)
	rulesIndex := indexRules(rulesLines, true)

	// modifyIndex is filtered for flowbits rules meaning the index is equivalent
	// in function to a list of disabled flowbits rules
	for k, v := range modifyIndex {
		disabledIndex[k] = v
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	deployed := consolidateEnabled(rulesIndex, disabledIndex)

	logger.WithField("deployedPublicIdsCount", len(deployed)).Debug("deployed sids")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	ret, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameSuricata), model.WithEnabled(true))
	if err != nil {
		logger.WithError(err).Error("unable to query for enabled detections")
		return nil, nil, detections.ErrIntCheckFailed
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	enabled := make([]string, 0, len(ret))
	for pid := range ret {
		enabled = append(enabled, pid)
	}

	logger.WithField("enabledDetectionsCount", len(enabled)).Debug("enabled detections")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return nil, nil, detections.ErrIntCheckerStopped
	}

	deployedButNotEnabled, enabledButNotDeployed, _ = detections.DiffLists(deployed, enabled)

	intCheckReport := logger.WithFields(log.Fields{
		"deployedButNotEnabled":      detections.TruncateList(deployedButNotEnabled, 20),
		"enabledButNotDeployed":      detections.TruncateList(enabledButNotDeployed, 20),
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

func consolidateEnabled(rulesIndex map[string]int, disabledIndex map[string]int) (pids []string) {
	pids = make([]string, 0, len(rulesIndex))

	for pid := range rulesIndex {
		_, disabled := disabledIndex[pid]
		if !disabled {
			pids = append(pids, pid)
		}
	}

	return pids
}
