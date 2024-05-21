// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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

var errModuleStopped = fmt.Errorf("suricata module has stopped running")
var sidExtracter = regexp.MustCompile(`(?i)\bsid: ?['"]?(.*?)['"]?;`)

const modifyFromTo = `"flowbits" "noalert; flowbits"`

var licenseBySource = map[string]string{
	"etopen": model.LicenseBSD,
	"etpro":  model.LicenseCommercial,
}

const (
	DEFAULT_COMMUNITY_RULES_FILE                  = "/nsm/rules/suricata/emerging-all.rules"
	DEFAULT_RULES_FINGERPRINT_FILE                = "/opt/sensoroni/fingerprints/emerging-all.fingerprint"
	DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECS = 86400
	DEFAULT_STATE_FILE_PATH                       = "/opt/sensoroni/fingerprints/suricataengine.state"
	DEFAULT_ALLOW_REGEX                           = ""
	DEFAULT_DENY_REGEX                            = ""
	DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS     = 300
	DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT    = 10
	DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS     = 600
)

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
	ReadDir(path string) ([]os.DirEntry, error)
}

type SuricataEngine struct {
	srv                                  *server.Server
	communityRulesFile                   string
	rulesFingerprintFile                 string
	communityRulesImportFrequencySeconds int
	communityRulesImportErrorSeconds     int
	failAfterConsecutiveErrorCount       int
	isRunning                            bool
	syncThread                           *sync.WaitGroup
	interruptSync                        chan bool
	interm                               sync.Mutex
	allowRegex                           *regexp.Regexp
	denyRegex                            *regexp.Regexp
	notify                               bool
	stateFilePath                        string
	migrations                           map[string]func(string) error
	detections.IntegrityCheckerData
	model.EngineState
	IOManager
}

func NewSuricataEngine(srv *server.Server) *SuricataEngine {
	e := &SuricataEngine{
		srv:       srv,
		IOManager: &ResourceManager{},
	}

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
	e.syncThread = &sync.WaitGroup{}
	e.interruptSync = make(chan bool, 1)
	e.IntegrityCheckerData.Thread = &sync.WaitGroup{}
	e.IntegrityCheckerData.Interrupt = make(chan bool, 1)

	e.communityRulesFile = module.GetStringDefault(config, "communityRulesFile", DEFAULT_COMMUNITY_RULES_FILE)
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", DEFAULT_RULES_FINGERPRINT_FILE)
	e.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECS)
	e.communityRulesImportErrorSeconds = module.GetIntDefault(config, "communityRulesImportErrorSeconds", DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS)
	e.failAfterConsecutiveErrorCount = module.GetIntDefault(config, "failAfterConsecutiveErrorCount", DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT)
	e.IntegrityCheckerData.FrequencySeconds = module.GetIntDefault(config, "integrityCheckFrequencySeconds", DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS)

	allow := module.GetStringDefault(config, "allowRegex", DEFAULT_ALLOW_REGEX)
	deny := module.GetStringDefault(config, "denyRegex", DEFAULT_DENY_REGEX)

	if allow != "" {
		var err error
		e.allowRegex, err = regexp.Compile(allow)
		if err != nil {
			return fmt.Errorf("unable to compile Suricata's allowRegex: %w", err)
		}
	}

	if deny != "" {
		var err error
		e.denyRegex, err = regexp.Compile(deny)
		if err != nil {
			return fmt.Errorf("unable to compile Suricata's denyRegex: %w", err)
		}
	}

	e.stateFilePath = module.GetStringDefault(config, "stateFilePath", DEFAULT_STATE_FILE_PATH)

	return nil
}

func (e *SuricataEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameSuricata] = e
	e.isRunning = true
	e.IntegrityCheckerData.IsRunning = true

	go e.watchCommunityRules()
	go detections.IntegrityChecker(model.EngineNameSuricata, e, &e.IntegrityCheckerData, &e.EngineState.IntegrityFailure)

	return nil
}

func (e *SuricataEngine) Stop() error {
	e.isRunning = false
	e.InterruptSync(false, false)
	e.syncThread.Wait()
	e.pauseIntegrityChecker()
	e.interruptIntegrityCheck()
	e.IntegrityCheckerData.Thread.Wait()

	return nil
}

func (e *SuricataEngine) InterruptSync(fullUpgrade bool, notify bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = notify

	if len(e.interruptSync) == 0 {
		e.interruptSync <- fullUpgrade
	}
}

func (e *SuricataEngine) resetInterrupt() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.interruptSync) != 0 {
		<-e.interruptSync
	}
}

func (e *SuricataEngine) interruptIntegrityCheck() {
	e.interm.Lock()
	defer e.interm.Unlock()

	if len(e.IntegrityCheckerData.Interrupt) == 0 {
		e.IntegrityCheckerData.Interrupt <- true
	}
}

func (e *SuricataEngine) pauseIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = false
}

func (e *SuricataEngine) resumeIntegrityChecker() {
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

func (e *SuricataEngine) watchCommunityRules() {
	e.syncThread.Add(1)
	defer func() {
		e.syncThread.Done()
		e.isRunning = false
	}()

	// |> nil: no import has been completed, it's this way during the first sync
	// so that the timerDur returned by DetermineWaitTime is used. After first sync,
	// the pointer should always have a value
	// |> false: the last sync was not successful, the timer for the next sync should use
	// the shorter communityRulesImportErrorSeconds timer.
	// |> true: the last sync was successful, the timer for the next sync should use
	// the normal communityRulesImportFrequencySeconds timer.
	var lastSyncSuccess *bool

	// publicId of a detection that was written but not read back
	var writeNoRead *string

	ctx := e.srv.Context
	templateFound := false
	checkMigrationsOnce := sync.OnceFunc(e.checkForMigrations)

	lastImport, timerDur := detections.DetermineWaitTime(e.IOManager, e.stateFilePath, time.Second*time.Duration(e.communityRulesImportFrequencySeconds))

	for e.isRunning {
		if lastImport == nil && lastSyncSuccess != nil && *lastSyncSuccess {
			now := uint64(time.Now().UnixMilli())
			lastImport = &now
		}

		e.EngineState.Syncing = false
		e.EngineState.Importing = lastImport == nil
		e.EngineState.Migrating = false
		e.EngineState.SyncFailure = lastSyncSuccess != nil && !*lastSyncSuccess

		e.resetInterrupt()

		var forceSync bool

		if lastSyncSuccess != nil {
			if *lastSyncSuccess {
				timerDur = time.Second * time.Duration(e.communityRulesImportFrequencySeconds)
			} else {
				timerDur = time.Second * time.Duration(e.communityRulesImportErrorSeconds)
				forceSync = true
			}
		}

		timer := time.NewTimer(timerDur)

		lastSyncStatus := "nil"
		if lastSyncSuccess != nil {
			lastSyncStatus = strconv.FormatBool(*lastSyncSuccess)
		}

		log.WithFields(log.Fields{
			"waitTimeSeconds":   timerDur.Seconds(),
			"forceSync":         forceSync,
			"lastSyncSuccess":   lastSyncStatus,
			"expectedStartTime": time.Now().Add(timerDur).Format(time.RFC3339),
		}).Info("waiting for next suricata community rules sync")

		e.resumeIntegrityChecker()

		select {
		case <-timer.C:
		case typ := <-e.interruptSync:
			forceSync = forceSync || typ
		}

		e.pauseIntegrityChecker()

		if !e.isRunning {
			break
		}

		lastSyncSuccess = util.Ptr(false)

		if detections.CheckWriteNoRead(e.srv.Context, e.srv.Detectionstore, writeNoRead) {
			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "error",
				})
			}

			continue
		}

		writeNoRead = nil

		log.WithFields(log.Fields{
			"forceSync": forceSync,
		}).Info("syncing suricata community rules")

		e.EngineState.Syncing = true

		start := time.Now()

		if !templateFound {
			exists, err := e.srv.Detectionstore.DoesTemplateExist(ctx, "so-detection")
			if err != nil {
				log.WithError(err).Error("unable to check for detection index template")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
						Engine: model.EngineNameSuricata,
						Status: "error",
					})
				}

				continue
			}

			if !exists {
				log.Warn("detection index template does not exist, skipping import")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
						Engine: model.EngineNameSuricata,
						Status: "error",
					})
				}

				continue
			}

			templateFound = true
		}

		rules, hash, err := readAndHash(e.communityRulesFile)
		if err != nil {
			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "error",
				})
			}

			log.WithError(err).Error("unable to read community rules file")

			continue
		}

		// If no import has been completed, then do a full sync
		if lastImport == nil {
			forceSync = true
		}

		if !forceSync {
			fingerprint, haveFP, err := readFingerprint(e.rulesFingerprintFile)
			if err != nil {
				log.WithError(err).Error("unable to read rules fingerprint file")
				continue
			}

			if haveFP && strings.EqualFold(*fingerprint, hash) {
				// if we have a fingerprint and the hashes are equal, there's nothing to do
				log.Info("suricata sync found no changes")

				detections.WriteStateFile(e.IOManager, e.stateFilePath)

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
						Engine: model.EngineNameSuricata,
						Status: "success",
					})
				}

				checkMigrationsOnce()

				err = e.IntegrityCheck(false)

				e.EngineState.IntegrityFailure = err != nil
				lastSyncSuccess = util.Ptr(err == nil)

				if err != nil {
					log.WithError(err).Error("post-sync integrity check failed")
				} else {
					log.Info("post-sync integrity check passed")
				}

				continue
			}
		}

		allSettings, err := e.srv.Configstore.GetSettings(ctx)
		if err != nil {
			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "error",
				})
			}

			log.WithError(err).Error("unable to get settings")

			continue
		}

		if !e.isRunning {
			break
		}

		ruleset := settingByID(allSettings, "idstools.config.ruleset")

		commDetections, err := e.ParseRules(rules, ruleset.Value, true)
		if err != nil {
			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "error",
				})
			}

			log.WithError(err).Error("unable to parse community rules")

			continue
		}

		for _, d := range commDetections {
			d.IsCommunity = true
		}

		errMap, err := e.syncCommunityDetections(ctx, commDetections, true, allSettings)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of suricata community detections due to module stopping")
				break
			}

			if err.Error() == "Object not found" {
				// errMap contains exactly 1 error: the publicId of the detection that
				// was written to but not read back
				for publicId := range errMap {
					writeNoRead = util.Ptr(publicId)
				}
			}

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "error",
				})
			}

			log.WithError(err).Error("unable to sync suricata community detections")

			continue
		}

		detections.WriteStateFile(e.IOManager, e.stateFilePath)
		lastSyncSuccess = util.Ptr(true)

		if len(errMap) > 0 {
			// there were errors, don't save the fingerprint.
			// idempotency means we might fix it if we try again later.
			log.WithFields(log.Fields{
				"suricataSyncErrors": errMap,
			}).Error("unable to sync all community detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "partial",
				})
			}
		} else {
			err = os.WriteFile(e.rulesFingerprintFile, []byte(hash), 0644)
			if err != nil {
				log.WithError(err).WithField("repoPath", e.rulesFingerprintFile).Error("unable to write rules fingerprint file")
			}

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameSuricata,
					Status: "success",
				})
			}

			err = e.IntegrityCheck(false)

			e.EngineState.IntegrityFailure = err != nil
			lastSyncSuccess = util.Ptr(err == nil)

			if err != nil {
				log.WithError(err).Error("post-sync integrity check failed")
			} else {
				log.Info("post-sync integrity check passed")
			}
		}

		dur := time.Since(start)

		log.WithFields(log.Fields{
			"durationSeconds": dur.Seconds(),
		}).Info("suricata community rules sync finished")

		checkMigrationsOnce()
	}
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

func readAndHash(path string) (content string, sha256Hash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	hasher := sha256.New()
	data := io.TeeReader(f, hasher)

	raw, err := io.ReadAll(data)
	if err != nil {
		return "", "", err
	}

	return string(raw), hex.EncodeToString(hasher.Sum(nil)), nil
}

func readFingerprint(path string) (fingerprint *string, ok bool, err error) {
	_, err = os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}

		return nil, false, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	fingerprint = util.Ptr(strings.TrimSpace(string(raw)))

	return fingerprint, true, nil
}

func (e *SuricataEngine) ValidateRule(rule string) (string, error) {
	parsed, err := ParseSuricataRule(rule)
	if err != nil {
		return rule, err
	}

	return parsed.String(), nil
}

func (e *SuricataEngine) ParseRules(content string, ruleset string, applyFilters bool) ([]*model.Detection, error) {
	// expecting one rule per line
	lines := strings.Split(content, "\n")
	dets := []*model.Detection{}

	for i, line := range lines {
		if !e.isRunning {
			return nil, errModuleStopped
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

		if applyFilters {
			if e.denyRegex != nil && e.denyRegex.MatchString(line) {
				log.WithField("suricataDenyRegex", line).Debug("content matched suricata's denyRegex")
				continue
			}

			if e.allowRegex != nil && !e.allowRegex.MatchString(line) {
				log.WithField("suricataAllowRegex", line).Debug("content didn't match suricata's allowRegex")
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

func (e *SuricataEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	allSettings, err := e.srv.Configstore.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	localDets := []*model.Detection{}
	communityDets := []*model.Detection{}

	for _, detect := range detections {
		if detect.IsCommunity {
			communityDets = append(communityDets, detect)
		} else {
			localDets = append(localDets, detect)
		}
	}

	errMap = map[string]string{} // map[sid]error

	if len(communityDets) != 0 {
		eMap, err := e.syncCommunityDetections(ctx, communityDets, false, allSettings)
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
			return nil, errModuleStopped
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
		localLines = updateLocal(localLines, localIndex, sid, detect)

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

func updateLocal(localLines []string, localIndex map[string]int, sid string, detect *model.Detection) []string {
	lineNum, inLocal := localIndex[sid]
	if !inLocal {
		if detect.IsEnabled {
			// not in local, but should be
			localLines = append(localLines, detect.Content)
			lineNum = len(localLines) - 1
			localIndex[sid] = lineNum
		}
	} else {
		// in local...
		if detect.IsEnabled {
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
	remove := !detect.IsEnabled && !isFlowbits

	line := detect.PublicID
	if remove {
		line = ""
	}

	if !inEnabled {
		enabledLines = append(enabledLines, line)
		lineNum = len(enabledLines) - 1
		enabledIndex[sid] = lineNum
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
	if detect.IsEnabled {
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

	line := fmt.Sprintf("%s %s %s", detect.PublicID, *override.Regex, *override.Value)

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
	if !isFlowbits {
		lineNum, inDisabled := disabledIndex[sid]

		line := detect.PublicID
		if detect.IsEnabled {
			line = ""
		}

		if !inDisabled {
			disabledLines = append(disabledLines, line)
			lineNum = len(disabledLines) - 1
			disabledIndex[sid] = lineNum
		} else {
			disabledLines[lineNum] = line
			if detect.IsEnabled {
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

	if !inModify {
		// not in the modify file, but should be
		modifyLines = append(modifyLines, line)
		lineNum = len(modifyLines) - 1
		modifyIndex[sid] = lineNum
	} else {
		// in modify, but should be updated
		modifyLines[lineNum] = line
	}

	return modifyLines
}

func updateThreshold(thresholdIndex map[string][]*model.Override, genID int, detect *model.Detection) {
	delete(thresholdIndex, detect.PublicID)
	detOverrides := lo.Filter(detect.Overrides, func(o *model.Override, _ int) bool {
		return o.IsEnabled
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

func (e *SuricataEngine) syncCommunityDetections(ctx context.Context, detects []*model.Detection, deleteUnreferenced bool, allSettings []*model.Setting) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()
	errMap = map[string]string{}

	changedByUser := web.IsChangedByUser(ctx)

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
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

	commSIDs, err := e.srv.Detectionstore.GetAllDetections(ctx, util.Ptr(model.EngineNameSuricata), nil, util.Ptr(true))
	if err != nil {
		return nil, err
	}

	toDelete := map[string]struct{}{}
	for sid := range commSIDs {
		toDelete[sid] = struct{}{}
	}

	et := detections.NewErrorTracker(e.failAfterConsecutiveErrorCount)

	for _, detect := range detects {
		if !e.isRunning {
			return nil, errModuleStopped
		}

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

		_, inEnabled := enabledIndex[sid]
		_, inDisabled := disabledIndex[sid]

		if changedByUser || inEnabled || inDisabled {
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

		if exists {
			if orig.Content != detect.Content || orig.Ruleset != detect.Ruleset || len(detect.Overrides) != 0 || orig.IsEnabled != detect.IsEnabled {
				detect.Kind = ""

				_, err = e.srv.Detectionstore.UpdateDetection(ctx, detect)
				if err != nil {
					if err.Error() == "Object not found" {
						errMap = map[string]string{
							detect.PublicID: "Object not found",
						}

						return errMap, err
					}

					errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
				} else {
					results.Updated++
					delete(toDelete, detect.PublicID)
				}

				err = et.AddError(err)
				if err != nil {
					return errMap, err
				}
			} else {
				results.Unchanged++
				delete(toDelete, detect.PublicID)
			}
		} else {
			_, err = e.srv.Detectionstore.CreateDetection(ctx, detect)
			if err != nil {
				if err.Error() == "Object not found" {
					errMap = map[string]string{
						detect.PublicID: err.Error(),
					}

					return errMap, err
				}

				errMap[detect.PublicID] = fmt.Sprintf("unable to create detection; reason=%s", err.Error())
			} else {
				results.Added++
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
				return nil, errModuleStopped
			}

			removeFromIndex(enabledLines, enabledIndex, sid)
			removeFromIndex(disabledLines, disabledIndex, sid)
			removeFromIndex(modifyLines, modifyIndex, sid)
			delete(thresholdIndex, sid)

			_, err = e.srv.Detectionstore.DeleteDetection(ctx, commSIDs[sid].Id)
			if err != nil {
				errMap[sid] = fmt.Sprintf("unable to delete detection; reason=%s", err.Error())
			} else {
				results.Removed++
			}
		}
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

	log.WithFields(log.Fields{
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

func (e *SuricataEngine) generateUnusedPublicId(ctx context.Context) (string, error) {
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
	id, err := e.generateUnusedPublicId(ctx)
	if err != nil {
		return nil, err
	}

	rule, err := ParseSuricataRule(detection.Content)
	if err != nil {
		return nil, err
	}

	rule.UpdateForDuplication(id)

	dets, err := e.ParseRules(rule.String(), detections.RULESET_CUSTOM, false)
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

	return det, nil
}

func (e *SuricataEngine) IntegrityCheck(canInterrupt bool) error {
	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return detections.ErrIntCheckerStopped
	}

	logger := log.WithFields(log.Fields{
		"detectionEngine": model.EngineNameSuricata,
		"intCheckId":      uuid.New().String(),
	})

	allSettings, err := e.srv.Configstore.GetSettings(e.srv.Context)
	if err != nil {
		return err
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return detections.ErrIntCheckerStopped
	}

	commRules, err := e.ReadFile(e.communityRulesFile)
	if err != nil {
		logger.WithError(err).WithField("path", e.communityRulesFile).Error("unable to read community rules file")
		return err
	}

	local := settingByID(allSettings, "idstools.rules.local__rules")
	if local == nil {
		return fmt.Errorf("unable to find local rules setting")
	}

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	if disabled == nil {
		return fmt.Errorf("unable to find disabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return fmt.Errorf("unable to find modify setting")
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return detections.ErrIntCheckerStopped
	}

	// unpack settings into lines/indices
	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")
	rulesLines := strings.Split(local.Value, "\n")
	rulesLines = append(rulesLines, strings.Split(string(commRules), "\n")...)

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
		return detections.ErrIntCheckerStopped
	}

	deployed := consolidateEnabled(rulesIndex, disabledIndex)

	logger.WithField("deployedPublicIdsCount", len(deployed)).Debug("deployed sids")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return detections.ErrIntCheckerStopped
	}

	ret, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, util.Ptr(model.EngineNameSuricata), util.Ptr(true), util.Ptr(true))
	if err != nil {
		logger.WithError(err).Error("unable to query for enabled detections")
		return detections.ErrIntCheckFailed
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return detections.ErrIntCheckerStopped
	}

	enabled := make([]string, 0, len(ret))
	for _, d := range ret {
		enabled = append(enabled, d.PublicID)
	}

	logger.WithField("enabledDetectionsCount", len(enabled)).Debug("enabled detections")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return detections.ErrIntCheckerStopped
	}

	deployedButNotEnabled, enabledButNotDeployed, _ := detections.DiffLists(deployed, enabled)

	logger.WithFields(log.Fields{
		"deployedButNotEnabled": deployedButNotEnabled,
		"enabledButNotDeployed": enabledButNotDeployed,
	}).Info("integrity check report")

	if len(deployedButNotEnabled) > 0 || len(enabledButNotDeployed) > 0 {
		logger.Info("integrity check failed")
		return detections.ErrIntCheckFailed
	}

	logger.Info("integrity check passed")

	return nil
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

// go install go.uber.org/mock/mockgen@latest
//go:generate mockgen -destination mock/mock_iomanager.go -package mock . IOManager

type ResourceManager struct{}

func (_ *ResourceManager) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (_ *ResourceManager) WriteFile(path string, contents []byte, perm fs.FileMode) error {
	return os.WriteFile(path, contents, perm)
}

func (_ *ResourceManager) DeleteFile(path string) error {
	return os.Remove(path)
}

func (_ *ResourceManager) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}
