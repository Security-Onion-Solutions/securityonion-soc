// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/kennygrant/sanitize"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

var errModuleStopped = fmt.Errorf("elastalert module has stopped running")

const (
	DEFAULT_AIRGAP_BASE_PATH                         = "/nsm/rules/detect-sigma/rulesets/"
	DEFAULT_ALLOW_REGEX                              = ""
	DEFAULT_DENY_REGEX                               = ""
	DEFAULT_AIRGAP_ENABLED                           = false
	DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECONDS = 86400
	DEFAULT_SIGMA_PACKAGE_DOWNLOAD_TEMPLATE          = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_%s.zip"
	DEFAULT_ELASTALERT_RULES_FOLDER                  = "/opt/sensoroni/elastalert"
	DEFAULT_RULES_FINGERPRINT_FILE                   = "/opt/sensoroni/fingerprints/sigma.fingerprint"
	DEFAULT_SIGMA_PIPELINES_FINGERPRINT_FILE         = "/opt/sensoroni/fingerprints/sigma.pipelines.fingerprint"
	DEFAULT_SIGMA_PIPELINE_FINAL_FILE                = "/opt/sensoroni/sigma_final_pipeline.yaml"
	DEFAULT_SIGMA_PIPELINE_SO_FILE                   = "/opt/sensoroni/sigma_so_pipeline.yaml"
	DEFAULT_REPOS_FOLDER                             = "/opt/sensoroni/sigma/repos"
	DEFAULT_STATE_FILE_PATH                          = "/opt/sensoroni/fingerprints/elastalertengine.state"
	DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS        = 300
	DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT       = 10
	DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS        = 600
)

var acceptedExtensions = map[string]bool{
	".yml":  true,
	".yaml": true,
}

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
	ReadDir(path string) ([]os.DirEntry, error)
	MakeRequest(*http.Request) (*http.Response, error)
	ExecCommand(cmd *exec.Cmd) ([]byte, int, time.Duration, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
}

type ElastAlertEngine struct {
	srv                                  *server.Server
	airgapBasePath                       string
	communityRulesImportFrequencySeconds int
	communityRulesImportErrorSeconds     int
	failAfterConsecutiveErrorCount       int
	sigmaPackageDownloadTemplate         string
	elastAlertRulesFolder                string
	rulesFingerprintFile                 string
	sigmaPipelineFinal                   string
	sigmaPipelineSO                      string
	sigmaPipelinesFingerprintFile        string
	sigmaRulePackages                    []string
	autoEnabledSigmaRules                []string
	additionalAlerters                   []string
	rulesRepos                           []*model.RuleRepo
	reposFolder                          string
	isRunning                            bool
	syncThread                           *sync.WaitGroup
	interruptSync                        chan bool
	interm                               sync.Mutex
	allowRegex                           *regexp.Regexp
	denyRegex                            *regexp.Regexp
	airgapEnabled                        bool
	notify                               bool
	stateFilePath                        string
	detections.IntegrityCheckerData
	model.EngineState
	IOManager
}

func checkRulesetEnabled(e *ElastAlertEngine, det *model.Detection) {
	det.IsEnabled = false
	if det.Ruleset == "" || det.Severity == "" {
		return
	}

	// Combine Ruleset and Severity into a single string
	metaCombined := det.Ruleset + "+" + string(det.Severity)
	for _, rule := range e.autoEnabledSigmaRules {
		if strings.EqualFold(rule, metaCombined) {
			det.IsEnabled = true
			break
		}
	}
}

func NewElastAlertEngine(srv *server.Server) *ElastAlertEngine {
	engine := &ElastAlertEngine{
		srv: srv,
	}

	resMan := &ResourceManager{Engine: engine}
	engine.IOManager = resMan

	return engine
}

func (e *ElastAlertEngine) PrerequisiteModules() []string {
	return nil
}

func (e *ElastAlertEngine) GetState() *model.EngineState {
	return util.Ptr(e.EngineState)
}

func (e *ElastAlertEngine) Init(config module.ModuleConfig) (err error) {
	e.syncThread = &sync.WaitGroup{}
	e.interruptSync = make(chan bool, 1)
	e.IntegrityCheckerData.Thread = &sync.WaitGroup{}
	e.IntegrityCheckerData.Interrupt = make(chan bool, 1)

	e.airgapBasePath = module.GetStringDefault(config, "airgapBasePath", DEFAULT_AIRGAP_BASE_PATH)
	e.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECONDS)
	e.sigmaPackageDownloadTemplate = module.GetStringDefault(config, "sigmaPackageDownloadTemplate", DEFAULT_SIGMA_PACKAGE_DOWNLOAD_TEMPLATE)
	e.elastAlertRulesFolder = module.GetStringDefault(config, "elastAlertRulesFolder", DEFAULT_ELASTALERT_RULES_FOLDER)
	e.sigmaPipelineFinal = module.GetStringDefault(config, "sigmaPipelineFinal", DEFAULT_SIGMA_PIPELINE_FINAL_FILE)
	e.sigmaPipelineSO = module.GetStringDefault(config, "sigmaPipelineSO", DEFAULT_SIGMA_PIPELINE_SO_FILE)
	e.sigmaPipelinesFingerprintFile = module.GetStringDefault(config, "sigmaPipelinesFingerprintFile", DEFAULT_SIGMA_PIPELINES_FINGERPRINT_FILE)
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", DEFAULT_RULES_FINGERPRINT_FILE)
	e.autoEnabledSigmaRules = module.GetStringArrayDefault(config, "autoEnabledSigmaRules", []string{"securityonion-resources+critical", "securityonion-resources+high"})
	e.communityRulesImportErrorSeconds = module.GetIntDefault(config, "communityRulesImportErrorSeconds", DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS)
	e.failAfterConsecutiveErrorCount = module.GetIntDefault(config, "failAfterConsecutiveErrorCount", DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT)
	e.additionalAlerters = module.GetStringArrayDefault(config, "additionalAlerters", []string{})
	e.IntegrityCheckerData.FrequencySeconds = module.GetIntDefault(config, "integrityCheckFrequencySeconds", DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS)

	pkgs := module.GetStringArrayDefault(config, "sigmaRulePackages", []string{"core", "emerging_threats_addon"})
	e.parseSigmaPackages(pkgs)

	e.reposFolder = module.GetStringDefault(config, "reposFolder", DEFAULT_REPOS_FOLDER)
	e.rulesRepos, err = model.GetReposDefault(config, "rulesRepos", []*model.RuleRepo{
		{
			Repo:    "https://github.com/Security-Onion-Solutions/securityonion-resources",
			License: "DRL",
			Folder:  util.Ptr("sigma/stable"),
		},
	})
	if err != nil {
		return fmt.Errorf("unable to parse ElastAlert's rulesRepos: %w", err)
	}

	if e.srv != nil && e.srv.Config != nil {
		e.airgapEnabled = e.srv.Config.AirgapEnabled
	} else {
		e.airgapEnabled = DEFAULT_AIRGAP_ENABLED
	}

	allow := module.GetStringDefault(config, "allowRegex", DEFAULT_ALLOW_REGEX)
	deny := module.GetStringDefault(config, "denyRegex", DEFAULT_DENY_REGEX)

	if allow != "" {
		var err error
		e.allowRegex, err = regexp.Compile(allow)
		if err != nil {
			return fmt.Errorf("unable to compile ElastAlert's allowRegex: %w", err)
		}
	}

	if deny != "" {
		var err error
		e.denyRegex, err = regexp.Compile(deny)
		if err != nil {
			return fmt.Errorf("unable to compile ElastAlert's denyRegex: %w", err)
		}
	}

	e.stateFilePath = module.GetStringDefault(config, "stateFilePath", DEFAULT_STATE_FILE_PATH)

	return nil
}

func (e *ElastAlertEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameElastAlert] = e
	e.isRunning = true
	e.IntegrityCheckerData.IsRunning = true

	go e.startCommunityRuleImport()
	go detections.IntegrityChecker(model.EngineNameElastAlert, e, &e.IntegrityCheckerData, &e.EngineState.IntegrityFailure)

	return nil
}

func (e *ElastAlertEngine) Stop() error {
	e.isRunning = false

	e.InterruptSync(false, false)
	e.syncThread.Wait()
	e.pauseIntegrityChecker()
	e.interruptIntegrityCheck()
	e.IntegrityCheckerData.Thread.Wait()

	return nil
}

func (e *ElastAlertEngine) InterruptSync(fullUpgrade bool, notify bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = notify

	if len(e.interruptSync) == 0 {
		e.interruptSync <- fullUpgrade
	}
}

func (e *ElastAlertEngine) resetInterruptSync() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.interruptSync) != 0 {
		<-e.interruptSync
	}
}

func (e *ElastAlertEngine) interruptIntegrityCheck() {
	e.interm.Lock()
	defer e.interm.Unlock()

	if len(e.IntegrityCheckerData.Interrupt) == 0 {
		e.IntegrityCheckerData.Interrupt <- true
	}
}

func (e *ElastAlertEngine) pauseIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = false
}

func (e *ElastAlertEngine) resumeIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = true
}

func (e *ElastAlertEngine) IsRunning() bool {
	return e.isRunning
}

func (e *ElastAlertEngine) ValidateRule(data string) (string, error) {
	_, err := ParseElastAlertRule([]byte(data))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *ElastAlertEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
	return e.sigmaToElastAlert(ctx, detect)
}

func (e *ElastAlertEngine) ExtractDetails(detect *model.Detection) error {
	rule, err := ParseElastAlertRule([]byte(detect.Content))
	if err != nil {
		return err
	}

	if rule.ID != nil {
		detect.PublicID = *rule.ID
	}

	if detect.PublicID == "" {
		return fmt.Errorf("rule does not contain a public Id")
	}

	if rule.Description != nil {
		detect.Description = *rule.Description
	}

	if rule.LogSource.Category != nil {
		detect.Category = *rule.LogSource.Category
	}

	if rule.LogSource.Product != nil {
		detect.Product = *rule.LogSource.Product
	}

	if rule.LogSource.Service != nil {
		detect.Service = *rule.LogSource.Service
	}

	if rule.Level != nil {
		switch strings.ToLower(string(*rule.Level)) {
		case "informational":
			detect.Severity = model.SeverityInformational
		case "low":
			detect.Severity = model.SeverityLow
		case "medium":
			detect.Severity = model.SeverityMedium
		case "high":
			detect.Severity = model.SeverityHigh
		case "critical":
			detect.Severity = model.SeverityCritical
		default:
			detect.Severity = model.SeverityUnknown
		}
	} else {
		detect.Severity = model.SeverityUnknown
	}

	if rule.Title != "" {
		detect.Title = rule.Title
	} else {
		detect.Title = "Detection title not yet provided - click here to update this title"
	}

	if rule.Author != nil {
		detect.Author = *rule.Author
	}

	return nil
}

func (e *ElastAlertEngine) parseSigmaPackages(pkgs []string) {
	set := map[string]struct{}{}

	for _, pkg := range pkgs {
		pkg = strings.ToLower(strings.TrimSpace(pkg))
		switch pkg {
		case "all":
			set["all_rules"] = struct{}{}
		case "emerging_threats":
			set["emerging_threats_addon"] = struct{}{}
		case "core++", "core+", "core", "emerging_threats_addon", "all_rules":
			if pkg != "" {
				set[pkg] = struct{}{}
			}
		}
	}

	_, ok := set["all_rules"]
	if ok {
		delete(set, "core++")
		delete(set, "core+")
		delete(set, "core")
		delete(set, "emerging_threats_addon")
	}

	_, ok = set["core++"]
	if ok {
		delete(set, "core+")
		delete(set, "core")
	}

	_, ok = set["core+"]
	if ok {
		delete(set, "core")
	}

	e.sigmaRulePackages = make([]string, 0, len(set))
	for pkg := range set {
		e.sigmaRulePackages = append(e.sigmaRulePackages, pkg)
	}
}

func (e *ElastAlertEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	errMap = map[string]string{} // map[publicID]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	index, err := e.IndexExistingRules()
	if err != nil {
		return nil, fmt.Errorf("unable to index existing rules: %w", err)
	}

	for _, det := range detections {
		path := index[det.PublicID]
		if path == "" {
			name := sanitize.Name(det.PublicID)
			path = filepath.Join(e.elastAlertRulesFolder, fmt.Sprintf("%s.yml", name))
		}

		if det.IsEnabled {
			eaRule, err := e.sigmaToElastAlert(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Sprintf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			wrapped, err := wrapRule(det, eaRule, e.additionalAlerters)
			if err != nil {
				continue
			}

			err = e.WriteFile(path, []byte(wrapped), 0644)
			if err != nil {
				errMap[det.PublicID] = fmt.Sprintf("unable to write enabled detection file: %s", err)
				continue
			}
		} else {
			// was enabled, no longer is enabled: Disable
			err = e.DeleteFile(path)
			if err != nil && !os.IsNotExist(err) {
				errMap[det.PublicID] = fmt.Sprintf("unable to remove disabled detection file: %s", err)
				continue
			}
		}
	}

	return errMap, nil
}

func (e *ElastAlertEngine) startCommunityRuleImport() {
	e.syncThread.Add(1)
	defer func() {
		e.syncThread.Done()
		e.isRunning = false
	}()

	var err error

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

	lastImport, timerDur := detections.DetermineWaitTime(e.IOManager, e.stateFilePath, time.Duration(e.communityRulesImportFrequencySeconds)*time.Second)

	for e.isRunning {
		if lastImport == nil && lastSyncSuccess != nil && *lastSyncSuccess {
			now := uint64(time.Now().UnixMilli())
			lastImport = &now
		}

		e.EngineState.Syncing = false
		e.EngineState.Importing = lastImport == nil
		e.EngineState.Migrating = false
		e.EngineState.SyncFailure = lastSyncSuccess != nil && !*lastSyncSuccess

		e.resetInterruptSync()

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
		}).Info("waiting for next elastalert community rules sync")

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

		timerDur = time.Second * time.Duration(e.communityRulesImportFrequencySeconds)

		log.WithFields(log.Fields{
			"forceSync": forceSync,
		}).Info("syncing elastalert community rules")

		e.EngineState.Syncing = true

		start := time.Now()

		if !templateFound {
			exists, err := e.srv.Detectionstore.DoesTemplateExist(ctx, "so-detection")
			if err != nil {
				log.WithError(err).Error("unable to check for detection index template")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
						Engine: model.EngineNameElastAlert,
						Status: "error",
					})
				}

				continue
			}

			if !exists {
				log.Warn("detection index template does not exist, skipping import")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
						Engine: model.EngineNameElastAlert,
						Status: "error",
					})
				}

				continue
			}

			templateFound = true
		}

		var zips map[string][]byte
		var errMap map[string]error
		var regenNeeded bool
		var sigmaPipelineNewHash string

		// Check to see if the sigma processing pipelines have changed.
		// If they have, (later) set forceSync to true to regenerate the elastalert rule files.
		regenNeeded, sigmaPipelineNewHash, err = e.checkSigmaPipelines()
		if err != nil {
			log.WithField("sigmaPipelineError", err).Error("failed to check the sigma processing pipelines")
		} else {
			log.Info("successfully checked the sigma processing pipelines")
		}

		// If the system is Airgap, load the sigma packages from disk.
		// else, not Airgap, downoad the sigma packages.
		if e.airgapEnabled {
			zips, errMap = e.loadSigmaPackagesFromDisk()
		} else {
			zips, errMap = e.downloadSigmaPackages()
		}

		if len(errMap) != 0 {
			log.WithField("sigmaPackageErrors", errMap).Error("something went wrong loading sigma packages")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
					Status: "error",
				})
			}

			continue
		}

		dirtyRepos, repoChanges, err := detections.UpdateRepos(&e.isRunning, e.reposFolder, e.rulesRepos, e.srv.Config)
		if err != nil {
			if strings.Contains(err.Error(), "module stopped") {
				break
			}

			log.WithError(err).Error("unable to update Sigma repos")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
					Status: "error",
				})
			}

			continue
		}

		zipHashes := map[string]string{}
		for pkg, data := range zips {
			h := sha256.Sum256(data)
			zipHashes[pkg] = base64.StdEncoding.EncodeToString(h[:])
		}

		// If no import has been completed, or
		// elastalert rule files need to be regenerated -
		// then do a full sync.
		if lastImport == nil || regenNeeded {
			forceSync = true
		}

		if !forceSync {
			raw, err := e.ReadFile(e.rulesFingerprintFile)
			if err != nil && !os.IsNotExist(err) {
				log.WithError(err).WithField("fingerprintPath", e.rulesFingerprintFile).Error("unable to read rules fingerprint file")
				continue
			} else if err == nil {
				oldHashes := map[string]string{}

				err = json.Unmarshal(raw, &oldHashes)
				if err != nil {
					log.WithError(err).Error("unable to unmarshal rules fingerprint file")
					continue
				}

				if reflect.DeepEqual(oldHashes, zipHashes) && !repoChanges {
					// only an exact match means no work needs to be done.
					// If there's extra hashes in the old file, we need to remove them.
					// If there's extra hashes in the new file, we need to add them.
					// If there's a mix of new and old hashes, we need to include them all
					// or the old ones would be removed.
					log.Info("elastalert sync found no changes")

					detections.WriteStateFile(e.IOManager, e.stateFilePath)

					if e.notify {
						e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
							Engine: model.EngineNameElastAlert,
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

					continue
				}
			}
		}

		if !e.isRunning {
			break
		}

		detects, errMap := e.parseZipRules(zips)
		if errMap != nil {
			log.WithField("sigmaParseError", errMap).Error("something went wrong while parsing sigma rule files from zips")
		}

		if errMap["module"] == errModuleStopped || !e.isRunning {
			break
		}

		repoDets, errMap := e.parseRepoRules(dirtyRepos)
		if errMap != nil {
			log.WithField("sigmaParseError", errMap).Error("something went wrong while parsing sigma rule files from repos")
		}

		if errMap["module"] == errModuleStopped || !e.isRunning {
			break
		}

		detects = append(detects, repoDets...)

		detects = detections.DeduplicateByPublicId(detects)

		errMap, err = e.syncCommunityDetections(ctx, detects)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of elastalert community detections due to module stopping")
				return
			}

			if err.Error() == "Object not found" {
				// errMap contains exactly 1 error: the publicId of the detection that
				// was written to but not read back
				for publicId := range errMap {
					writeNoRead = util.Ptr(publicId)
				}
			}

			log.WithError(err).Error("unable to sync elastalert community detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
					Status: "error",
				})
			}

			continue
		}

		detections.WriteStateFile(e.IOManager, e.stateFilePath)
		lastSyncSuccess = util.Ptr(true)

		if len(errMap) > 0 {
			// there were errors, don't save the fingerprint.
			// idempotency means we might fix it if we try again later.
			log.WithFields(log.Fields{
				"elastAlertSyncErrors": detections.TruncateMap(errMap, 5),
			}).Error("unable to sync all ElastAlert community detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
					Status: "partial",
				})
			}
		} else {
			fingerprints, err := json.Marshal(zipHashes)
			if err != nil {
				log.WithError(err).Error("unable to marshal rules fingerprints")
			} else {
				err = e.WriteFile(e.rulesFingerprintFile, fingerprints, 0644)
				if err != nil {
					log.WithError(err).WithField("fingerprintPath", e.rulesFingerprintFile).Error("unable to write rules fingerprint file")
				}
			}

			// Now that a successful sync completed - if the sigma pipelines changed, write out the new sigma pipelines hash .
			if regenNeeded {
				err = e.WriteFile(e.sigmaPipelinesFingerprintFile, []byte(sigmaPipelineNewHash), 0644)
				if err != nil {
					log.WithError(err).WithField("fingerprintPath", e.sigmaPipelinesFingerprintFile).Error("unable to write sigma pipelines fingerprint file")
				} else {
					log.WithField("fingerprintPath", e.sigmaPipelinesFingerprintFile).Info("updated sigma pipelines fingerprint file")
				}

			}

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
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
		}).Info("elastalert community rules sync finished")
	}
}

func (e *ElastAlertEngine) checkSigmaPipelines() (bool, string, error) {
	// Hash the pipeline files
	hashFinal, err := e.hashFile(e.sigmaPipelineFinal)
	if err != nil {
		return false, "", fmt.Errorf("error hashing file %s: %w", e.sigmaPipelineFinal, err)
	}
	hashSO, err := e.hashFile(e.sigmaPipelineSO)
	if err != nil {
		return false, "", fmt.Errorf("error hashing file %s: %w", e.sigmaPipelineSO, err)
	}
	newHash := hashFinal + "-" + hashSO

	// Read the existing hash from the fingerprint file
	oldHash, err := e.ReadFile(e.sigmaPipelinesFingerprintFile)
	if err != nil && !os.IsNotExist(err) {
		return false, "", fmt.Errorf("error reading fingerprint file: %w", err)
	}

	// Compare hashes
	if string(oldHash) == newHash {
		log.Info("no changes to sigma processing pipeline")
		return false, "", nil
	}

	// If hashes do not match, the elastalert rules need to be regenerated
	log.Info("changes detected in sigma processing pipelines")

	return true, newHash, nil
}

func (e *ElastAlertEngine) hashFile(filePath string) (string, error) {
	data, err := e.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func (e *ElastAlertEngine) parseZipRules(pkgZips map[string][]byte) (detections []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName|fileName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for _, pkg := range e.sigmaRulePackages {
		if !e.isRunning {
			return nil, map[string]error{"module": errModuleStopped}
		}

		zipData := pkgZips[pkg]

		reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err != nil {
			errMap[pkg] = err
			continue
		}

		for _, file := range reader.File {
			if !e.isRunning {
				return nil, map[string]error{"module": errModuleStopped}
			}

			if file.FileInfo().IsDir() || !acceptedExtensions[strings.ToLower(filepath.Ext(file.Name))] {
				continue
			}

			f, err := file.Open()
			if err != nil {
				errMap[file.Name] = err
				continue
			}

			data, err := io.ReadAll(f)
			if err != nil {
				f.Close()
				errMap[file.Name] = err

				continue
			}

			f.Close()

			rule, err := ParseElastAlertRule(data)
			if err != nil {
				errMap[file.Name] = err
				continue
			}

			if e.denyRegex != nil && e.denyRegex.MatchString(string(data)) {
				log.WithField("elastAlertRuleFile", file.Name).Debug("content matched elastalert's denyRegex")
				continue
			}

			if e.allowRegex != nil && !e.allowRegex.MatchString(string(data)) {
				log.WithField("elastAlertRuleFile", file.Name).Debug("content didn't match elastalert's allowRegex")
				continue
			}

			det := rule.ToDetection(pkg, model.LicenseDRL, true)

			detections = append(detections, det)
		}
	}

	return detections, errMap
}

func (e *ElastAlertEngine) parseRepoRules(allRepos []*detections.RepoOnDisk) (detections []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[repoName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for _, repo := range allRepos {
		if !e.isRunning {
			return nil, map[string]error{"module": errModuleStopped}
		}

		baseDir := repo.Path
		if repo.Repo.Folder != nil {
			baseDir = filepath.Join(baseDir, *repo.Repo.Folder)
		}

		err := e.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.WithError(err).WithField("repoPath", path).Error("Failed to walk path")
				return nil
			}

			if !e.isRunning {
				return errModuleStopped
			}

			if d.IsDir() {
				return nil
			}

			ext := filepath.Ext(d.Name())
			if strings.ToLower(ext) != ".yml" && strings.ToLower(ext) != ".yaml" {
				return nil
			}

			raw, err := e.ReadFile(path)
			if err != nil {
				log.WithError(err).WithField("elastAlertRuleFile", path).Error("failed to read elastalert rule file")
				return nil
			}

			rule, err := ParseElastAlertRule(raw)
			if err != nil {
				errMap[path] = err
				return nil
			}

			ruleset := filepath.Base(repo.Path)

			det := rule.ToDetection(ruleset, repo.Repo.License, repo.Repo.Community)

			detections = append(detections, det)

			return nil
		})
		if err != nil {
			log.WithError(err).WithField("elastAlertRuleRepo", repo.Path).Error("Failed to walk repo")
			continue
		}
	}

	return detections, errMap
}

func (e *ElastAlertEngine) syncCommunityDetections(ctx context.Context, detects []*model.Detection) (errMap map[string]error, err error) {
	existing, err := e.IndexExistingRules()
	if err != nil {
		return nil, err
	}

	community, err := e.srv.Detectionstore.GetAllDetections(ctx, model.WithEngine(model.EngineNameElastAlert), model.WithCommunity(true))
	if err != nil {
		return nil, err
	}

	index := map[string]string{}
	toDelete := map[string]struct{}{} // map[publicID]struct{}
	for _, det := range community {
		toDelete[det.PublicID] = struct{}{}

		path, ok := existing[det.PublicID]
		if ok {
			index[det.PublicID] = path
		}
	}

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
	}{}

	errMap = map[string]error{} // map[publicID]error
	et := detections.NewErrorTracker(e.failAfterConsecutiveErrorCount)

	for _, det := range detects {
		if !e.isRunning {
			return nil, errModuleStopped
		}

		path, ok := index[det.PublicID]
		if !ok {
			path = index[det.Title]
		}

		// 1. Save sigma Detection to ElasticSearch
		oldDet, exists := community[det.PublicID]
		if exists {
			det.IsEnabled = oldDet.IsEnabled
			det.Id = oldDet.Id
			det.Overrides = oldDet.Overrides
			det.CreateTime = oldDet.CreateTime

			if oldDet.Content != det.Content || oldDet.Ruleset != det.Ruleset || len(det.Overrides) != 0 {
				_, err = e.srv.Detectionstore.UpdateDetection(ctx, det)
				if err != nil && err.Error() == "Object not found" {
					errMap = map[string]error{
						det.PublicID: err,
					}

					return errMap, err
				}

				eterr := et.AddError(err)
				if eterr != nil {
					return nil, eterr
				}

				if err != nil {
					errMap[det.PublicID] = fmt.Errorf("unable to update detection: %s", err)
					continue
				}

				results.Updated++
			} else {
				results.Unchanged++
			}

			delete(toDelete, det.PublicID)
		} else {
			checkRulesetEnabled(e, det)

			_, err = e.srv.Detectionstore.CreateDetection(ctx, det)
			if err != nil && err.Error() == "Object not found" {
				errMap = map[string]error{
					det.PublicID: err,
				}

				return errMap, err
			}

			eterr := et.AddError(err)
			if eterr != nil {
				return nil, eterr
			}

			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to create detection: %s", err)
				continue
			}

			delete(toDelete, det.PublicID)
			results.Added++
		}

		if det.IsEnabled {
			// 2. if enabled, send data to cli package to get converted to query
			rule, err := e.sigmaToElastAlert(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			rule, err = wrapRule(det, rule, e.additionalAlerters)
			if err != nil {
				continue
			}

			// 3. put query in elastAlertRulesFolder for salt to pick up
			if path == "" {
				name := sanitize.Name(det.PublicID)
				path = filepath.Join(e.elastAlertRulesFolder, fmt.Sprintf("%s.yml", name))
			}

			err = e.WriteFile(path, []byte(rule), 0644)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to write enabled detection file: %s", err)
				continue
			}
		} else if path != "" {
			// detection is disabled but a file exists, remove it
			err = e.DeleteFile(path)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to remove disabled detection file: %s", err)
				continue
			}
		}
	}

	for publicId := range toDelete {
		if !e.isRunning {
			return nil, errModuleStopped
		}

		_, err = e.srv.Detectionstore.DeleteDetection(ctx, community[publicId].Id)
		if err != nil {
			errMap[publicId] = fmt.Errorf("unable to delete detection: %s", err)
			continue
		}

		results.Removed++
	}

	log.WithFields(log.Fields{
		"elastAlertSyncadded":     results.Added,
		"elastAlertSyncupdated":   results.Updated,
		"elastAlertSyncremoved":   results.Removed,
		"elastAlertSyncunchanged": results.Unchanged,
		"elastAlertSyncerrors":    detections.TruncateMap(errMap, 5),
	}).Info("elastalert community diff")

	return errMap, nil
}

func (e *ElastAlertEngine) loadSigmaPackagesFromDisk() (zipData map[string][]byte, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	zipData = map[string][]byte{}
	stats := map[string]int{}

	for _, pkg := range e.sigmaRulePackages {
		filePath := filepath.Join(e.airgapBasePath, "sigma_"+pkg+".zip")

		data, err := e.ReadFile(filePath)
		if err != nil {
			errMap[pkg] = err
			continue
		}

		zipData[pkg] = data
		stats[pkg] = len(data)
	}

	log.WithField("packageSizes", stats).Info("loaded sigma packages from disk")

	return zipData, errMap
}

func (e *ElastAlertEngine) downloadSigmaPackages() (zipData map[string][]byte, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	stats := map[string]int{} // map[pkgName]fileSize
	zipData = map[string][]byte{}

	for _, pkg := range e.sigmaRulePackages {
		download := fmt.Sprintf(e.sigmaPackageDownloadTemplate, pkg)

		req, err := http.NewRequest(http.MethodGet, download, nil)
		if err != nil {
			errMap[pkg] = err
			continue
		}

		resp, err := e.MakeRequest(req)
		if err != nil {
			errMap[pkg] = err
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			errMap[pkg] = fmt.Errorf("non-200 status code during download: %d", resp.StatusCode)
			continue
		}

		zipData[pkg], err = io.ReadAll(resp.Body)
		if err != nil {
			errMap[pkg] = err
			continue
		}

		stats[pkg] = len(zipData[pkg])
	}

	log.WithField("downloadSizes", stats).Info("downloaded sigma packages")

	return zipData, errMap
}

// IndexExistingRules maps the publicID of a detection to the path of the rule file.
// Note that it indexes ALL rules and not just community rules.
func (e *ElastAlertEngine) IndexExistingRules() (index map[string]string, err error) {
	index = map[string]string{} // map[id | title]path

	rules, err := e.ReadDir(e.elastAlertRulesFolder)
	if err != nil {
		return nil, fmt.Errorf("unable to read elastalert rules directory: %w", err)
	}

	for _, rule := range rules {
		if rule.IsDir() {
			continue
		}

		filename := filepath.Join(e.elastAlertRulesFolder, rule.Name())

		ext := filepath.Ext(rule.Name())
		if !acceptedExtensions[strings.ToLower(ext)] {
			continue
		}

		id := strings.TrimSuffix(rule.Name(), ext)

		index[id] = filename
	}

	return index, nil
}

func (e *ElastAlertEngine) sigmaToElastAlert(ctx context.Context, det *model.Detection) (string, error) {
	rule := det.Content

	filters := lo.Filter(det.Overrides, func(item *model.Override, _ int) bool {
		return item.Type == model.OverrideTypeCustomFilter && item.IsEnabled
	})

	// apply overrides
	if len(filters) > 0 {
		doc := map[string]interface{}{}

		err := yaml.Unmarshal([]byte(rule), &doc)
		if err != nil {
			return "", fmt.Errorf("unable to unmarshal sigma rule: %w", err)
		}

		detection := doc["detection"].(map[string]interface{})
		if detection == nil {
			return "", fmt.Errorf("sigma rule does not contain a detection section")
		}

		for _, f := range filters {
			o, err := f.PrepareForSigma()
			if err != nil {
				return "", fmt.Errorf("unable to marshal filter: %w", err)
			}

			for k, v := range o {
				detection[k] = v
			}
		}

		condition := detection["condition"].(string)
		detection["condition"] = fmt.Sprintf("(%s) and not 1 of sofilter*", condition)

		raw, err := yaml.Marshal(doc)
		if err != nil {
			return "", fmt.Errorf("unable to marshal sigma rule with overrides: %w", err)
		}

		rule = string(raw)
	}

	args := []string{"convert", "-t", "eql", "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "/dev/stdin"}

	cmd := exec.CommandContext(ctx, "sigma", args...)
	cmd.Stdin = strings.NewReader(rule)

	raw, code, runtime, err := e.ExecCommand(cmd)

	log.WithFields(log.Fields{
		"sigmaConvertCode":     code,
		"sigmaConvertOutput":   string(raw),
		"sigmaConvertCommand":  cmd.String(),
		"sigmaConvertExecTime": runtime.Seconds(),
		"sigmaConvertError":    err,
	}).Info("executing sigma cli")

	if err != nil {
		return "", fmt.Errorf("problem with sigma cli: %w", err)
	}

	query := string(raw)

	firstLine := strings.Index(string(raw), "\n")
	if firstLine != -1 {
		query = query[firstLine+1:]
	}

	query = strings.TrimSpace(query)

	return query, nil
}

func (e *ElastAlertEngine) GenerateUnusedPublicId(ctx context.Context) (string, error) {
	id := uuid.New().String()

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

		id = uuid.New().String()
	}

	if i >= 10 {
		return "", fmt.Errorf("unable to generate a unique publicId")
	}

	return id, nil
}

func (e *ElastAlertEngine) DuplicateDetection(ctx context.Context, detection *model.Detection) (*model.Detection, error) {
	id, err := e.GenerateUnusedPublicId(ctx)
	if err != nil {
		return nil, err
	}

	rule, err := ParseElastAlertRule([]byte(detection.Content))
	if err != nil {
		return nil, err
	}

	rule.Title += " (copy)"
	rule.ID = &id

	det := rule.ToDetection(detections.RULESET_CUSTOM, detection.License, false)

	err = e.ExtractDetails(det)
	if err != nil {
		return nil, err
	}

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	user, err := e.srv.Userstore.GetUserById(ctx, userID)
	if err != nil {
		return nil, err
	}

	det.Author = detections.AddUser(det.Author, user, ", ")

	return det, nil
}

type CustomWrapper struct {
	DetectionTitle    string   `yaml:"detection_title"`
	DetectionPublicId string   `yaml:"detection_public_id"`
	SigmaCategory     string   `yaml:"sigma_category,omitempty"`
	SigmaProduct      string   `yaml:"sigma_product,omitempty"`
	SigmaService      string   `yaml:"sigma_service,omitempty"`
	EventModule       string   `yaml:"event.module"`
	EventDataset      string   `yaml:"event.dataset"`
	EventSeverity     int      `yaml:"event.severity"`
	SigmaLevel        string   `yaml:"sigma_level"`
	Alert             []string `yaml:"alert"`

	Index   string                   `yaml:"index"`
	Name    string                   `yaml:"name"`
	Realert *TimeFrame               `yaml:"realert,omitempty"` // or 0
	Type    string                   `yaml:"type"`
	Filter  []map[string]interface{} `yaml:"filter"`
}

type TimeFrame struct {
	Milliseconds *int    `yaml:"milliseconds,omitempty"`
	Seconds      *int    `yaml:"seconds,omitempty"`
	Minutes      *int    `yaml:"minutes,omitempty"`
	Hours        *int    `yaml:"hours,omitempty"`
	Days         *int    `yaml:"days,omitempty"`
	Weeks        *int    `yaml:"weeks,omitempty"`
	Schedule     *string `yaml:"schedule,omitempty"`
}

func (dur *TimeFrame) SetSeconds(s int) {
	dur.Milliseconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Seconds = util.Ptr(s)
}

func (dur *TimeFrame) SetMilliseconds(m int) {
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Milliseconds = util.Ptr(m)
}

func (dur *TimeFrame) SetMinutes(m int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Minutes = util.Ptr(m)
}

func (dur *TimeFrame) SetHours(h int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Hours = util.Ptr(h)
}

func (dur *TimeFrame) SetDays(d int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Weeks = nil
	dur.Schedule = nil
	dur.Days = util.Ptr(d)
}

func (dur *TimeFrame) SetWeeks(w int) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Schedule = nil
	dur.Weeks = util.Ptr(w)
}

func (dur *TimeFrame) SetSchedule(w string) {
	dur.Milliseconds = nil
	dur.Seconds = nil
	dur.Minutes = nil
	dur.Hours = nil
	dur.Days = nil
	dur.Weeks = nil
	dur.Schedule = util.Ptr(w)
}

func (dur TimeFrame) MarshalYAML() (interface{}, error) {
	if dur.Milliseconds == nil &&
		dur.Seconds == nil &&
		dur.Minutes == nil &&
		dur.Hours == nil &&
		dur.Days == nil &&
		dur.Weeks == nil &&
		dur.Schedule == nil {
		return 0, nil
	}

	type Alias TimeFrame

	return struct {
		Alias `yaml:",inline"`
	}{(Alias)(dur)}, nil
}

func (dur *TimeFrame) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var zero int

	err := unmarshal(&zero)
	if err == nil {
		return nil
	}

	type Alias *TimeFrame

	dur = &TimeFrame{}

	err = unmarshal(struct {
		A Alias `yaml:",inline"`
	}{(Alias)(dur)})

	return err
}

func wrapRule(det *model.Detection, rule string, additionalAlerters []string) (string, error) {
	severities := map[model.Severity]int{
		model.SeverityUnknown:       0,
		model.SeverityInformational: 1,
		model.SeverityLow:           2,
		model.SeverityMedium:        3,
		model.SeverityHigh:          4,
		model.SeverityCritical:      5,
	}

	sevNum := severities[det.Severity]
	realert := TimeFrame{}
	realert.SetSeconds(0)

	wrapper := &CustomWrapper{
		DetectionTitle:    det.Title,
		DetectionPublicId: det.PublicID,
		EventModule:       "sigma",
		EventDataset:      "sigma.alert",
		EventSeverity:     sevNum,
		SigmaCategory:     det.Category,
		SigmaService:      det.Service,
		SigmaProduct:      det.Product,
		SigmaLevel:        string(det.Severity),
		Alert:             []string{"modules.so.securityonion-es.SecurityOnionESAlerter"},
		Index:             ".ds-logs-*",
		Name:              fmt.Sprintf("%s -- %s", det.Title, det.PublicID),
		Realert:           &realert,
		Type:              "any",
		Filter:            []map[string]interface{}{{"eql": rule}},
	}

	if licensing.IsEnabled(licensing.FEAT_NTF) {
		// Add any custom alerters to the rule.
		for _, alerter := range additionalAlerters {
			alerter = strings.TrimSpace(alerter)
			if len(alerter) > 0 {
				wrapper.Alert = append(wrapper.Alert, alerter)
			}
		}
	}

	rawYaml, err := yaml.Marshal(wrapper)
	if err != nil {
		return "", err
	}

	return string(rawYaml), nil
}

func (e *ElastAlertEngine) IntegrityCheck(canInterrupt bool) error {
	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return detections.ErrIntCheckerStopped
	}

	logger := log.WithFields(log.Fields{
		"detectionEngine": model.EngineNameElastAlert,
		"intCheckId":      uuid.New().String(),
	})

	deployed, err := e.getDeployedPublicIds()
	if err != nil {
		logger.WithError(err).Error("unable to get deployed publicIds")
		return detections.ErrIntCheckFailed
	}

	logger.WithField("deployedPublicIdsCount", len(deployed)).Debug("deployed publicIds")

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		logger.Info("integrity checker stopped")
		return detections.ErrIntCheckerStopped
	}

	ret, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameElastAlert), model.WithEnabled(true))
	if err != nil {
		logger.WithError(err).Error("unable to query for enabled detections")
		return detections.ErrIntCheckFailed
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

func (e *ElastAlertEngine) getDeployedPublicIds() (publicIds []string, err error) {
	files, err := e.ReadDir(e.elastAlertRulesFolder)
	if err != nil {
		return nil, fmt.Errorf("unable to read elastalert rules folder: %w", err)
	}

	publicIds = make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		ext := filepath.Ext(file.Name())

		_, ok := acceptedExtensions[strings.ToLower(ext)]
		if !ok {
			continue
		}

		pid := strings.TrimSuffix(file.Name(), ext)
		publicIds = append(publicIds, pid)
	}

	return publicIds, nil
}

// go install go.uber.org/mock/mockgen@latest
//go:generate mockgen -destination mock/mock_iomanager.go -package mock . IOManager

type ResourceManager struct {
	Engine  *ElastAlertEngine
	_client *http.Client
}

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

func (resman *ResourceManager) MakeRequest(req *http.Request) (*http.Response, error) {
	if resman._client == nil {
		// cache for reuse, the config values can't change without a server restart
		resman._client = resman.buildHttpClient()
	}

	return resman._client.Do(req)
}

func (resman *ResourceManager) buildHttpClient() *http.Client {
	transport := &http.Transport{}

	if resman.Engine.srv.Config.Proxy != "" {
		p, err := url.Parse(resman.Engine.srv.Config.Proxy)
		if err != nil {
			log.WithError(err).WithField("proxy", resman.Engine.srv.Config.Proxy).Error("unable to parse proxy URL, not using proxy")
		} else {
			transport.Proxy = http.ProxyURL(p)
		}
	}

	if resman.Engine.srv.Config.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if resman.Engine.srv.Config.AdditionalCA != "" {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}

		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}

		pool.AppendCertsFromPEM([]byte(resman.Engine.srv.Config.AdditionalCA))

		transport.TLSClientConfig.RootCAs = pool
	}

	return &http.Client{Transport: transport}
}

func (_ *ResourceManager) ExecCommand(cmd *exec.Cmd) (output []byte, exitCode int, runtime time.Duration, err error) {
	start := time.Now()
	output, err = cmd.CombinedOutput()
	runtime = time.Since(start)

	exitCode = cmd.ProcessState.ExitCode()

	return output, exitCode, runtime, err
}

func (_ *ResourceManager) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, fn)
}
