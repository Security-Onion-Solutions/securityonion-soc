// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	mutil "github.com/security-onion-solutions/securityonion-soc/server/modules/util"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"gopkg.in/yaml.v3"
)

var errModuleStopped = fmt.Errorf("elastalert module has stopped running")

var acceptedExtensions = map[string]bool{
	".yml":  true,
	".yaml": true,
}

var socAuthor = "__soc_import__"

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
	communityRulesImportFrequencySeconds int
	sigmaPackageDownloadTemplate         string
	elastAlertRulesFolder                string
	rulesFingerprintFile                 string
	sigmaRulePackages                    []string
	autoEnabledSigmaRules                []string
	rulesRepos                           []*module.RuleRepo
	reposFolder                          string
	isRunning                            bool
	thread                               *sync.WaitGroup
	interrupt                            chan bool
	interm                               sync.Mutex
	allowRegex                           *regexp.Regexp
	denyRegex                            *regexp.Regexp
	autoUpdateEnabled                    bool
	notify                               bool
	stateFilePath                        string
	IOManager
}

func checkRulesetEnabled(e *ElastAlertEngine, det *model.Detection) {
	det.IsEnabled = false
	if det.Ruleset == nil || det.Severity == "" {
		return
	}

	// Combine Ruleset and Severity into a single string
	metaCombined := *det.Ruleset + "+" + string(det.Severity)
	for _, rule := range e.autoEnabledSigmaRules {
		if strings.EqualFold(rule, metaCombined) {
			det.IsEnabled = true
			break
		}
	}
}

func NewElastAlertEngine(srv *server.Server) *ElastAlertEngine {
	return &ElastAlertEngine{
		srv:       srv,
		IOManager: &ResourceManager{},
	}
}

func (e *ElastAlertEngine) PrerequisiteModules() []string {
	return nil
}

func (e *ElastAlertEngine) Init(config module.ModuleConfig) (err error) {
	e.thread = &sync.WaitGroup{}
	e.interrupt = make(chan bool, 1)

	e.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", 86400)
	e.sigmaPackageDownloadTemplate = module.GetStringDefault(config, "sigmaPackageDownloadTemplate", "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_%s.zip")
	e.elastAlertRulesFolder = module.GetStringDefault(config, "elastAlertRulesFolder", "/opt/sensoroni/elastalert")
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", "/opt/sensoroni/fingerprints/sigma.fingerprint")
	e.autoUpdateEnabled = module.GetBoolDefault(config, "autoUpdateEnabled", false)
	e.autoEnabledSigmaRules = module.GetStringArrayDefault(config, "autoEnabledSigmaRules", []string{"securityonion-resources+critical", "securityonion-resources+high"})

	pkgs := module.GetStringArrayDefault(config, "sigmaRulePackages", []string{"core", "emerging_threats_addon"})
	e.parseSigmaPackages(pkgs)

	e.reposFolder = module.GetStringDefault(config, "reposFolder", "/opt/sensoroni/sigma/repos")
	e.rulesRepos, err = module.GetReposDefault(config, "rulesRepos", []*module.RuleRepo{
		{
			Repo:    "https://github.com/Security-Onion-Solutions/securityonion-resources",
			License: "DRL",
			Folder:  util.Ptr("sigma/stable"),
		},
	})
	if err != nil {
		return fmt.Errorf("unable to parse ElastAlert's rulesRepos: %w", err)
	}

	allow := module.GetStringDefault(config, "allowRegex", "")
	deny := module.GetStringDefault(config, "denyRegex", "")

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

	e.stateFilePath = module.GetStringDefault(config, "stateFilePath", "/opt/sensoroni/fingerprints/elastalertengine.state")

	return nil
}

func (e *ElastAlertEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameElastAlert] = e
	e.isRunning = true

	go e.startCommunityRuleImport()

	return nil
}

func (e *ElastAlertEngine) Stop() error {
	e.isRunning = false
	e.InterruptSleep(false)
	e.thread.Wait()

	return nil
}

func (e *ElastAlertEngine) InterruptSleep(fullUpgrade bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = true

	if len(e.interrupt) == 0 {
		e.interrupt <- fullUpgrade
	}
}

func (e *ElastAlertEngine) resetInterrupt() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.interrupt) != 0 {
		<-e.interrupt
	}
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

	if detect.Description == "" && rule.Description != nil {
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
			path = filepath.Join(e.elastAlertRulesFolder, fmt.Sprintf("%s.yml", det.PublicID))
		}

		if det.IsEnabled {
			eaRule, err := e.sigmaToElastAlert(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Sprintf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			wrapped, err := wrapRule(det, eaRule)
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
	e.thread.Add(1)
	defer func() {
		e.thread.Done()
		e.isRunning = false
	}()

	var err error

	ctx := e.srv.Context
	templateFound := false

	timerDur := mutil.DetermineWaitTime(e.IOManager, e.stateFilePath, time.Duration(e.communityRulesImportFrequencySeconds)*time.Second)

	for e.isRunning {
		e.resetInterrupt()

		timer := time.NewTimer(timerDur)

		var forceSync bool

		select {
		case <-timer.C:
		case typ := <-e.interrupt:
			forceSync = typ
		}

		if !e.isRunning {
			break
		}

		timerDur = time.Second * time.Duration(e.communityRulesImportFrequencySeconds)

		log.WithFields(log.Fields{
			"forceSync": forceSync,
		}).Info("syncing elastalert community rules")

		start := time.Now()

		if !templateFound {
			exists, err := e.srv.Detectionstore.DoesTemplateExist(ctx, "so-detection")
			if err != nil {
				log.WithError(err).Error("unable to check for detection index template")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
						Engine: model.EngineNameElastAlert,
						Status: "error",
					})
				}

				continue
			}

			if !exists {
				log.Warn("detection index template does not exist, skipping import")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
						Engine: model.EngineNameElastAlert,
						Status: "error",
					})
				}

				continue
			}

			templateFound = true
		}

		allRepos := map[string]*module.RuleRepo{}
		var repoChanges bool

		var zips map[string][]byte
		var errMap map[string]error
		if e.autoUpdateEnabled {
			zips, errMap = e.downloadSigmaPackages()
			if len(errMap) != 0 {
				log.WithField("errorMap", errMap).Error("something went wrong downloading sigma packages")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
						Engine: model.EngineNameElastAlert,
						Status: "error",
					})
				}

				continue
			}

			var dirtyRepos map[string]*mutil.DirtyRepo

			dirtyRepos, repoChanges, err = mutil.UpdateRepos(&e.isRunning, e.reposFolder, e.rulesRepos)
			if err != nil {
				if strings.Contains(err.Error(), "module stopped") {
					break
				}

				log.WithError(err).Error("unable to update Sigma repos")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
						Engine: model.EngineNameElastAlert,
						Status: "error",
					})
				}

				continue
			}

			for k, v := range dirtyRepos {
				allRepos[k] = v.Repo
			}
		} else {
			// Possible airgap installation, or admin has disabled auto-updates.

			// TODO: Perform a one-time check for a pre-downloaded ruleset on disk and if exists,
			// let the rest of the loop continue but then exit the loop. For now we're just hardcoding
			// to always exit the loop.
			return
		}

		zipHashes := map[string]string{}
		for pkg, data := range zips {
			h := sha256.Sum256(data)
			zipHashes[pkg] = base64.StdEncoding.EncodeToString(h[:])
		}

		if !forceSync {
			raw, err := e.ReadFile(e.rulesFingerprintFile)
			if err != nil && !os.IsNotExist(err) {
				log.WithError(err).WithField("path", e.rulesFingerprintFile).Error("unable to read rules fingerprint file")
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
					log.Info("ElastAlert sync found no changes")

					mutil.WriteStateFile(e.IOManager, e.stateFilePath)

					if e.notify {
						e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
							Engine: model.EngineNameElastAlert,
							Status: "success",
						})
					}

					continue
				}
			}
		}

		if !e.isRunning {
			break
		}

		detections, errMap := e.parseZipRules(zips)
		if errMap != nil {
			log.WithField("error", errMap).Error("something went wrong while parsing sigma rule files from zips")
		}

		if errMap["module"] == errModuleStopped || !e.isRunning {
			break
		}

		repoDets, errMap := e.parseRepoRules(allRepos)
		if errMap != nil {
			log.WithField("error", errMap).Error("something went wrong while parsing sigma rule files from repos")
		}

		if errMap["module"] == errModuleStopped || !e.isRunning {
			break
		}

		detections = append(detections, repoDets...)

		errMap, err = e.syncCommunityDetections(ctx, detections)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of elastalert community detections due to module stopping")
				return
			}

			log.WithError(err).Error("unable to sync elastalert community detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
					Status: "error",
				})
			}

			continue
		}

		mutil.WriteStateFile(e.IOManager, e.stateFilePath)

		if len(errMap) > 0 {
			// there were errors, don't save the fingerprint.
			// idempotency means we might fix it if we try again later.
			log.WithFields(log.Fields{
				"errors": mutil.TruncateMap(errMap, 5),
			}).Error("unable to sync all ElastAlert community detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
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
					log.WithError(err).WithField("path", e.rulesFingerprintFile).Error("unable to write rules fingerprint file")
				}
			}

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameElastAlert,
					Status: "success",
				})
			}
		}

		dur := time.Since(start)

		log.WithFields(log.Fields{
			"durationSeconds": dur.Seconds(),
		}).Info("elastalert community rules sync finished")
	}
}

func (e *ElastAlertEngine) parseZipRules(pkgZips map[string][]byte) (detections []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName|fileName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for pkg, zipData := range pkgZips {
		if !e.isRunning {
			return nil, map[string]error{"module": errModuleStopped}
		}

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
				log.WithField("file", file.Name).Info("content matched ElastAlert's denyRegex")
				continue
			}

			if e.allowRegex != nil && !e.allowRegex.MatchString(string(data)) {
				log.WithField("file", file.Name).Info("content didn't match ElastAlert's allowRegex")
				continue
			}

			det := rule.ToDetection(string(data), pkg, model.LicenseDRL)

			detections = append(detections, det)
		}
	}

	return detections, errMap
}

func (e *ElastAlertEngine) parseRepoRules(allRepos map[string]*module.RuleRepo) (detections []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[repoName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for repopath, repo := range allRepos {
		if !e.isRunning {
			return nil, map[string]error{"module": errModuleStopped}
		}

		baseDir := repopath
		if repo.Folder != nil {
			baseDir = filepath.Join(baseDir, *repo.Folder)
		}

		err := e.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.WithError(err).WithField("path", path).Error("Failed to walk path")
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
				log.WithError(err).WithField("file", path).Error("failed to read yara rule file")
				return nil
			}

			rule, err := ParseElastAlertRule(raw)
			if err != nil {
				errMap[path] = err
				return nil
			}

			ruleset := filepath.Base(repopath)

			det := rule.ToDetection(string(raw), ruleset, repo.License)

			detections = append(detections, det)

			return nil
		})
		if err != nil {
			log.WithError(err).WithField("repo", repopath).Error("Failed to walk repo")
			continue
		}
	}

	return detections, errMap
}

func (e *ElastAlertEngine) syncCommunityDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]error, err error) {
	existing, err := e.IndexExistingRules()
	if err != nil {
		return nil, err
	}

	community, err := e.srv.Detectionstore.GetAllCommunitySIDs(ctx, util.Ptr(model.EngineNameElastAlert))
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

	// carry forward existing overrides
	for i := range detections {
		det := detections[i]

		comDet, exists := community[det.PublicID]
		if exists {
			det.Overrides = comDet.Overrides
		}
	}

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
	}{}

	errMap = map[string]error{} // map[publicID]error

	for _, det := range detections {
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

			if oldDet.Content != det.Content || !util.ComparePtrs(oldDet.Ruleset, det.Ruleset) || len(det.Overrides) != 0 {
				_, err = e.srv.Detectionstore.UpdateDetection(ctx, det)
				if err != nil {
					errMap[det.PublicID] = fmt.Errorf("unable to update detection: %s", err)
					continue
				}

				delete(toDelete, det.PublicID)
				results.Updated++
			} else {
				delete(toDelete, det.PublicID)
				results.Unchanged++
			}
		} else {

			checkRulesetEnabled(e, det)

			_, err = e.srv.Detectionstore.CreateDetection(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to create detection: %s", err)
				continue
			}

			delete(toDelete, det.PublicID)
			results.Added++
		}

		if det.IsEnabled {
			// 2. if enabled, send data to cli pakcage to get converted to query
			rule, err := e.sigmaToElastAlert(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			rule, err = wrapRule(det, rule)
			if err != nil {
				continue
			}

			// 3. put query in elastAlertRulesFolder for salt to pick up
			if path == "" {
				path = filepath.Join(e.elastAlertRulesFolder, fmt.Sprintf("%s.yml", det.PublicID))
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
		"added":     results.Added,
		"updated":   results.Updated,
		"removed":   results.Removed,
		"unchanged": results.Unchanged,
		"errors":    mutil.TruncateMap(errMap, 5),
	}).Info("elastalert community diff")

	return errMap, nil
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
		"code":     code,
		"output":   string(raw),
		"command":  cmd.String(),
		"execTime": runtime.Seconds(),
		"error":    err,
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

type CustomWrapper struct {
	PlayTitle     string   `yaml:"play_title"`
	PlayID        string   `yaml:"play_id"`
	EventModule   string   `yaml:"event.module"`
	EventDataset  string   `yaml:"event.dataset"`
	EventSeverity int      `yaml:"event.severity"`
	RuleCategory  string   `yaml:"rule.category"`
	SigmaLevel    string   `yaml:"sigma_level"`
	Alert         []string `yaml:"alert"`

	Index       string                   `yaml:"index"`
	Name        string                   `yaml:"name"`
	Realert     *TimeFrame               `yaml:"realert,omitempty"` // or 0
	Type        string                   `yaml:"type"`
	Filter      []map[string]interface{} `yaml:"filter"`
	PlayUrl     string                   `yaml:"play_url"`
	KibanaPivot string                   `yaml:"kibana_pivot"`
	SocPivot    string                   `yaml:"soc_pivot"`
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

func wrapRule(det *model.Detection, rule string) (string, error) {
	severities := map[model.Severity]int{
		model.SeverityUnknown:       0,
		model.SeverityInformational: 1,
		model.SeverityLow:           2,
		model.SeverityMedium:        3,
		model.SeverityHigh:          4,
		model.SeverityCritical:      5,
	}

	sevNum := severities[det.Severity]

	wrapper := &CustomWrapper{
		PlayTitle:     det.Title,
		PlayID:        det.Id,
		EventModule:   "sigma",
		EventDataset:  "sigma.alert",
		EventSeverity: sevNum,
		RuleCategory:  "", // TODO: what should this be?
		SigmaLevel:    string(det.Severity),
		Alert:         []string{"modules.so.playbook-es.PlaybookESAlerter"},
		Index:         ".ds-logs-*",
		Name:          fmt.Sprintf("%s - %s", det.Title, det.Id),
		Realert:       nil,
		Type:          "any",
		Filter: []map[string]interface{}{
			{
				"eql": rule,
			},
		},
		PlayUrl:     "play_url",
		KibanaPivot: "kibana_pivot",
		SocPivot:    "soc_pivot",
	}

	rawYaml, err := yaml.Marshal(wrapper)
	if err != nil {
		return "", err
	}

	return string(rawYaml), nil
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

func (_ *ResourceManager) MakeRequest(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
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
