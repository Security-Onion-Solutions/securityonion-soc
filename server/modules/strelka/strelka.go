// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const (
	DEFAULT_ALLOW_REGEX                              = ""
	DEFAULT_DENY_REGEX                               = ""
	DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECONDS = 86400
	DEFAULT_YARA_RULES_FOLDER                        = "/opt/sensoroni/yara/rules"
	DEFAULT_REPOS_FOLDER                             = "/opt/sensoroni/yara/repos"
	DEFAULT_COMPILE_YARA_PYTHON_SCRIPT_PATH          = "/opt/so/conf/strelka/compile_yara.py"
	DEFAULT_COMPILE_RULES                            = true
	DEFAULT_STATE_FILE_PATH                          = "/opt/sensoroni/fingerprints/strelkaengine.state"
	DEFAULT_AUTO_ENABLED_YARA_RULES                  = "securityonion-yara"
	DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS        = 300
	DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT       = 10
	DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS        = 600
)

var titleUpdater = regexp.MustCompile(`(?i)rule\s+(\w+)(\s+:(\s*[^{]+))?(\s+){`)
var nameValidator = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`) // alphanumeric + underscore, can't start with a number

type StrelkaEngine struct {
	srv                            *server.Server
	isRunning                      bool
	interm                         sync.Mutex
	failAfterConsecutiveErrorCount int
	yaraRulesFolder                string
	reposFolder                    string
	autoEnabledYaraRules           []string
	rulesRepos                     []*model.RuleRepo
	compileYaraPythonScriptPath    string
	allowRegex                     *regexp.Regexp
	denyRegex                      *regexp.Regexp
	notify                         bool
	writeNoRead                    *string
	detections.SyncSchedulerParams
	detections.IntegrityCheckerData
	detections.IOManager
	model.EngineState
}

func checkRulesetEnabled(e *StrelkaEngine, det *model.Detection) {
	det.IsEnabled = false

	for _, rule := range e.autoEnabledYaraRules {
		if strings.EqualFold(rule, det.Ruleset) {
			det.IsEnabled = true
			break
		}
	}
}

func NewStrelkaEngine(srv *server.Server) *StrelkaEngine {
	return &StrelkaEngine{
		srv:       srv,
		IOManager: &detections.ResourceManager{Config: srv.Config},
	}
}

func (e *StrelkaEngine) PrerequisiteModules() []string {
	return nil
}

func (e *StrelkaEngine) GetState() *model.EngineState {
	return util.Ptr(e.EngineState)
}

func (e *StrelkaEngine) Init(config module.ModuleConfig) (err error) {
	e.SyncThread = &sync.WaitGroup{}
	e.InterruptChan = make(chan bool, 1)
	e.IntegrityCheckerData.Thread = &sync.WaitGroup{}
	e.IntegrityCheckerData.Interrupt = make(chan bool, 1)

	e.CommunityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", DEFAULT_COMMUNITY_RULES_IMPORT_FREQUENCY_SECONDS)
	e.yaraRulesFolder = module.GetStringDefault(config, "yaraRulesFolder", DEFAULT_YARA_RULES_FOLDER)
	e.reposFolder = module.GetStringDefault(config, "reposFolder", DEFAULT_REPOS_FOLDER)
	e.compileYaraPythonScriptPath = module.GetStringDefault(config, "compileYaraPythonScriptPath", DEFAULT_COMPILE_YARA_PYTHON_SCRIPT_PATH)
	e.autoEnabledYaraRules = module.GetStringArrayDefault(config, "autoEnabledYaraRules", []string{DEFAULT_AUTO_ENABLED_YARA_RULES})
	e.CommunityRulesImportErrorSeconds = module.GetIntDefault(config, "communityRulesImportErrorSeconds", DEFAULT_COMMUNITY_RULES_IMPORT_ERROR_SECS)
	e.failAfterConsecutiveErrorCount = module.GetIntDefault(config, "failAfterConsecutiveErrorCount", DEFAULT_FAIL_AFTER_CONSECUTIVE_ERROR_COUNT)
	e.IntegrityCheckerData.FrequencySeconds = module.GetIntDefault(config, "integrityCheckFrequencySeconds", DEFAULT_INTEGRITY_CHECK_FREQUENCY_SECONDS)

	e.rulesRepos, err = model.GetReposDefault(config, "rulesRepos", []*model.RuleRepo{
		{
			Repo:    "https://github.com/Security-Onion-Solutions/securityonion-yara",
			License: "DRL",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to parse Strelka's rulesRepos: %w", err)
	}

	allow := module.GetStringDefault(config, "allowRegex", DEFAULT_ALLOW_REGEX)
	deny := module.GetStringDefault(config, "denyRegex", DEFAULT_DENY_REGEX)

	if allow != "" {
		e.allowRegex, err = regexp.Compile(allow)
		if err != nil {
			return fmt.Errorf("unable to compile Strelka's allowRegex: %w", err)
		}
	}

	if deny != "" {
		var err error
		e.denyRegex, err = regexp.Compile(deny)
		if err != nil {
			return fmt.Errorf("unable to compile Strelka's denyRegex: %w", err)
		}
	}

	e.StateFilePath = module.GetStringDefault(config, "stateFilePath", DEFAULT_STATE_FILE_PATH)

	return nil
}

func (e *StrelkaEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameStrelka] = e
	e.isRunning = true

	go detections.SyncScheduler(e, &e.SyncSchedulerParams, &e.EngineState, model.EngineNameStrelka, &e.isRunning, e.IOManager)
	go detections.IntegrityChecker(model.EngineNameStrelka, e, &e.IntegrityCheckerData, &e.EngineState.IntegrityFailure)

	return nil
}

func (e *StrelkaEngine) Stop() error {
	e.isRunning = false
	e.InterruptSync(false, false)
	e.SyncThread.Wait()
	e.PauseIntegrityChecker()
	e.interruptIntegrityCheck()
	e.IntegrityCheckerData.Thread.Wait()

	return nil
}

func (e *StrelkaEngine) InterruptSync(fullUpgrade bool, notify bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = notify

	if len(e.InterruptChan) == 0 {
		e.InterruptChan <- fullUpgrade
	}
}

func (e *StrelkaEngine) resetInterrupt() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.InterruptChan) != 0 {
		<-e.InterruptChan
	}
}

func (e *StrelkaEngine) interruptIntegrityCheck() {
	e.interm.Lock()
	defer e.interm.Unlock()

	if len(e.IntegrityCheckerData.Interrupt) == 0 {
		e.IntegrityCheckerData.Interrupt <- true
	}
}

func (e *StrelkaEngine) PauseIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = false
}

func (e *StrelkaEngine) ResumeIntegrityChecker() {
	e.IntegrityCheckerData.IsRunning = true
}

func (e *StrelkaEngine) IsRunning() bool {
	return e.isRunning
}

func (e *StrelkaEngine) ValidateRule(data string) (string, error) {
	_, err := e.parseYaraRules([]byte(data), false)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *StrelkaEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (s *StrelkaEngine) ExtractDetails(detect *model.Detection) error {
	rules, err := s.parseYaraRules([]byte(detect.Content), false)
	if err != nil {
		return err
	}

	rule := rules[0]

	if rule.Identifier != "" {
		detect.Title = rule.Identifier
	} else {
		detect.Title = "Detection title not yet provided - click here to update this title"
	}

	if rule.Meta.Description != nil {
		detect.Description = *rule.Meta.Description
	}

	detect.Severity = model.SeverityUnknown
	detect.PublicID = detect.Title
	if rule.Meta.Author != nil {
		detect.Author = *rule.Meta.Author
	}

	return nil
}

func (e *StrelkaEngine) SyncLocalDetections(ctx context.Context, _ []*model.Detection) (errMap map[string]string, err error) {
	return nil, e.syncDetections(ctx)
}

func (e *StrelkaEngine) Sync(logger *log.Entry, forceSync bool) error {
	defer func() {
		e.resetInterrupt()
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

	e.EngineState.Syncing = true

	// ensure repos are up to date
	allRepos, anythingNew, err := detections.UpdateRepos(&e.isRunning, e.reposFolder, e.rulesRepos, e.srv.Config, e.IOManager)
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			return err
		}
	}

	if !anythingNew && !forceSync {
		// no updates, skip
		logger.Info("community rule sync found no changes")

		detections.WriteStateFile(e.IOManager, e.StateFilePath)

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameStrelka,
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

		// a non-forceSync sync that found no changes is a success
		return nil
	}

	if !e.isRunning {
		return detections.ErrModuleStopped
	}

	communityDetections, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameStrelka), model.WithCommunity(true))
	if err != nil {
		logger.WithError(err).Error("failed to get all community SIDs")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameStrelka,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	if !e.isRunning {
		return detections.ErrModuleStopped
	}

	toDelete := map[string]struct{}{}
	for pid := range communityDetections {
		toDelete[pid] = struct{}{}
	}

	et := detections.NewErrorTracker(e.failAfterConsecutiveErrorCount)
	detects := []*model.Detection{}

	// parse *.yar files in repos
	for repopath, repo := range allRepos {
		if !e.isRunning {
			return detections.ErrModuleStopped
		}

		if !repo.WasModified && !forceSync {
			continue
		}

		baseDir := repo.Path
		if repo.Repo.Folder != nil {
			baseDir = filepath.Join(baseDir, *repo.Repo.Folder)
		}

		err = e.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.WithError(err).WithField("repoPath", path).Error("failed to walk path")
				return nil
			}

			if !e.isRunning {
				return detections.ErrModuleStopped
			}

			if d.IsDir() {
				return nil
			}

			ext := filepath.Ext(d.Name())
			if strings.ToLower(ext) != ".yar" {
				return nil
			}

			raw, err := e.ReadFile(path)
			if err != nil {
				logger.WithError(err).WithField("yaraRuleFile", path).Error("failed to read yara rule file")
				return nil
			}

			parsed, err := e.parseYaraRules(raw, true)
			if err != nil {
				logger.WithError(err).WithField("yaraRuleFile", path).Error("failed to parse yara rule file")
				return nil
			}

			for _, rule := range parsed {
				det := rule.ToDetection(repo.Repo.License, filepath.Base(repo.Path), repo.Repo.Community)
				detects = append(detects, det)
			}

			return nil
		})
		if err != nil {
			logger.WithError(err).WithField("strelkaRepo", repopath).Error("failed while walking repo")

			continue
		}
	}

	if !e.isRunning {
		return detections.ErrModuleStopped
	}

	var eterr error
	detects = detections.DeduplicateByPublicId(detects)

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
	}{}

	for _, det := range detects {
		if !e.isRunning {
			return detections.ErrModuleStopped
		}

		logger.WithFields(log.Fields{
			"rule.uuid": det.PublicID,
			"rule.name": det.Title,
		}).Info("syncing YARA detection")

		comRule, exists := communityDetections[det.PublicID]
		if exists {
			if comRule.Content != det.Content || comRule.Ruleset != det.Ruleset || len(det.Overrides) != 0 {
				// pre-existing detection, update it
				det.IsEnabled = comRule.IsEnabled
				det.Id = comRule.Id
				det.Overrides = comRule.Overrides
				det.CreateTime = comRule.CreateTime

				logger.WithFields(log.Fields{
					"rule.uuid": det.PublicID,
					"rule.name": det.Title,
				}).Info("updating YARA detection")

				_, err = e.srv.Detectionstore.UpdateDetection(e.srv.Context, det)
				if err != nil && err.Error() == "Object not found" {
					e.writeNoRead = util.Ptr(det.PublicID)
					logger.WithField("publicId", det.PublicID).Error("unable to read back successful write")

					break
				}

				eterr = et.AddError(err)
				if eterr != nil {
					break
				}

				if err != nil {
					logger.WithError(err).WithField("publicId", det.PublicID).Error("failed to update detection")
					continue
				}

				results.Updated++
			} else {
				results.Unchanged++
			}

			delete(toDelete, det.PublicID)
		} else {
			// new detection, create it
			logger.WithFields(log.Fields{
				"rule.uuid": det.PublicID,
				"rule.name": det.Title,
			}).Info("creating new YARA detection")

			checkRulesetEnabled(e, det)

			_, err = e.srv.Detectionstore.CreateDetection(e.srv.Context, det)
			if err != nil && err.Error() == "Object not found" {
				e.writeNoRead = util.Ptr(det.PublicID)
				logger.WithField("publicId", det.PublicID).Error("unable to read back successful write")

				break
			}

			eterr = et.AddError(err)
			if eterr != nil {
				break
			}

			if err != nil {
				logger.WithError(err).WithField("publicId", det.PublicID).Error("failed to create detection")
				continue
			}

			delete(toDelete, det.PublicID)
			results.Added++
		}
	}

	if eterr != nil || e.writeNoRead != nil {
		if eterr != nil {
			logger.WithError(eterr).Error("unable to sync YARA community detections")
		}
		if e.writeNoRead != nil {
			logger.Warn("detection was written but not read back, attempting read before continuing")
		}

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameElastAlert,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	for publicId := range toDelete {
		if !e.isRunning {
			break
		}

		_, err = e.srv.Detectionstore.DeleteDetection(e.srv.Context, communityDetections[publicId].Id)
		if err != nil {
			logger.WithError(err).WithField("publicId", publicId).Error("Failed to delete unreferenced community detection")
			continue
		}

		results.Removed++
	}

	err = e.syncDetections(e.srv.Context)
	if err != nil {
		if errors.Is(err, detections.ErrModuleStopped) {
			logger.Info("incomplete sync of YARA community detections due to module stopping")
			return err
		}

		log.WithError(err).Error("unable to sync YARA community detections")

		if e.notify {
			e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
				Engine: model.EngineNameStrelka,
				Status: "error",
			})
		}

		return detections.ErrSyncFailed
	}

	detections.WriteStateFile(e.IOManager, e.StateFilePath)

	if e.notify {
		e.srv.Host.Broadcast("detection-sync", "detections", server.SyncStatus{
			Engine: model.EngineNameStrelka,
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

	logger.WithFields(log.Fields{
		"syncAdded":     results.Added,
		"syncUpdated":   results.Updated,
		"syncRemoved":   results.Removed,
		"syncUnchanged": results.Unchanged,
	}).Info("strelka community diff")

	return nil
}

func (e *StrelkaEngine) parseYaraRules(data []byte, filter bool) ([]*YaraRule, error) {
	rules := []*YaraRule{}
	rule := &YaraRule{}

	state := parseStateImportsID

	raw := string(data)
	buffer := bytes.NewBuffer([]byte{})
	last := ' '
	curCommentType := ' '                      // either '/' or '*' if in a comment, ' ' if not in comment
	curHeader := ""                            // meta, strings, condition, or empty if not yet in a section
	curQuotes := ' '                           // either ' or " if in a string, ' ' if not in a string
	fileImports := map[string]*regexp.Regexp{} // every import in the file paired with it's regex

	for i, r := range raw {
		rule.Src += string(r)

		if r == '\r' {
			continue
		}

		if (curCommentType == '*' && last == '*' && r == '/') ||
			(curCommentType == '/' && r == '\n') {
			curCommentType = ' '

			if last == '*' {
				last = r
				continue
			}
		}

		if last == '/' && (curQuotes == ' ' || curQuotes == '/') && curCommentType == ' ' {
			if r == '/' {
				curQuotes = ' '
				curCommentType = '/'
				if buffer.Len() != 0 {
					buffer.Truncate(buffer.Len() - 1)
				}
			} else if r == '*' {
				curCommentType = '*'
				if buffer.Len() != 0 {
					buffer.Truncate(buffer.Len() - 1)
				}
			}
		}

		if curCommentType != ' ' {
			// in a comment, skip everything
			last = r
			continue
		}

	reevaluateState:
		switch state {
		case parseStateImportsID:
			switch r {
			case '\n':
				// is this an import?
				buf := buffer.String() // expected: `import "foo"`
				if strings.HasPrefix(buf, "import ") {
					buf = strings.TrimSpace(strings.TrimPrefix(buf, "import "))
					buf = strings.Trim(buf, `"`)

					rule.Imports = append(rule.Imports, buf)
					fileImports[buf] = buildImportChecker(buf)

					buffer.Reset()
				}
			case '{':
				buf := strings.TrimSpace(buffer.String()) // expected: `rule foo {` or `private rule foo\n{`

				if strings.HasPrefix(buf, "private ") {
					rule.IsPrivate = true
					buf = strings.TrimSpace(strings.TrimPrefix(buf, "private"))
				}

				if strings.HasPrefix(strings.ToLower(buf), "rule") {
					buf = strings.TrimSpace(buf[4:])
				}

				if strings.Contains(buf, ":") {
					// gets rid of inheritance?
					// rule This : That {...} becomes "This"
					parts := strings.SplitN(buf, ":", 2)
					buf = strings.TrimSpace(parts[0])
				}

				if !nameValidator.MatchString(buf) {
					return nil, fmt.Errorf("unexpected character in rule identifier around %d", i)
				}

				if buf != "" {
					rule.Identifier = buf
				} else {
					return nil, fmt.Errorf("expected rule identifier at %d", i)
				}

				buffer.Reset()

				state = parseStateWatchForHeader
			default:
				buffer.WriteRune(r)
			}
		case parseStateWatchForHeader:
			buf := strings.TrimSpace(buffer.String())
			if r == '\n' && len(buf) != 0 && buf[len(buf)-1] == ':' {
				curHeader = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(buf, ":")))
				buffer.Reset()

				if curHeader != "meta" &&
					curHeader != "strings" &&
					curHeader != "condition" {
					return nil, fmt.Errorf("unexpected header at %d: %s", i, curHeader)
				}

				state = parseStateInSection
			} else {
				buffer.WriteRune(r)
			}
		case parseStateInSection:
			if r == '\n' {
				buf := strings.TrimSpace(buffer.String())
				if len(buf) != 0 && buf[len(buf)-1] == ':' && !strings.HasPrefix(buf, "for ") {
					// found a header, new section
					state = parseStateWatchForHeader
					goto reevaluateState
				} else {
					if buf != "" {
						switch curHeader {
						case "meta":
							parts := strings.SplitN(buf, "=", 2)
							if len(parts) != 2 {
								return nil, fmt.Errorf("invalid meta line at %d: %s", i, buf)
							}

							key := strings.TrimSpace(parts[0])
							value := strings.TrimSpace(parts[1])

							rule.Meta.Set(key, value)
						case "strings":
							rule.Strings = append(rule.Strings, buf)
						case "condition":
							rule.Condition = strings.TrimSpace(rule.Condition + " " + buf)
						}
					}

					buffer.Reset()
				}
			} else if r == '}' && len(strings.TrimSpace(buffer.String())) == 0 && curQuotes != '}' {
				// end of rule
				rule.Src = strings.TrimSpace(rule.Src)
				keep := true

				if filter && e.denyRegex != nil && e.denyRegex.MatchString(rule.Src) {
					log.WithField("ruleIdentifier", rule.Identifier).Debug("content matched Strelka's denyRegex")
					keep = false
				}

				if filter && e.allowRegex != nil && !e.allowRegex.MatchString(rule.Src) {
					log.WithField("ruleIdentifier", rule.Identifier).Debug("content didn't match Strelka's allowRegex")
					keep = false
				}

				if keep {
					addMissingImports(rule, fileImports)
					rules = append(rules, rule)
				}

				buffer.Reset()

				state = parseStateImportsID
				curHeader = ""
				curQuotes = ' '
				rule = &YaraRule{}
			} else {
				buffer.WriteRune(r)
				if (r == '\'' || r == '"' || r == '{' || r == '/') && last != '\\' && curQuotes == ' ' {
					// starting a string
					if r == '{' {
						curQuotes = '}'
					} else {
						curQuotes = r
					}
				} else if curQuotes != ' ' && r == curQuotes && last != '\\' {
					// ending a string
					curQuotes = ' '
				}
			}
		}

		if (r == '\\' || r == '/') && last == '\\' && curQuotes != ' ' {
			// this is an escaped slash in the middle of a string,
			// so we need to remove the previous slash so it's not
			// mistaken for an escape character in case this is the
			// last character in the string
			last = ' '
		} else {
			last = r
		}
	}

	if state != parseStateImportsID || len(strings.TrimSpace(buffer.String())) != 0 {
		return nil, errors.New("unexpected end of rule")
	}

	return rules, nil
}

func addMissingImports(rule *YaraRule, imports map[string]*regexp.Regexp) {
	newImports := []string{}

	for pkg, finder := range imports {
		hasImport := slices.Contains(rule.Imports, pkg)
		if !hasImport {
			usesImport := finder.MatchString(rule.Src)
			if usesImport {
				rule.Imports = append(rule.Imports, pkg)
				newImports = append(newImports, fmt.Sprintf("import \"%s\"", pkg))
			}
		}
	}

	if len(newImports) != 0 {
		rule.Src = fmt.Sprintf("%s\n\n%s", strings.Join(newImports, "\n"), rule.Src)
	}
}

// buildImportChecker builds a regex looking for the use of a package in an use case
// other than the import statement.
func buildImportChecker(pkg string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`[^"]\b%s\b[^"]`, pkg))
}

func (e *StrelkaEngine) syncDetections(ctx context.Context) (err error) {
	results, err := e.srv.Detectionstore.GetAllDetections(ctx, model.WithEngine(model.EngineNameStrelka), model.WithEnabled(true))
	if err != nil {
		return err
	}

	enabledDetections := map[string]*model.Detection{}
	for pid, det := range results {
		if !e.isRunning {
			return detections.ErrModuleStopped
		}

		_, exists := enabledDetections[pid]
		if exists {
			return fmt.Errorf("duplicate detection with public ID %s", pid)
		}
		enabledDetections[pid] = det
	}

	// Clear existing .yar files in the directory
	files, err := e.ReadDir(e.yaraRulesFolder)
	if err != nil {
		return fmt.Errorf("failed to read directory: %v", err)
	}

	deleteByExt := map[string]struct{}{
		".yar":      {},
		".compiled": {},
	}

	for _, file := range files {
		_, ok := deleteByExt[strings.ToLower(filepath.Ext(file.Name()))]
		if ok {
			err := e.DeleteFile(filepath.Join(e.yaraRulesFolder, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to delete existing .yar file %s: %v", file.Name(), err)
			}
		}
	}

	// Process and write new .yar files
	for publicId, det := range enabledDetections {
		filename := filepath.Join(e.yaraRulesFolder, fmt.Sprintf("%s.yar", publicId))

		err := e.WriteFile(filename, []byte(det.Content), 0644)
		if err != nil {
			return fmt.Errorf("failed to write file for detection %s: %v", publicId, err)
		}
	}

	// compile yara rules, call even if no yara rules
	cmd := exec.CommandContext(ctx, "python3", e.compileYaraPythonScriptPath, e.yaraRulesFolder)

	raw, code, dur, err := e.ExecCommand(cmd)

	log.WithFields(log.Fields{
		"yaraCommand":  cmd.String(),
		"yaraOutput":   string(raw),
		"yaraCode":     code,
		"yaraExecTime": dur.Seconds(),
		"yaraError":    err,
	}).Info("yara compilation results")

	if err != nil {
		return err
	}

	return nil
}

func (e *StrelkaEngine) DuplicateDetection(ctx context.Context, detection *model.Detection) (*model.Detection, error) {
	rules, err := e.parseYaraRules([]byte(detection.Content), false)
	if err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("unable to parse rule")
	}

	rule := rules[0]

	rule.Src = titleUpdater.ReplaceAllString(rule.Src, "rule ${1}_copy${2}${4}{")

	det := rule.ToDetection(detection.License, detections.RULESET_CUSTOM, false)

	err = e.ExtractDetails(det)
	if err != nil {
		return nil, err
	}

	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	user, err := e.srv.Userstore.GetUserById(ctx, userID)
	if err != nil {
		return nil, err
	}

	det.Author = detections.AddUser(det.Author, user, "; ")

	return det, nil
}

func (e *StrelkaEngine) GenerateUnusedPublicId(ctx context.Context) (string, error) {
	// PublicIDs for Strelka are the rule name which should correlate with what the rule does.
	// Cannot generate arbitrary but still useful public IDs
	return "", fmt.Errorf("not implemented")
}

func (e *StrelkaEngine) IntegrityCheck(canInterrupt bool, logger *log.Entry) (deployedButNotEnabled []string, enabledButNotDeployed []string, err error) {
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

	// get deployed
	report, err := e.getCompilationReport()
	if err != nil {
		logger.WithError(err).Error("unable to get compilation report")
		return nil, nil, detections.ErrIntCheckFailed
	}

	err = e.verifyCompiledHash(report.CompiledRulesHash)
	if err != nil {
		logger.WithError(err).Error("compiled rules hash mismatch, this report is not for the latest compiled rules")
		return nil, nil, detections.ErrIntCheckFailed
	}

	logger.WithFields(log.Fields{
		"successfullyDeployed": len(report.Success),
		"failedToDeploy":       len(report.Failure),
		"rulesCount":           len(report.Success) + len(report.Failure),
		"lastDeployed":         report.Timestamp,
		"compiledHash":         report.CompiledRulesHash,
	}).Debug("deployed rules")

	if len(report.Failure) > 0 {
		problemSample := report.Failure
		if len(report.Failure) > 5 {
			problemSample = report.Failure[:5]
		}

		logger.WithField("failedPublicIDs", problemSample).Error("integrity check failed because some rules failed to deploy")

		return nil, nil, detections.ErrIntCheckFailed
	}

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	deployed := getDeployed(report)

	// escape
	if canInterrupt && !e.IntegrityCheckerData.IsRunning {
		return nil, nil, detections.ErrIntCheckerStopped
	}

	ret, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameStrelka), model.WithEnabled(true))
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
		"deployedButNotEnabled": deployedButNotEnabled,
		"enabledButNotDeployed": enabledButNotDeployed,
	})

	if len(deployedButNotEnabled) > 0 || len(enabledButNotDeployed) > 0 {
		intCheckReport.Warn("integrity check failed")
		return deployedButNotEnabled, enabledButNotDeployed, detections.ErrIntCheckFailed
	}

	intCheckReport.Info("integrity check passed")

	return deployedButNotEnabled, enabledButNotDeployed, nil
}

func (e *StrelkaEngine) getCompilationReport() (*model.CompilationReport, error) {
	path := "/opt/so/state/detections_yara_compilation-total.log"

	raw, err := e.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read compilation report: %w", err)
	}

	report := &model.CompilationReport{}

	err = json.Unmarshal(raw, &report)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal compilation report: %w", err)
	}

	return report, nil
}

func (e *StrelkaEngine) verifyCompiledHash(hash string) error {
	path := "/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled"

	raw, err := e.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && hash == "" {
			// there were no enabled rules
			return nil
		}

		return fmt.Errorf("failed to read compiled rules: %w", err)
	}

	hashed := sha256.Sum256(raw)

	actual := hex.EncodeToString(hashed[:])

	// don't need subtle, we're not comparing passwords
	if !strings.EqualFold(actual, hash) {
		return fmt.Errorf("compiled rules hash mismatch: expected %s, got %s", hash, actual)
	}

	return nil
}

func getDeployed(report *model.CompilationReport) []string {
	return append(report.Success, report.Failure...)
}
