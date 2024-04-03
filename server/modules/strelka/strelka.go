// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
)

var errModuleStopped = fmt.Errorf("strelka module has stopped running")

var socAuthor = "__soc_import__"

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
	ReadDir(path string) ([]os.DirEntry, error)
	MakeRequest(*http.Request) (*http.Response, error)
	ExecCommand(cmd *exec.Cmd) ([]byte, int, time.Duration, error)
}

type StrelkaEngine struct {
	srv                                  *server.Server
	isRunning                            bool
	thread                               *sync.WaitGroup
	interrupt                            chan bool
	interm                               sync.Mutex
	communityRulesImportFrequencySeconds int
	yaraRulesFolder                      string
	reposFolder                          string
	rulesRepos                           []*module.RuleRepo
	compileYaraPythonScriptPath          string
	allowRegex                           *regexp.Regexp
	denyRegex                            *regexp.Regexp
	compileRules                         bool
	autoUpdateEnabled                    bool
	notify                               bool
	stateFilePath                        string
	IOManager
}

func NewStrelkaEngine(srv *server.Server) *StrelkaEngine {
	return &StrelkaEngine{
		srv:       srv,
		IOManager: &ResourceManager{},
	}
}

func (e *StrelkaEngine) PrerequisiteModules() []string {
	return nil
}

func (e *StrelkaEngine) Init(config module.ModuleConfig) (err error) {
	e.thread = &sync.WaitGroup{}
	e.interrupt = make(chan bool, 1)

	e.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", 86400)
	e.yaraRulesFolder = module.GetStringDefault(config, "yaraRulesFolder", "/opt/sensoroni/yara/rules")
	e.reposFolder = module.GetStringDefault(config, "reposFolder", "/opt/sensoroni/yara/repos")
	e.compileYaraPythonScriptPath = module.GetStringDefault(config, "compileYaraPythonScriptPath", "/opt/so/conf/strelka/compile_yara.py")
	e.compileRules = module.GetBoolDefault(config, "compileRules", true)
	e.autoUpdateEnabled = module.GetBoolDefault(config, "autoUpdateEnabled", false)

	e.rulesRepos, err = module.GetReposDefault(config, "rulesRepos", []*module.RuleRepo{
		{
			Repo:    "https://github.com/Security-Onion-Solutions/securityonion-yara",
			License: "DRL",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to parse Strelka's rulesRepos: %w", err)
	}

	allow := module.GetStringDefault(config, "allowRegex", "")
	deny := module.GetStringDefault(config, "denyRegex", "")

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

	e.stateFilePath = module.GetStringDefault(config, "stateFilePath", "/opt/so/conf/soc/strelkaengine.state")

	return nil
}

func (e *StrelkaEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameStrelka] = e
	e.isRunning = true

	go e.startCommunityRuleImport()

	return nil
}

func (e *StrelkaEngine) Stop() error {
	e.isRunning = false
	e.InterruptSleep(false)
	e.thread.Wait()

	return nil
}

func (e *StrelkaEngine) InterruptSleep(fullUpgrade bool) {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = true

	if len(e.interrupt) == 0 {
		e.interrupt <- fullUpgrade
	}
}

func (e *StrelkaEngine) resetInterrupt() {
	e.interm.Lock()
	defer e.interm.Unlock()

	e.notify = false

	if len(e.interrupt) != 0 {
		<-e.interrupt
	}
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

func (s *StrelkaEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
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

	detect.Severity = model.SeverityUnknown
	detect.PublicID = rule.GetID()

	return nil
}

func (e *StrelkaEngine) SyncLocalDetections(ctx context.Context, _ []*model.Detection) (errMap map[string]string, err error) {
	return e.syncDetections(ctx)
}

func (e *StrelkaEngine) startCommunityRuleImport() {
	e.thread.Add(1)
	defer func() {
		e.thread.Done()
		e.isRunning = false
	}()

	templateFound := false

	lastImport, err := e.readStateFile()
	if err != nil {
		log.WithError(err).Error("unable to read state file, deleting it")

		err = e.DeleteFile(e.stateFilePath)
		if err != nil {
			log.WithError(err).WithField("path", e.stateFilePath).Error("unable to remove state file, ignoring it")
		}
	}

	timerDur := time.Second * time.Duration(e.communityRulesImportFrequencySeconds)

	if lastImport != nil {
		lastImportTime := time.Unix(int64(*lastImport), 0)
		nextImportTime := lastImportTime.Add(time.Second * time.Duration(e.communityRulesImportFrequencySeconds))

		timerDur = time.Until(nextImportTime)
	} else if err == nil {
		log.Info("no Strelka state file found, waiting 20 mins for first import")
		timerDur = time.Duration(time.Minute * 20)
	}

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
		}).Info("syncing strelka community rules")

		start := time.Now()

		if !templateFound {
			exists, err := e.srv.Detectionstore.DoesTemplateExist(e.srv.Context, "so-detection")
			if err != nil {
				log.WithError(err).Error("unable to check for detection index template")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
						Engine: model.EngineNameStrelka,
						Status: "error",
					})
				}

				continue
			}

			if !exists {
				log.Warn("detection index template does not exist, skipping import")

				if e.notify {
					e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
						Engine: model.EngineNameStrelka,
						Status: "error",
					})
				}

				continue
			}

			templateFound = true
		}

		// read existing repos
		entries, err := os.ReadDir(e.reposFolder)
		if err != nil {
			log.WithError(err).Error("Failed to read yara repos folder")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "error",
				})
			}

			continue
		}

		existingRepos := map[string]struct{}{}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			existingRepos[entry.Name()] = struct{}{}
		}

		upToDate := map[string]*module.RuleRepo{}

		if e.autoUpdateEnabled {
			// pull or clone repos
			for _, repo := range e.rulesRepos {
				if !e.isRunning {
					break
				}

				parser, err := url.Parse(repo.Repo)
				if err != nil {
					log.WithError(err).WithField("repo", repo).Error("Failed to parse repo URL, doing nothing with it")
					continue
				}

				_, lastFolder := path.Split(parser.Path)
				repoPath := filepath.Join(e.reposFolder, lastFolder)

				if _, ok := existingRepos[lastFolder]; ok {
					// repo already exists, pull
					gitrepo, err := git.PlainOpen(repoPath)
					if err != nil {
						log.WithError(err).WithField("repo", gitrepo).Error("Failed to open repo, doing nothing with it")
						continue
					}

					work, err := gitrepo.Worktree()
					if err != nil {
						log.WithError(err).WithField("repo", gitrepo).Error("Failed to get worktree, doing nothing with it")
						continue
					}

					ctx, cancel := context.WithTimeout(e.srv.Context, time.Minute*5)

					err = work.PullContext(ctx, &git.PullOptions{
						Depth:        1,
						SingleBranch: true,
					})
					if err != nil && err != git.NoErrAlreadyUpToDate {
						cancel()
						log.WithError(err).WithField("repo", repo).Error("Failed to pull repo, doing nothing with it")
						continue
					}
					cancel()

					if err == nil || forceSync {
						upToDate[repoPath] = repo
					}
				} else {
					// repo does not exist, clone
					_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
						Depth:        1,
						SingleBranch: true,
						URL:          repo.Repo,
					})
					if err != nil {
						log.WithError(err).WithField("repo", repo).Error("Failed to clone repo, doing nothing with it")
						continue
					}

					upToDate[repoPath] = repo
				}
			}
		} else {
			// Possible airgap installation, or admin has disabled auto-updates.

			// TODO: Perform a one-time check for a pre-downloaded ruleset on disk and if exists,
			// let the rest of the loop continue but then exit the loop. For now we're just hardcoding
			// to always exit the loop.
			return
		}

		if len(upToDate) == 0 {
			// no updates, skip
			log.Info("Strelka sync found no changes")

			e.writeStateFile()

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "success",
				})
			}

			continue
		}

		communityDetections, err := e.srv.Detectionstore.GetAllCommunitySIDs(e.srv.Context, util.Ptr(model.EngineNameStrelka))
		if err != nil {
			log.WithError(err).Error("Failed to get all community SIDs")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "error",
				})
			}

			continue
		}

		// parse *.yar files in repos
		for repopath, repo := range upToDate {
			if !e.isRunning {
				return
			}

			baseDir := repopath
			if repo.Folder != nil {
				baseDir = filepath.Join(baseDir, *repo.Folder)
			}

			err = filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
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
				if strings.ToLower(ext) != ".yar" {
					return nil
				}

				raw, err := e.ReadFile(path)
				if err != nil {
					log.WithError(err).WithField("file", path).Error("failed to read yara rule file")
					return nil
				}

				parsed, err := e.parseYaraRules(raw, true)
				if err != nil {
					log.WithError(err).WithField("file", path).Error("failed to parse yara rule file")
					return nil
				}

				for _, rule := range parsed {
					sev := model.SeverityUnknown

					metaSev, err := strconv.Atoi(rule.Meta.Rest["severity"])
					if err == nil {
						metaSev = 0
					}

					switch {
					case metaSev >= 1 && metaSev < 20:
						sev = model.SeverityInformational
					case metaSev >= 20 && metaSev < 40:
						sev = model.SeverityLow
					case metaSev >= 40 && metaSev < 60:
						sev = model.SeverityMedium
					case metaSev >= 60 && metaSev < 80:
						sev = model.SeverityHigh
					case metaSev >= 80:
						sev = model.SeverityCritical
					}

					license, ok := rule.Meta.Rest["license"]
					if !ok {
						license = repo.License
					}

					ruleset := filepath.Base(repopath)

					det := &model.Detection{
						Author:      socAuthor,
						Engine:      model.EngineNameStrelka,
						PublicID:    rule.GetID(),
						Title:       rule.Identifier,
						Severity:    sev,
						Content:     rule.String(),
						IsCommunity: true,
						Language:    model.SigLangYara,
						Ruleset:     util.Ptr(ruleset),
						License:     license,
					}

					comRule, exists := communityDetections[det.PublicID]
					if exists {
						det.Id = comRule.Id
						det.IsEnabled = comRule.IsEnabled
					}

					if rule.Meta.Author != nil {
						det.Author = util.Unquote(*rule.Meta.Author)
					}

					if rule.Meta.Description != nil {
						det.Description = util.Unquote(*rule.Meta.Description)
					}

					if exists {
						// pre-existing detection, update it
						det, err = e.srv.Detectionstore.UpdateDetection(e.srv.Context, det)
						if err != nil {
							log.WithError(err).WithField("det", det).Error("Failed to update detection")
							continue
						}
					} else {
						// new detection, create it
						det, err = e.srv.Detectionstore.CreateDetection(e.srv.Context, det)
						if err != nil {
							log.WithError(err).WithField("det", det).Error("Failed to create detection")
							continue
						}
					}
				}

				return nil
			})
			if err != nil {
				log.WithError(err).WithField("repo", repopath).Error("Failed to walk repo")

				continue
			}
		}

		errMap, err := e.syncDetections(e.srv.Context)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of YARA community detections due to module stopping")
				return
			}

			log.WithError(err).Error("unable to sync YARA community detections")

			if e.notify {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "error",
				})
			}

			continue
		}

		e.writeStateFile()

		if e.notify {
			if len(errMap) > 0 {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "partial",
				})
			} else {
				e.srv.Host.Broadcast("detection-sync", "detection", server.SyncStatus{
					Engine: model.EngineNameStrelka,
					Status: "success",
				})
			}
		}

		log.WithFields(log.Fields{
			"errMap": errMap,
			"time":   time.Since(start).Seconds(),
		}).Info("strelka community rules sync finished")
	}
}

func (e *StrelkaEngine) parseYaraRules(data []byte, filter bool) ([]*YaraRule, error) {
	rules := []*YaraRule{}
	rule := &YaraRule{}

	state := parseStateImportsID

	raw := string(data)
	buffer := bytes.NewBuffer([]byte{})
	last := ' '
	curCommentType := ' ' // either '/' or '*' if in a comment, ' ' if not in comment
	curHeader := ""       // meta, strings, condition, or empty if not yet in a section
	curQuotes := ' '      // either ' or " if in a string, ' ' if not in a string

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

		if last == '/' && curQuotes == ' ' && curCommentType == ' ' {
			if r == '/' {
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

					buffer.Reset()
				}
			case '{':
				buf := strings.TrimSpace(buffer.String()) // expected: `rule foo {` or `rule foo\n{`
				buf = strings.TrimSpace(strings.TrimPrefix(buf, "rule"))

				if strings.Contains(buf, ":") {
					// gets rid of inheritance?
					// rule This : That {...} becomes "This"
					parts := strings.SplitN(buf, ":", 2)
					buf = strings.TrimSpace(parts[0])
				}

				if buf != "" {
					rule.Identifier = buf
				} else {
					return nil, errors.New(fmt.Sprintf("expected rule identifier at %d", i))
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
					return nil, errors.New(fmt.Sprintf("unexpected header at %d: %s", i, curHeader))
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
								return nil, errors.New(fmt.Sprintf("invalid meta line at %d: %s", i, buf))
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
					log.WithField("id", rule.Identifier).Info("content matched Strelka's denyRegex")
					keep = false
				}

				if filter && e.allowRegex != nil && !e.allowRegex.MatchString(rule.Src) {
					log.WithField("id", rule.Identifier).Info("content didn't match Strelka's allowRegex")
					keep = false
				}

				if keep {
					rules = append(rules, rule)
				}

				imports := []string{}
				buffer.Reset()

				state = parseStateImportsID
				curHeader = ""
				curQuotes = ' '
				rule = &YaraRule{}

				if len(imports) > 0 {
					rule.Imports = append([]string{}, imports...)
				}
			} else {
				buffer.WriteRune(r)
				if (r == '\'' || r == '"' || r == '{') && last != '\\' && curQuotes == ' ' {
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

		if r == '\\' && last == '\\' && curQuotes != ' ' {
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

func (e *StrelkaEngine) syncDetections(ctx context.Context) (errMap map[string]string, err error) {
	results, err := e.srv.Detectionstore.Query(ctx, `so_detection.engine:strelka AND so_detection.isEnabled:true AND _index:"*:so-detection"`, -1)
	if err != nil {
		return nil, err
	}

	enabledDetections := map[string]*model.Detection{}
	for _, det := range results {
		if !e.isRunning {
			return nil, errModuleStopped
		}

		d := det.(*model.Detection)
		enabledDetections[d.PublicID] = d
	}

	filename := filepath.Join(e.yaraRulesFolder, "enabled_rules.yar")

	if len(enabledDetections) == 0 {
		err = e.DeleteFile(filename)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}

		return nil, nil
	}

	buf := bytes.Buffer{}

	for _, det := range enabledDetections {
		buf.WriteString(det.Content + "\n")
	}

	err = e.WriteFile(filename, buf.Bytes(), 0644)
	if err != nil {
		return nil, err
	}

	if e.compileRules {
		// compile yara rules
		cmd := exec.CommandContext(ctx, "python3", e.compileYaraPythonScriptPath, e.yaraRulesFolder)

		raw, code, dur, err := e.ExecCommand(cmd)

		log.WithFields(log.Fields{
			"command":  cmd.String(),
			"output":   string(raw),
			"code":     code,
			"execTime": dur.Seconds(),
			"error":    err,
		}).Info("yara compilation results")

		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func (e *StrelkaEngine) readStateFile() (lastImport *uint64, err error) {
	raw, err := e.ReadFile(e.stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("unable to read Strelka state file: %w", err)
	}

	unix, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Strelka state file: %w", err)
	}

	return &unix, nil
}

func (e *StrelkaEngine) writeStateFile() {
	unix := time.Now().Unix()
	sUnix := strconv.FormatInt(unix, 10)

	err := e.WriteFile(e.stateFilePath, []byte(sUnix), 0644)
	if err != nil {
		log.WithError(err).Error("unable to write Strelka state file")
	}
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
