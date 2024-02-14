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
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"gopkg.in/yaml.v3"
)

var errModuleStopped = fmt.Errorf("module has stopped running")

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
}

type ElastAlertEngine struct {
	srv                                  *server.Server
	communityRulesImportFrequencySeconds int
	sigmaPackageDownloadTemplate         string
	elastAlertRulesFolder                string
	rulesFingerprintFile                 string
	sigmaRulePackages                    []string
	isRunning                            bool
	thread                               *sync.WaitGroup
	IOManager
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

func (e *ElastAlertEngine) Init(config module.ModuleConfig) error {
	e.thread = &sync.WaitGroup{}

	e.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", 600)
	e.sigmaPackageDownloadTemplate = module.GetStringDefault(config, "sigmaPackageDownloadTemplate", "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_%s.zip")
	e.elastAlertRulesFolder = module.GetStringDefault(config, "elastAlertRulesFolder", "/opt/so/rules/elastalert")
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", "/opt/so/conf/soc/sigma.fingerprint")

	pkgs := module.GetStringDefault(config, "sigmaRulePackages", "core")
	e.parseSigmaPackages(pkgs)

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

	return nil
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

func (s *ElastAlertEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
	return s.sigmaToElastAlert(ctx, detect)
}

func (e *ElastAlertEngine) parseSigmaPackages(cfg string) {
	pkgs := strings.Split(strings.ToLower(cfg), "\n")
	set := map[string]struct{}{}

	for _, pkg := range pkgs {
		pkg = strings.TrimSpace(pkg)
		switch pkg {
		case "all":
			set["all_rules"] = struct{}{}
		case "emerging_threats":
			set["emerging_threats_addon"] = struct{}{}
		default:
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

	ctx := e.srv.Context

	for e.isRunning {
		time.Sleep(time.Duration(e.communityRulesImportFrequencySeconds) * time.Second)
		if !e.isRunning {
			return
		}

		start := time.Now()

		zips, errMap := e.downloadSigmaPackages(ctx)
		if len(errMap) != 0 {
			log.WithField("errorMap", errMap).Error("something went wrong downloading sigma packages")
			continue
		}

		zipHashes := map[string]string{}
		for pkg, data := range zips {
			h := sha256.Sum256(data)
			zipHashes[pkg] = base64.StdEncoding.EncodeToString(h[:])
		}

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

			if reflect.DeepEqual(oldHashes, zipHashes) {
				// only an exact match means no work needs to be done.
				// If there's extra hashes in the old file, we need to remove them.
				// If there's extra hashes in the new file, we need to add them.
				// If there's a mix of new and old hashes, we need to include them all
				// or the old ones would be removed.
				log.Info("no sigma package changes to sync")
				continue
			}
		}

		detections, errMap := e.parseRules(zips)
		if errMap != nil {
			log.WithField("error", errMap).Error("something went wrong while parsing sigma rule files")
			continue
		}

		errMap, err = e.syncCommunityDetections(ctx, detections)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of elastalert community detections due to module stopping")
				return
			}

			log.WithError(err).Error("unable to sync elastalert community detections")
			continue
		}

		if len(errMap) > 0 {
			// there were errors, don't save the fingerprint.
			// idempotency means we might fix it if we try again later.
			log.WithFields(log.Fields{
				"errors": errMap,
			}).Error("unable to sync all community detections")
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
		}

		dur := time.Since(start)

		log.WithFields(log.Fields{
			"durationSeconds": dur.Seconds(),
		}).Info("elastalert community rules synced")
	}
}

func (e *ElastAlertEngine) parseRules(pkgZips map[string][]byte) (detections []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName|fileName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	for pkg, zipData := range pkgZips {
		reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err != nil {
			errMap[pkg] = err
			continue
		}

		for _, file := range reader.File {
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

			id := rule.Title

			if rule.ID != nil {
				id = *rule.ID
			}

			sev := model.SeverityUnknown

			if rule.Level != nil {
				switch strings.ToLower(string(*rule.Level)) {
				case "informational":
					sev = model.SeverityInformational
				case "low":
					sev = model.SeverityLow
				case "medium":
					sev = model.SeverityMedium
				case "high":
					sev = model.SeverityHigh
				case "critical":
					sev = model.SeverityCritical
				}
			}

			detections = append(detections, &model.Detection{
				PublicID:    id,
				Title:       rule.Title,
				Severity:    sev,
				Content:     string(data),
				IsCommunity: true,
				Engine:      model.EngineNameElastAlert,
				Language:    model.SigLangSigma,
				Ruleset:     util.Ptr(pkg),
				License:     model.LicenseDRL,
			})
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

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
	}{}

	errMap = map[string]error{} // map[publicID]error

	for _, det := range detections {
		path, ok := index[det.PublicID]
		if !ok {
			path = index[det.Title]
		}

		// 1. Save sigma Detection to ElasticSearch
		oldDet, exists := community[det.PublicID]
		if exists {
			det.IsEnabled, det.Id = oldDet.IsEnabled, oldDet.Id
			if oldDet.Content != det.Content {
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
			det.IsEnabled = false

			_, err = e.srv.Detectionstore.CreateDetection(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to create detection: %s", err)
				continue
			}

			delete(toDelete, det.PublicID)
			results.Added++
		}

		if det.IsEnabled {
			// 2. if enabled, send data to docker container to get converted to query

			rule, err := e.sigmaToElastAlert(ctx, det) // get sigma from docker container
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			rule, err = wrapRule(det, rule)
			if err != nil {
				continue
			}

			// 3. put query in /opt/so/rules/sigma for salt to pick up
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
		"errors":    errMap,
	}).Info("elastalert community diff")

	return errMap, nil
}

func (e *ElastAlertEngine) downloadSigmaPackages(ctx context.Context) (zipData map[string][]byte, errMap map[string]error) {
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
	args := []string{"convert", "-t", "eql", "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "/dev/stdin"}

	cmd := exec.CommandContext(ctx, "sigma", args...)
	cmd.Stdin = strings.NewReader(det.Content)

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

	// apply the first (should only have 1) CustomFilter override if any
	for _, o := range det.Overrides {
		if o.IsEnabled && o.Type == model.OverrideTypeCustomFilter && o.CustomFilter != nil {
			rule = fmt.Sprintf("(%s) and %s", rule, *o.CustomFilter)
			break
		}
	}

	wrapper := &CustomWrapper{
		PlayTitle:     det.Title,
		PlayID:        det.Id,
		EventModule:   "elastalert",
		EventDataset:  "elastalert.alert",
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
