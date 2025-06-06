// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_AUTO_UPDATE_ENABLED               = false
	DEFAULT_PLAYBOOK_IMPORT_FREQUENCY_SECONDS = 24 * 60 * 60
	DEFAULT_PLAYBOOK_IMPORT_ERROR_SECONDS     = 10 * 60
	DEFAULT_PLAYBOOK_REPO                     = "https://github.com/Security-Onion-Solutions/securityonion-resources-playbooks"
	DEFAULT_PLAYBOOK_REPO_BRANCH              = "main"
	DEFAULT_PLAYBOOK_REPO_PATH                = "/opt/sensoroni/playbooks"
	DEFAULT_PLAYBOOK_PATH_IN_REPO             = "securityonion-normalized"
)

var ErrBadPermissions = fmt.Errorf("playbooks module not authorized to read playbooks")

type PlaybookDiskManager struct {
	srv                            *server.Server
	isRunning                      bool
	playbookRepoUrl                string
	playbookRepoBranch             string
	playbookRepoPath               string
	playbookPathInRepo             string
	autoUpdateEnabled              bool
	pbUpdateMutex                  sync.RWMutex
	interm                         sync.Mutex
	interruptChan                  chan bool
	playbookImportFrequencySeconds int
	playbookImportErrorSeconds     int

	PlaybooksByDetectionId map[string][]string
	PlaybooksByCategory    map[string][]string
	PlaybooksByEngine      map[string][]string
	playbooksOnDisk        map[string]string
	playbookTypes          map[string]string // Maps playbook ID to detection type

	detections.IOManager
}

func NewPlaybookDiskManager(srv *server.Server) *PlaybookDiskManager {
	return &PlaybookDiskManager{
		srv:       srv,
		IOManager: &detections.ResourceManager{Config: srv.Config},
	}
}

func (pdm *PlaybookDiskManager) PrerequisiteModules() []string {
	return nil
}

func (pdm *PlaybookDiskManager) Init(config module.ModuleConfig) (err error) {
	pdm.interruptChan = make(chan bool, 1)

	pdm.autoUpdateEnabled = module.GetBoolDefault(config, "autoUpdateEnabled", DEFAULT_AUTO_UPDATE_ENABLED)
	pdm.playbookImportFrequencySeconds = module.GetIntDefault(config, "playbookImportFrequencySeconds", DEFAULT_PLAYBOOK_IMPORT_FREQUENCY_SECONDS)
	pdm.playbookImportErrorSeconds = module.GetIntDefault(config, "playbookImportErrorSeconds", DEFAULT_PLAYBOOK_IMPORT_ERROR_SECONDS)
	pdm.playbookRepoUrl = module.GetStringDefault(config, "playbookRepoUrl", DEFAULT_PLAYBOOK_REPO)
	pdm.playbookRepoBranch = module.GetStringDefault(config, "playbookRepoBranch", DEFAULT_PLAYBOOK_REPO_BRANCH)
	pdm.playbookRepoPath = module.GetStringDefault(config, "playbookRepoPath", DEFAULT_PLAYBOOK_REPO_PATH)
	pdm.playbookPathInRepo = module.GetStringDefault(config, "playbookPathInRepo", DEFAULT_PLAYBOOK_PATH_IN_REPO)

	return nil
}

func (pdm *PlaybookDiskManager) Start() error {
	pdm.srv.Playbookstore = pdm
	pdm.isRunning = true

	go pdm.scheduler()

	return nil
}

func (pdm *PlaybookDiskManager) Stop() error {
	pdm.isRunning = false

	return nil
}

func (pdm *PlaybookDiskManager) IsRunning() bool {
	return pdm.isRunning
}

func (pdm *PlaybookDiskManager) Interrupt(ctx context.Context, force bool) error {
	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return err
	}

	pdm.interm.Lock()
	defer pdm.interm.Unlock()

	if len(pdm.interruptChan) == 0 {
		pdm.interruptChan <- force
	}

	return nil
}

func (pdm *PlaybookDiskManager) resetInterrupt() {
	pdm.interm.Lock()
	defer pdm.interm.Unlock()

	if len(pdm.interruptChan) != 0 {
		<-pdm.interruptChan
	}
}

func (pdm *PlaybookDiskManager) scheduler() {
	wasSuccessful := false
	var timer *time.Timer

	firstRun := sync.OnceFunc(func() {
		_ = pdm.Interrupt(pdm.srv.Context, true)
	})

	for pdm.isRunning {
		if wasSuccessful {
			timer = time.NewTimer(time.Second * time.Duration(pdm.playbookImportFrequencySeconds))
		} else {
			timer = time.NewTimer(time.Second * time.Duration(pdm.playbookImportErrorSeconds))
		}

		force := false
		pdm.resetInterrupt()

		firstRun()

		select {
		case inter := <-pdm.interruptChan:
			force = inter
		case <-timer.C:
		}

		syncId := uuid.New().String()
		logger := log.WithFields(log.Fields{
			"module": "playbookDiskManager",
			"syncId": syncId,
		})

		if !pdm.isRunning {
			logger.Info("playbook disk manager stopped")
			return
		}

		var anythingNew bool

		if pdm.autoUpdateEnabled {
			var err error
			anythingNew, err = pdm.UpdateRepoOnDisk()
			if err != nil {
				logger.WithError(err).Error("unable to update playbook repo")
				wasSuccessful = false
				continue
			}
		} else {
			logger.Info("autoUpdateEnabled is disabled, skipping updating playbooks")
		}

		if !pdm.isRunning {
			logger.Info("playbook disk manager stopped")
			return
		}

		if anythingNew || force {
			start := time.Now()

			err := pdm.LoadPlaybooks(logger)
			if err != nil {
				logger.WithError(err).Error("unable to load playbooks")
				wasSuccessful = false

				continue
			}

			logger.WithField("totalSeconds", time.Since(start).Seconds()).Info("successfully loaded playbooks")

			wasSuccessful = true
		}
	}
}

func (pdm *PlaybookDiskManager) UpdateRepoOnDisk() (anythingNew bool, err error) {
	_, anythingNew, err = detections.UpdateRepos(&pdm.isRunning, pdm.playbookRepoPath, []*model.RuleRepo{
		{
			Repo:   pdm.playbookRepoUrl,
			Branch: util.Ptr(pdm.playbookRepoBranch),
		},
	}, pdm.IOManager)

	if err != nil {
		return false, err
	}

	return anythingNew, nil
}

func (pdm *PlaybookDiskManager) LoadPlaybooks(logger log.Interface) error {
	start := time.Now()
	playbooks, err := pdm.readPlaybooks(logger)
	if err != nil {
		logger.WithError(err).Error("unable to read playbooks")
		return err
	}

	if !pdm.isRunning {
		return detections.ErrModuleStopped
	}

	logger.WithFields(log.Fields{
		"readPlaybookDuration": time.Since(start).Seconds(),
		"playbookCount":        len(playbooks),
	}).Info("read playbooks")

	return nil
}

func (pdm *PlaybookDiskManager) readPlaybooks(logger log.Interface) ([]*model.Playbook, error) {
	byDetId := make(map[string][]string)
	onDisk := make(map[string]string)
	byCategory := make(map[string][]string)
	byEngine := make(map[string][]string)
	types := make(map[string]string)

	repo, err := url.Parse(pdm.playbookRepoUrl)
	if err != nil {
		return nil, err
	}

	repoFolderName := path.Base(repo.Path)

	targetDir := path.Join(pdm.playbookRepoPath, repoFolderName, pdm.playbookPathInRepo)
	files := 0
	playbooks := []*model.Playbook{}

	err = pdm.IOManager.WalkDir(targetDir, func(p string, dir fs.DirEntry, err error) error {
		if !pdm.isRunning {
			return detections.ErrModuleStopped
		}

		if err != nil {
			// we can't process this file, but keep walking the dir
			logger.WithError(err).WithFields(log.Fields{
				"playbookDir":  targetDir,
				"playbookPath": p,
			}).Warn("error while walking playbook directory")
			return nil
		}

		info, err := dir.Info()
		if err != nil {
			// we can't process this file, but keep walking the dir
			logger.WithError(err).WithFields(log.Fields{
				"playbookDir":  targetDir,
				"playbookPath": p,
				"dirEntry":     dir,
			}).Warn("error while walking playbook directory")
			return nil
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		contents, err := pdm.ReadFile(p)
		if err != nil {
			// we can't process this file, but keep walking the dir
			logger.WithError(err).WithFields(log.Fields{
				"playbookDir":  targetDir,
				"playbookPath": p,
			}).Warn("unable to read file while walking playbook directory")
			return nil
		}

		pb := &model.Playbook{}

		err = yaml.Unmarshal(contents, &pb)
		if err != nil {
			// we can't process this file, but keep walking the dir
			logger.WithError(err).WithFields(log.Fields{
				"playbookDir":  targetDir,
				"playbookPath": p,
			}).Warn("unable to unmarshal playbook")
			return nil
		}

		id := strings.ToLower(pb.Id)
		playbooks = append(playbooks, pb)
		files++

		if pb.DetectionType != "" {
			types[id] = strings.ToLower(pb.DetectionType)
		}

		if pb.DetectionId != "" {
			detId := strings.ToLower(pb.DetectionId)
			byDetId[detId] = append(byDetId[detId], id)
		}

		if pb.DetectionCategory != "" {
			category := strings.ToLower(pb.DetectionCategory)
			byCategory[category] = append(byCategory[category], id)
		}

		if pb.DetectionId == "" && pb.DetectionCategory == "" {
			switch strings.ToLower(pb.DetectionType) {
			case "sigma":
				byEngine[string(model.EngineNameElastAlert)] = append(byEngine[string(model.EngineNameElastAlert)], id)
			case "strelka":
				byEngine[string(model.EngineNameStrelka)] = append(byEngine[string(model.EngineNameStrelka)], id)
			case "nids":
				byEngine[string(model.EngineNameSuricata)] = append(byEngine[string(model.EngineNameSuricata)], id)
			default:
				logger.Warn("unexpected playbook detection_type: " + pb.DetectionType)
			}
		}

		_, ok := onDisk[id]
		if ok {
			logger.WithField("playbookId", id).Warn("duplicate playbook id")
		}

		onDisk[id] = p

		return nil
	})
	if err != nil {
		logger.WithError(err).WithField("playbookDir", targetDir).Error("unable to read playbooks")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"playbookDir": targetDir,
		"fileCount":   files,
	}).Info("read playbooks")

	pdm.pbUpdateMutex.Lock()

	pdm.PlaybooksByEngine = byEngine
	pdm.PlaybooksByCategory = byCategory
	pdm.PlaybooksByDetectionId = byDetId
	pdm.playbooksOnDisk = onDisk
	pdm.playbookTypes = types

	pdm.pbUpdateMutex.Unlock()

	return playbooks, nil
}

func (pdm *PlaybookDiskManager) GetPlaybooksForDetection(ctx context.Context, publicId string, detectCategory string, detectEngine model.EngineName) ([]*model.Playbook, error) {
	logger := log.FromContext(ctx)

	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return nil, err
	}

	publicId = strings.ToLower(publicId)
	detectCategory = strings.ToLower(detectCategory)

	pdm.pbUpdateMutex.RLock()
	defer pdm.pbUpdateMutex.RUnlock()

	forId := pdm.PlaybooksByDetectionId[publicId]
	forCategory := []string{}

	// First try exact match, filtered by detection type for engine consistency
	if matches := pdm.PlaybooksByCategory[detectCategory]; len(matches) > 0 {
		expectedType := ""
		switch detectEngine {
		case model.EngineNameSuricata:
			expectedType = "nids"
		case model.EngineNameElastAlert:
			expectedType = "sigma"
		case model.EngineNameStrelka:
			expectedType = "strelka"
		}

		for _, playbookId := range matches {
			playbookType, ok := pdm.playbookTypes[playbookId]
			if !ok || playbookType == expectedType {
				// Include playbooks with matching type or no type specified
				forCategory = append(forCategory, playbookId)
			}
		}
	}

	// For NIDS engine, try matching base category without prefix
	if detectEngine == model.EngineNameSuricata && detectCategory != "" {
		// Split category into parts (e.g. "ET SCAN" -> ["ET", "SCAN"])
		parts := strings.Fields(detectCategory)
		if len(parts) > 1 {
			// Last part is the base category (e.g. "SCAN")
			baseCategory := strings.ToLower(parts[len(parts)-1])
			if matches := pdm.PlaybooksByCategory[baseCategory]; len(matches) > 0 {
				// Filter matches to only include NIDS playbooks
				for _, playbookId := range matches {
					playbookType, ok := pdm.playbookTypes[playbookId]
					if ok && playbookType == "nids" {
						forCategory = append(forCategory, playbookId)
					}
				}
			}
		}
	}

	results := append([]string{}, forId...)
	results = append(results, forCategory...)

	if len(results) == 0 {
		results = pdm.PlaybooksByEngine[string(detectEngine)]
	}

	pbs := make([]*model.Playbook, 0, len(results))
	for _, id := range results {
		path, ok := pdm.playbooksOnDisk[id]
		if !ok {
			logger.WithFields(log.Fields{
				"detectionPublicId": publicId,
				"playbookId":        id,
			}).Warn("referenced playbook is not known to be on disk")
			continue
		}

		raw, err := pdm.ReadFile(path)
		if err != nil {
			logger.WithFields(log.Fields{
				"detectionPublicId": publicId,
				"playbookId":        id,
				"playbookPath":      path,
			}).Error("unable to read playbook from disk")
			continue
		}

		pb := &model.Playbook{}

		err = yaml.Unmarshal(raw, &pb)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"playbookId":   id,
				"playbookPath": path,
			}).Error("unable to parse playbook from disk")
			continue
		}

		pbs = append(pbs, pb)
	}

	logger.WithFields(log.Fields{
		"playbookCount":     len(pbs),
		"detectionPublicId": publicId,
		"detectCategory":    detectCategory,
		"detectEngine":      detectEngine,
		"playbookIds":       results,
	}).Info("retrieving playbooks for detection")

	return pbs, nil
}

func (pdm *PlaybookDiskManager) GetPlaybookById(ctx context.Context, id string) (pb *model.Playbook, err error) {
	logger := log.FromContext(ctx)

	err = pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return nil, err
	}

	defer func() {
		l := logger.WithField("playbookId", id)
		if err != nil {
			l.WithError(err)
			l.Error("error getting playbook by id")
		} else {
			l.Info("successfully retrieved playbook by id")
		}
	}()

	pdm.pbUpdateMutex.RLock()
	defer pdm.pbUpdateMutex.RUnlock()

	path, ok := pdm.playbooksOnDisk[id]

	if !ok {
		return nil, nil
	}

	raw, err := pdm.ReadFile(path)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"playbookPath": path,
			"playbookId":   id,
		}).Error("unable to read playbook off disk")

		return nil, err
	}

	pb = &model.Playbook{}

	err = yaml.Unmarshal(raw, &pb)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"playbookPath": path,
			"playbookId":   id,
		}).Error("unable to parse playbook from disk")

		return nil, err
	}

	return pb, nil
}

func (pdm *PlaybookDiskManager) ConvertQuestions(ctx context.Context, queries []string) ([]*model.ConvertedQuery, error) {
	logger := log.FromContext(ctx)

	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return nil, err
	}

	args := []string{"convert", "-t", "security_onion", "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "--disable-pipeline-check", "/dev/stdin"}

	cmd := exec.CommandContext(pdm.srv.Context, "sigma", args...)
	cmd.Stdin = strings.NewReader(strings.Join(queries, "\n---\n"))

	raw, code, runtime, err := pdm.ExecCommand(cmd)

	logger.WithFields(log.Fields{
		"sigmaConvertCode":     code,
		"sigmaConvertOutput":   string(raw),
		"sigmaConvertCommand":  cmd.String(),
		"sigmaConvertExecTime": runtime.Seconds(),
		"sigmaConvertError":    err,
	}).Info("executing sigma cli")

	if err != nil {
		return nil, fmt.Errorf("problem with sigma cli: %w", err)
	}

	oql := string(raw)

	firstLine := strings.Index(string(raw), "\n")
	if firstLine != -1 {
		oql = oql[firstLine+1:]
	}

	oql = strings.TrimSpace(oql)

	lines := strings.Split(oql, "\n")

	// filter out blank lines
	lines = lo.Filter(lines, func(line string, _ int) bool {
		return len(line) > 0
	})

	output := make([]*model.ConvertedQuery, 0, len(lines))

	for _, line := range lines {
		cq := &model.ConvertedQuery{}

		err = json.Unmarshal([]byte(line), &cq)
		if err != nil {
			return nil, fmt.Errorf("problem unmarshalling sigma cli output: %w", err)
		}

		output = append(output, cq)
	}

	return output, nil
}
