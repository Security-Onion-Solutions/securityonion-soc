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
	DEFAULT_PLAYBOOK_REPO                     = "https://github.com/Security-Onion-Solutions/securityonion-resources"
	DEFAULT_PLAYBOOK_REPO_BRANCH              = "playbook-stable"
	DEFAULT_PLAYBOOK_REPO_PATH                = "/opt/sensoroni/playbooks"
	DEFAULT_PLAYBOOK_PATH_IN_REPO             = "playbook/dev"
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
	InterruptChan                  chan bool
	PlaybookImportFrequencySeconds int
	PlaybookImportErrorSeconds     int

	PlaybooksByDetectionId map[string][]*model.Playbook
	PlaybooksByCategory    map[string][]*model.Playbook
	PlaybooksByEngine      map[string][]*model.Playbook
	PlaybooksByPlaybookId  map[string]*model.Playbook

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
	pdm.InterruptChan = make(chan bool, 1)

	pdm.autoUpdateEnabled = module.GetBoolDefault(config, "autoUpdateEnabled", DEFAULT_AUTO_UPDATE_ENABLED)
	pdm.PlaybookImportFrequencySeconds = module.GetIntDefault(config, "playbookImportFrequencySeconds", DEFAULT_PLAYBOOK_IMPORT_FREQUENCY_SECONDS)
	pdm.PlaybookImportErrorSeconds = module.GetIntDefault(config, "playbookImportErrorSeconds", DEFAULT_PLAYBOOK_IMPORT_ERROR_SECONDS)
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

	if len(pdm.InterruptChan) == 0 {
		pdm.InterruptChan <- force
	}

	return nil
}

func (pdm *PlaybookDiskManager) resetInterrupt() {
	pdm.interm.Lock()
	defer pdm.interm.Unlock()

	if len(pdm.InterruptChan) != 0 {
		<-pdm.InterruptChan
	}
}

func (pdm *PlaybookDiskManager) scheduler() {
	wasSuccessful := false
	var timer *time.Timer

	err := pdm.checkPermissions(time.Second * 15)
	if err != nil {
		log.WithError(err).Error("playbooks module not authorized to read playbooks, stopping module")
		pdm.Stop()

		return
	}

	firstRun := sync.OnceFunc(func() {
		_ = pdm.Interrupt(pdm.srv.Context, true)
	})

	for pdm.isRunning {
		if wasSuccessful {
			timer = time.NewTimer(time.Second * time.Duration(pdm.PlaybookImportFrequencySeconds))
		} else {
			timer = time.NewTimer(time.Second * time.Duration(pdm.PlaybookImportErrorSeconds))
		}

		force := false
		pdm.resetInterrupt()

		firstRun()

		select {
		case inter := <-pdm.InterruptChan:
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

		anythingNew, err := pdm.UpdateRepoOnDisk()
		if err != nil {
			logger.WithError(err).Error("unable to update playbook repo")
			wasSuccessful = false
			continue
		}

		if !pdm.isRunning {
			logger.Info("playbook disk manager stopped")
			return
		}

		if anythingNew || force {
			start := time.Now()

			err = pdm.LoadPlaybooks(logger)
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

func (pdm *PlaybookDiskManager) checkPermissions(wait time.Duration) error {
	begin := time.Now()
	for pdm.isRunning {
		err := pdm.srv.CheckAuthorized(pdm.srv.Context, "read", "playbooks")
		if err == nil {
			break
		}

		if time.Since(begin) > wait {
			return ErrBadPermissions
		}

		time.Sleep(time.Millisecond * 200)
	}

	return nil
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

	start = time.Now()

	err = pdm.organizePlaybooks(logger, playbooks)
	if err != nil {
		logger.WithError(err).Error("unable to organize playbooks")
		return err
	}

	logger.WithFields(log.Fields{
		"organizePlaybookDuration": time.Since(start).Seconds(),
	}).Info("organized playbooks")

	return nil
}

func (pdm *PlaybookDiskManager) readPlaybooks(logger log.Interface) ([]*model.Playbook, error) {
	repo, err := url.Parse(pdm.playbookRepoUrl)
	if err != nil {
		return nil, err
	}

	repoFolderName := path.Base(repo.Path)

	targetDir := path.Join(pdm.playbookRepoPath, repoFolderName, pdm.playbookPathInRepo)
	files := 0
	playbooks := []*model.Playbook{}

	err = pdm.IOManager.WalkDir(targetDir, func(p string, dir fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := dir.Info()
		if err != nil {
			return err
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
			return err
		}

		pb := &model.Playbook{}

		err = yaml.Unmarshal(contents, &pb)
		if err != nil {
			return err
		}

		playbooks = append(playbooks, pb)
		files++

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

	return playbooks, nil
}

func (pdm *PlaybookDiskManager) organizePlaybooks(logger log.Interface, playbooks []*model.Playbook) error {
	byDetId := make(map[string][]*model.Playbook)
	byPBId := make(map[string]*model.Playbook)
	byCategory := make(map[string][]*model.Playbook)
	byEngine := make(map[string][]*model.Playbook)

	for _, pb := range playbooks {
		if pb.DetectionId != "" {
			key := strings.ToLower(pb.DetectionId)
			byDetId[key] = append(byDetId[key], pb)
		}

		if pb.DetectionCategory != "" {
			key := strings.ToLower(pb.DetectionCategory)
			byCategory[key] = append(byCategory[key], pb)
		}

		if pb.DetectionId == "" && pb.DetectionCategory == "" {
			switch strings.ToLower(pb.DetectionType) {
			case "sigma":
				byEngine[string(model.EngineNameElastAlert)] = append(byEngine[string(model.EngineNameElastAlert)], pb)
			case "strelka":
				byEngine[string(model.EngineNameStrelka)] = append(byEngine[string(model.EngineNameStrelka)], pb)
			case "nids":
				byEngine[string(model.EngineNameSuricata)] = append(byEngine[string(model.EngineNameSuricata)], pb)
			default:
				logger.Warn("unexpected playbook detection_type: " + pb.DetectionType)
			}
		}

		key := strings.ToLower(pb.Id)

		_, ok := byPBId[key]
		if ok {
			logger.WithField("playbookId", key).Warn("duplicate playbook id")
		}

		byPBId[key] = pb
	}

	pdm.pbUpdateMutex.Lock()

	pdm.PlaybooksByEngine = byEngine
	pdm.PlaybooksByCategory = byCategory
	pdm.PlaybooksByDetectionId = byDetId
	pdm.PlaybooksByPlaybookId = byPBId

	pdm.pbUpdateMutex.Unlock()

	return nil
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
	forCategory := pdm.PlaybooksByCategory[detectCategory]

	results := append([]*model.Playbook{}, forId...)
	results = append(results, forCategory...)

	if len(results) == 0 {
		results = pdm.PlaybooksByEngine[string(detectEngine)]
	}

	ids := make([]string, 0, len(results))
	for _, pb := range results {
		ids = append(ids, pb.Id)
	}

	logger.WithFields(log.Fields{
		"playbookCount":  len(results),
		"publicId":       publicId,
		"detectCategory": detectCategory,
		"detectEngine":   detectEngine,
		"playbookIds":    ids,
	}).Info("retrieving playbooks for detection")

	return results, nil
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

	var ok bool
	pb, ok = pdm.PlaybooksByPlaybookId[id]

	if !ok {
		return nil, nil
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
