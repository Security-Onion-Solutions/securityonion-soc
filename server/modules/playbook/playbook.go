// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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
	DEFAULT_PLAYBOOK_REPO_BRANCH              = "dev"
	DEFAULT_PLAYBOOK_REPO_PATH                = "/opt/sensoroni/playbooks"
	DEFAULT_PLAYBOOK_PATH_IN_REPO             = "playbook/dev"
)

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

func (pbm *PlaybookDiskManager) PrerequisiteModules() []string {
	return nil
}

func (pbm *PlaybookDiskManager) Init(config module.ModuleConfig) (err error) {
	pbm.InterruptChan = make(chan bool, 1)

	pbm.autoUpdateEnabled = module.GetBoolDefault(config, "autoUpdateEnabled", DEFAULT_AUTO_UPDATE_ENABLED)
	pbm.PlaybookImportFrequencySeconds = module.GetIntDefault(config, "playbookImportFrequencySeconds", DEFAULT_PLAYBOOK_IMPORT_FREQUENCY_SECONDS)
	pbm.PlaybookImportErrorSeconds = module.GetIntDefault(config, "playbookImportErrorSeconds", DEFAULT_PLAYBOOK_IMPORT_ERROR_SECONDS)
	pbm.playbookRepoUrl = module.GetStringDefault(config, "playbookRepoUrl", DEFAULT_PLAYBOOK_REPO)
	pbm.playbookRepoBranch = module.GetStringDefault(config, "playbookRepoBranch", DEFAULT_PLAYBOOK_REPO_BRANCH)
	pbm.playbookRepoPath = module.GetStringDefault(config, "playbookRepoPath", DEFAULT_PLAYBOOK_REPO_PATH)
	pbm.playbookPathInRepo = module.GetStringDefault(config, "playbookPathInRepo", DEFAULT_PLAYBOOK_PATH_IN_REPO)

	return nil
}

func (pbm *PlaybookDiskManager) Start() error {
	pbm.srv.Playbookstore = pbm
	pbm.isRunning = true

	go pbm.scheduler()

	return nil
}

func (pbm *PlaybookDiskManager) Stop() error {
	pbm.isRunning = false

	return nil
}

func (pbm *PlaybookDiskManager) IsRunning() bool {
	return pbm.isRunning
}

func (pbm *PlaybookDiskManager) Interrupt(force bool) {
	pbm.interm.Lock()
	defer pbm.interm.Unlock()

	if len(pbm.InterruptChan) == 0 {
		pbm.InterruptChan <- force
	}
}

func (pbm *PlaybookDiskManager) resetInterrupt() {
	pbm.interm.Lock()
	defer pbm.interm.Unlock()

	if len(pbm.InterruptChan) != 0 {
		<-pbm.InterruptChan
	}
}

func (pbm *PlaybookDiskManager) scheduler() {
	wasSuccessful := false
	var timer *time.Timer
	for pbm.isRunning {
		if wasSuccessful {
			timer = time.NewTimer(time.Second * time.Duration(pbm.PlaybookImportFrequencySeconds))
		} else {
			timer = time.NewTimer(time.Second * time.Duration(pbm.PlaybookImportErrorSeconds))
		}

		force := false
		pbm.resetInterrupt()

		select {
		case inter := <-pbm.InterruptChan:
			force = inter
		case <-timer.C:
		}

		syncId := uuid.New().String()
		logger := log.WithFields(log.Fields{
			"module": "playbookDiskManager",
			"syncId": syncId,
		})

		anythingNew, err := pbm.UpdateRepoOnDisk()
		if err != nil {
			logger.WithError(err).Error("unable to update playbook repo")
			wasSuccessful = false
			continue
		}

		if anythingNew || force {
			start := time.Now()

			err = pbm.LoadPlaybooks(logger)
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

func (pbm *PlaybookDiskManager) UpdateRepoOnDisk() (anythingNew bool, err error) {
	_, anythingNew, err = detections.UpdateRepos(&pbm.isRunning, pbm.playbookRepoPath, []*model.RuleRepo{
		{
			Repo:   pbm.playbookRepoUrl,
			Branch: util.Ptr(pbm.playbookRepoBranch),
		},
	}, pbm.IOManager)

	if err != nil {
		return false, err
	}

	return anythingNew, nil
}

func (pbm *PlaybookDiskManager) LoadPlaybooks(logger log.Interface) error {
	start := time.Now()
	playbooks, err := pbm.readPlaybooks(logger)
	if err != nil {
		logger.WithError(err).Error("unable to read playbooks")
		return err
	}

	if !pbm.isRunning {
		return detections.ErrModuleStopped
	}

	logger.WithFields(log.Fields{
		"duration":      time.Since(start).Seconds(),
		"playbookCount": len(playbooks),
	}).Info("read playbooks")

	start = time.Now()

	for _, pb := range playbooks {
		if !pbm.isRunning {
			return detections.ErrModuleStopped
		}

		err = pbm.ConvertQueries(logger, pb)
		if err != nil {
			logger.WithError(err).WithField("playbookId", pb.Id).Error("unable to convert queries")
			continue
		}
	}

	logger.WithFields(log.Fields{
		"duration": time.Since(start).Seconds(),
	}).Info("converted playbook queries")

	start = time.Now()

	err = pbm.organizePlaybooks(logger, playbooks)
	if err != nil {
		logger.WithError(err).Error("unable to organize playbooks")
		return err
	}

	logger.WithFields(log.Fields{
		"duration": time.Since(start).Seconds(),
	}).Info("organized playbooks")

	return nil
}

func (pbm *PlaybookDiskManager) readPlaybooks(logger log.Interface) ([]*model.Playbook, error) {
	repo, err := url.Parse(pbm.playbookRepoUrl)
	if err != nil {
		return nil, err
	}

	repoFolderName := path.Base(repo.Path)

	targetDir := path.Join(pbm.playbookRepoPath, repoFolderName, pbm.playbookPathInRepo)

	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, err
	}

	logger.WithFields(log.Fields{
		"playbookDir": targetDir,
		"fileCount":   len(entries),
	}).Info("reading playbooks")

	playbooks := make([]*model.Playbook, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		f, err := os.Open(path.Join(targetDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		defer f.Close()

		pb := &model.Playbook{}

		err = yaml.NewDecoder(f).Decode(pb)
		if err != nil {
			return nil, err
		}

		playbooks = append(playbooks, pb)
	}

	return playbooks, nil
}

func (pbm *PlaybookDiskManager) organizePlaybooks(logger log.Interface, playbooks []*model.Playbook) error {
	byDetId := make(map[string][]*model.Playbook)
	byPBId := make(map[string]*model.Playbook)
	byCategory := make(map[string][]*model.Playbook)
	byEngine := make(map[string][]*model.Playbook)

	for _, pb := range playbooks {
		if pb.DetectionId != "" {
			byDetId[pb.DetectionId] = append(byDetId[pb.DetectionId], pb)
		}

		if pb.DetectionCategory != "" {
			byCategory[pb.DetectionCategory] = append(byCategory[pb.DetectionCategory], pb)
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

		_, ok := byPBId[pb.Id]
		if ok {
			logger.WithField("playbookId", pb.Id).Warn("duplicate playbook id")
		}

		byPBId[pb.Id] = pb
	}

	pbm.pbUpdateMutex.Lock()

	pbm.PlaybooksByEngine = byEngine
	pbm.PlaybooksByCategory = byCategory
	pbm.PlaybooksByDetectionId = byDetId
	pbm.PlaybooksByPlaybookId = byPBId

	defer pbm.pbUpdateMutex.Unlock()

	return nil
}

func (pbm *PlaybookDiskManager) GetPlaybooksForDetection(publicId string, detectCategory string, detectEngine model.EngineName) ([]*model.Playbook, error) {
	pbm.pbUpdateMutex.RLock()
	defer pbm.pbUpdateMutex.RUnlock()

	forId := pbm.PlaybooksByDetectionId[publicId]
	forCategory := pbm.PlaybooksByCategory[detectCategory]

	results := append([]*model.Playbook{}, forId...)
	results = append(results, forCategory...)

	if len(results) == 0 {
		results = pbm.PlaybooksByEngine[string(detectEngine)]
	}

	return results, nil
}

func (pbm *PlaybookDiskManager) GetPlaybookById(id string) (*model.Playbook, error) {
	pbm.pbUpdateMutex.RLock()
	defer pbm.pbUpdateMutex.RUnlock()

	pb, ok := pbm.PlaybooksByPlaybookId[id]
	if !ok {
		return nil, nil
	}

	return pb, nil
}

type conversionResponse struct {
	Query  string
	Fields []string
}

func (pbm *PlaybookDiskManager) ConvertQueries(logger log.Interface, pb *model.Playbook) (err error) {
	queries := lo.Map(pb.Questions, func(question *model.Question, _ int) string {
		return question.Query
	})
	args := []string{"convert", "-t", "security_onion", "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "--disable-pipeline-check", "/dev/stdin"}

	cmd := exec.CommandContext(pbm.srv.Context, "sigma", args...)
	cmd.Stdin = strings.NewReader(strings.Join(queries, "\n---\n"))

	raw, code, runtime, err := pbm.ExecCommand(cmd)

	logger.WithFields(log.Fields{
		"sigmaConvertCode":     code,
		"sigmaConvertOutput":   string(raw),
		"sigmaConvertCommand":  cmd.String(),
		"sigmaConvertExecTime": runtime.Seconds(),
		"sigmaConvertError":    err,
	}).Info("executing sigma cli")

	if err != nil {
		return fmt.Errorf("problem with sigma cli: %w", err)
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

	for i, line := range lines {
		cr := conversionResponse{}

		err = json.Unmarshal([]byte(line), &cr)
		if err != nil {
			return fmt.Errorf("problem unmarshalling sigma cli output: %w", err)
		}

		pb.Questions[i].OQL = cr.Query
		pb.Questions[i].Fields = cr.Fields
	}

	return nil
}
