// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

const (
	DEFAULT_AUTO_UPDATE_ENABLED               = false
	DEFAULT_PLAYBOOK_IMPORT_FREQUENCY_SECONDS = 24 * 60 * 60
	DEFAULT_PLAYBOOK_IMPORT_ERROR_SECONDS     = 10 * 60
	DEFAULT_PLAYBOOK_REPO_PATH                = "/opt/sensoroni/playbooks"
	DEFAULT_PLACEHOLDER_MAP_PATH              = "/opt/sensoroni/playbook_placeholder_map.yaml"
	DEFAULT_USER_PLACEHOLDER_MAP_PATH         = "/opt/sensoroni/playbook_placeholder_map_custom.yaml"
)

var ( // treat as constant
	DEFAULT_PLAYBOOK_REPOS = []*model.Repo{
		{
			RepoUrl: "https://github.com/Security-Onion-Solutions/securityonion-resources-playbooks",
			Branch:  util.Ptr("main"),
			Folder:  util.Ptr("securityonion-normalized"),
		},
	}
)

var ErrBadPermissions = fmt.Errorf("playbooks module not authorized to read playbooks")

type PlaybookDiskManager struct {
	srv                            *server.Server
	isRunning                      bool
	playbookRepos                  []*model.Repo
	playbookRepoPath               string
	autoUpdateEnabled              bool
	pbUpdateMutex                  sync.RWMutex
	interm                         sync.Mutex
	interruptChan                  chan bool
	playbookImportFrequencySeconds int
	playbookImportErrorSeconds     int

	// placeholderMap maps a Sigma placeholder name (%name%) to the event field its value
	// resolves from (via lookupEventValue). It is the shipped global map overlaid with the
	// editable user map
	placeholderMap         map[string]string
	placeholderMapPath     string // shipped defaults, overwritten on upgrade
	userPlaceholderMapPath string // grid-editable overrides, preserved across upgrades

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
	pdm.playbookRepoPath = module.GetStringDefault(config, "playbookRepoPath", DEFAULT_PLAYBOOK_REPO_PATH)

	pdm.playbookRepos, err = model.GetReposDefault(config, "playbookRepos", false, DEFAULT_PLAYBOOK_REPOS)
	if err != nil {
		return fmt.Errorf("unable to parse Playbooks playbookRepos: %w", err)
	}

	pdm.placeholderMapPath = module.GetStringDefault(config, "placeholderMapPath", DEFAULT_PLACEHOLDER_MAP_PATH)
	pdm.userPlaceholderMapPath = module.GetStringDefault(config, "userPlaceholderMapPath", DEFAULT_USER_PLACEHOLDER_MAP_PATH)

	// The combined map is the shipped global map overlaid with the editable user map
	// (user entries win). Both are optional; a missing file just contributes nothing.
	globalMap := pdm.loadPlaceholderMap(pdm.placeholderMapPath)
	userMap := pdm.loadPlaceholderMap(pdm.userPlaceholderMapPath)
	pdm.placeholderMap = mergePlaceholderMaps(globalMap, userMap)

	if len(pdm.placeholderMap) == 0 {
		log.WithFields(log.Fields{
			"globalMapPath": pdm.placeholderMapPath,
			"userMapPath":   pdm.userPlaceholderMapPath,
		}).Warn("no playbook placeholder tokens declared")
	} else {
		log.WithFields(log.Fields{
			"globalTokens": len(globalMap),
			"userTokens":   len(userMap),
			"totalTokens":  len(pdm.placeholderMap),
		}).Info("loaded playbook placeholder maps")
	}

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
		var repos []*detections.RepoOnDisk

		if pdm.autoUpdateEnabled {
			var err error
			repos, anythingNew, err = pdm.updateReposOnDisk()
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

			err := pdm.LoadPlaybooks(logger, repos)
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

func (pdm *PlaybookDiskManager) updateReposOnDisk() (repos []*detections.RepoOnDisk, anythingNew bool, err error) {
	repos, anythingNew, err = detections.UpdateRepos(&pdm.isRunning, pdm.playbookRepoPath, pdm.playbookRepos, pdm.IOManager)

	if err != nil {
		return nil, false, err
	}

	return repos, anythingNew, nil
}

func (pdm *PlaybookDiskManager) LoadPlaybooks(logger log.Interface, repos []*detections.RepoOnDisk) error {
	start := time.Now()
	playbooks, err := pdm.readPlaybooks(logger, repos)
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

func (pdm *PlaybookDiskManager) readPlaybooks(logger log.Interface, repos []*detections.RepoOnDisk) ([]*model.Playbook, error) {
	byDetId := make(map[string][]string)
	onDisk := make(map[string]string)
	byCategory := make(map[string][]string)
	byEngine := make(map[string][]string)
	types := make(map[string]string)

	total := 0
	playbooks := []*model.Playbook{}

	for _, pbRepo := range repos {
		files := 0
		targetDir := pbRepo.Path

		if pbRepo.Repo.Folder != nil {
			targetDir = filepath.Join(targetDir, *pbRepo.Repo.Folder)
		}

		err := pdm.IOManager.WalkDir(targetDir, func(p string, dir fs.DirEntry, err error) error {
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
			"playbookDir":     targetDir,
			"playbooksLoaded": files,
		}).Info("read playbooks")

		total += files
	}

	logger.WithFields(log.Fields{
		"fileCount": total,
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
			expectedType = "yara"
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

func (pdm *PlaybookDiskManager) GetEventSpecificPlaybook(ctx context.Context, id string, stage model.PlaybookStage, ts time.Time) ([]*model.Playbook, error) {
	logger := log.FromContext(ctx)

	event, err := server.FindEventBySocId(ctx, pdm.srv.Eventstore, id, ts)
	if err != nil {
		return nil, err
	}
	if event == nil {
		return nil, fmt.Errorf("no alert found with ID %s", id)
	}

	detId, ok := event.Payload["rule.uuid"].(string)
	if !ok {
		logger.WithField("specifiedEvent", event).Error("event does not have a rule.uuid field")
		return nil, fmt.Errorf("alert does not have a rule.uuid field")
	}

	detection, err := pdm.srv.Detectionstore.GetDetectionByPublicId(ctx, detId)
	if err != nil {
		return nil, fmt.Errorf("failed to get detection by ID %s: %w", detId, err)
	}

	engInt, ok := pdm.srv.DetectionEngines.Load(detection.Engine)
	if ok {
		eng := engInt.(server.DetectionEngine)

		err = eng.ExtractDetails(detection)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"detectionEngine":   detection.Engine,
				"detectionPublicId": detection.PublicID,
			}).Error("unable to extract details from detection")
		}
	} else {
		logger.WithFields(log.Fields{
			"detectionEngine":   detection.Engine,
			"detectionPublicId": detection.PublicID,
		}).Error("retrieved detection with unsupported engine")
	}

	// no playbooks for this detection is a valid state, not an error
	playbooks, err := pdm.srv.Playbookstore.GetPlaybooksForDetection(ctx, detection.PublicID, detection.Category, detection.Engine)
	if err != nil {
		return nil, fmt.Errorf("failed to get playbooks for detection %s: %w", detection.PublicID, err)
	}
	if len(playbooks) == 0 {
		return playbooks, nil
	}

	switch stage {
	case model.PlaybookStageSkeleton:
		// questions only
	case model.PlaybookStageConvert:
		err = pdm.ConvertPlaybookQueries(ctx, event, playbooks)
		if err != nil {
			return nil, fmt.Errorf("failed to convert playbook queries: %w", err)
		}
	default:
		err = pdm.srv.Playbookstore.ExecutePlaybookSearches(ctx, event, playbooks)
		if err != nil {
			return nil, fmt.Errorf("failed to execute playbook searches: %w", err)
		}
	}

	return playbooks, nil
}

// ruleTitleRegex matches a top-level `title:` key in a Sigma rule document.
var ruleTitleRegex = regexp.MustCompile(`(?m)^title:`)

func (pdm *PlaybookDiskManager) ConvertQuestions(ctx context.Context, queries []string, event *model.EventRecord) ([]*model.ConvertedQuery, error) {
	logger := log.FromContext(ctx)

	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return nil, err
	}

	// Resolve %placeholder% values from this alert's event via a per-call `vars:` pipeline.
	// SecurityOnion_playbook_placeholders reads pipeline.vars; pySigma merges the -p pipelines.
	// The combined placeholder map declares the known tokens; any token used in a query but
	// undeclared is resolved by name against the event (see buildVarsFromEvent).
	used := extractPlaceholders(queries...)
	varsYaml, err := yaml.Marshal(map[string]interface{}{"vars": pdm.buildVarsFromEvent(event, pdm.placeholderMap, used)})
	if err != nil {
		return nil, fmt.Errorf("unable to marshal placeholder vars: %w", err)
	}

	varsPath := filepath.Join(os.TempDir(), "playbook-vars-"+uuid.New().String()+".yaml")
	if err := pdm.WriteFile(varsPath, varsYaml, 0600); err != nil {
		return nil, fmt.Errorf("unable to write placeholder vars file: %w", err)
	}
	defer func() {
		if rmErr := pdm.DeleteFile(varsPath); rmErr != nil {
			logger.WithError(rmErr).WithField("varsPath", varsPath).Warn("unable to remove placeholder vars file")
		}
	}()

	args := []string{"convert", "-t", "security_onion", "-p", "SecurityOnion_playbook_placeholders", "-p", varsPath, "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "/opt/sensoroni/sigma_playbook_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "--disable-pipeline-check", "/dev/stdin"}

	// pySigma rejects a title-less rule, so prepend a throwaway title to any query
	// that lacks one. It is stripped from the OQL output and need not be unique.
	titled := make([]string, len(queries))
	for i, q := range queries {
		if !ruleTitleRegex.MatchString(q) {
			q = "title: Playbook Question\n" + q
		}
		titled[i] = q
	}

	// the request context, so an abandoned request stops its conversion
	cmd := exec.CommandContext(ctx, "sigma", args...)
	cmd.Stdin = strings.NewReader(strings.Join(titled, "\n---\n"))

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

// ConvertPlaybookQueries fills each question's query from the alert event and
// converts it to OQL in one batched sigma exec; on failure each query is retried
// alone, so one bad query only leaves its own question unconverted.
func (pdm *PlaybookDiskManager) ConvertPlaybookQueries(ctx context.Context, event *model.EventRecord, pbs []*model.Playbook) error {
	logger := log.FromContext(ctx)

	// LEGACY {field} substitution; a no-op for %placeholder% playbooks, whose
	// values are resolved at convert time via buildVarsFromEvent.
	queryVariableSubstitution(event, pbs)

	questions := make([]*model.Question, 0)
	filled := make([]string, 0)
	for _, pb := range pbs {
		for _, question := range pb.Questions {
			questions = append(questions, question)
			filled = append(filled, question.FilledQuery)
		}
	}

	if len(questions) == 0 {
		return nil
	}

	converted, err := pdm.ConvertQuestions(ctx, filled, event)
	if err != nil || len(converted) != len(filled) {
		// conversion is positional, so a count mismatch cannot be mapped back safely
		logger.WithError(err).WithFields(log.Fields{
			"eventId":        event.Id,
			"convertedCount": len(converted),
			"questionCount":  len(filled),
		}).Warn("batch conversion failed; converting questions individually")

		converted = pdm.convertQuestionsIndividually(ctx, event, filled)
	}

	for i, question := range questions {
		if converted[i] == nil {
			continue
		}

		question.OqlQuery = converted[i].Query
		question.QueryFields = converted[i].Fields
		question.IsAggregate = isQuestionAggregate(question.Query)
	}

	return nil
}

// convertQuestionsIndividually converts each query in its own sigma exec,
// returning a nil entry for any query that fails.
func (pdm *PlaybookDiskManager) convertQuestionsIndividually(ctx context.Context, event *model.EventRecord, filled []string) []*model.ConvertedQuery {
	logger := log.FromContext(ctx)

	converted := make([]*model.ConvertedQuery, len(filled))
	for i, query := range filled {
		result, err := pdm.ConvertQuestions(ctx, []string{query}, event)
		if err != nil || len(result) != 1 {
			logger.WithError(err).WithField("eventId", event.Id).Warn("unable to convert question")
			continue
		}

		converted[i] = result[0]
	}

	return converted
}

// ExecuteQuestionSearch runs one converted question's query against the event
// store, windowed around eventTime by the question's Range, and fills its
// QueryResults. Rangeless questions are the caller's responsibility.
func (pdm *PlaybookDiskManager) ExecuteQuestionSearch(ctx context.Context, eventTime time.Time, question *model.Question) error {
	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return err
	}

	if question.Range == nil {
		return errors.New("question has no range; it is answered by the alert itself")
	}

	if question.OqlQuery == "" {
		return errors.New("question has no converted query")
	}

	dateRange := buildQuestionRange(eventTime, *question.Range, "UTC")
	if dateRange == "" {
		return fmt.Errorf("unable to build a date range from %q", *question.Range)
	}

	query := question.OqlQuery

	if !question.IsAggregate {
		query += " | sortby @timestamp"
	}

	criteria := model.NewEventSearchCriteria()

	err = criteria.Populate(query, dateRange, time.RFC3339, "", "5", "5")
	if err != nil {
		return fmt.Errorf("unable to populate search criteria: %w", err)
	}

	criteria.Timeout = time.Second * 30
	criteria.AllowTimeout = true

	searchResults, err := pdm.srv.Eventstore.Search(ctx, criteria)
	if err != nil {
		return fmt.Errorf("unable to execute search: %w", err)
	}

	if question.IsAggregate {
		// the longest key holds the metrics grouped by the full set of fields
		longest := ""
		for key := range searchResults.Metrics {
			if len(key) > len(longest) {
				longest = key
			}
		}

		events := make([]*model.EventRecord, 0, len(searchResults.Metrics[longest]))

		for _, metric := range searchResults.Metrics[longest] {
			m := map[string]any{}

			m["Count"] = metric.Value
			// QueryFields can come from the request body, so don't trust it to
			// line up with the metric keys
			for k, v := range question.QueryFields {
				if k >= len(metric.Keys) {
					break
				}
				m[v] = metric.Keys[k]
			}

			events = append(events, &model.EventRecord{Payload: m})
		}

		question.QueryResults = events
	} else {
		question.QueryResults = searchResults.Events
		question.QueryTimedOut = searchResults.TimedOut
	}

	return nil
}

func (pdm *PlaybookDiskManager) ExecutePlaybookSearches(ctx context.Context, event *model.EventRecord, pbs []*model.Playbook) error {
	logger := log.FromContext(ctx)

	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return err
	}

	err = pdm.ConvertPlaybookQueries(ctx, event, pbs)
	if err != nil {
		return err
	}

	for _, pb := range pbs {
		for _, question := range pb.Questions {
			if question.Range == nil {
				question.QueryResults = []*model.EventRecord{event}
				continue
			}

			// unconverted questions stay unanswered without failing the rest
			if question.OqlQuery == "" {
				continue
			}

			err = pdm.ExecuteQuestionSearch(ctx, getEventTimestamp(event), question)
			if err != nil {
				logger.WithError(err).WithFields(log.Fields{"playbookId": pb.Id, "eventId": event.Id}).Warn("unable to execute question search")
				return err
			}
		}
	}

	return nil
}

// queryVariableSubstitution substitutes {field} variables in playbook queries with values
// from the alert event, writing the result to each question's FilledQuery.
//
// LEGACY: this is the original "normalized" playbook mechanism —  string replacement
// of {payload.key} tokens BEFORE conversion. It is superseded by the %placeholder% pipeline
// (SecurityOnion_playbook_placeholders + buildVarsFromEvent), which resolves values at `sigma convert` time
// Un-normalized playbooks use %placeholder% and contain no {} tokens, so for them this is a
// no-op (FilledQuery == Query). Retained only for any remaining normalized playbooks.
func queryVariableSubstitution(event *model.EventRecord, playbooks []*model.Playbook) {
	// Fields that require special array handling
	arrayFields := []string{"network.private_ip", "network.public_ip", "related.ip"}

	// Convert arrayFields to a map for faster lookup
	arrayFieldsMap := make(map[string]bool)
	for _, field := range arrayFields {
		arrayFieldsMap[field] = true
	}

	// Regex to find variables in the format {variable}
	varRegex := regexp.MustCompile(`\{([^}]+)\}`)

	for _, pb := range playbooks {
		for _, question := range pb.Questions {
			q := question.Query

			// Find all variables in the query
			matches := varRegex.FindAllStringSubmatch(q, -1)

			for _, match := range matches {
				if len(match) < 2 {
					continue
				}

				variable := match[0]  // Full match including braces: {fieldName}
				fieldName := match[1] // Just the field name: fieldName

				// Get value from event payload, default to "NODATA" if not found
				var value interface{} = "NODATA"
				if eventValue, exists := event.Payload[fieldName]; exists {
					value = eventValue
				}

				// Check if this field requires special array handling
				if arrayFieldsMap[fieldName] {
					if valueSlice, ok := value.([]interface{}); ok {
						// Find the line containing the variable
						lines := strings.Split(q, "\n")
						for i, line := range lines {
							if strings.Contains(line, variable) {
								// Match field assignment pattern: field: or - field:
								fieldRegex := regexp.MustCompile(`^(\s*)(?:-\s*)?(\w+(?:\.\w+)*(?:\|\w+)*):(?:\s*|$)`)
								fieldMatch := fieldRegex.FindStringSubmatch(line)

								if len(fieldMatch) >= 3 {
									indent := fieldMatch[1]
									field := fieldMatch[2]
									hasDash := strings.Contains(fieldMatch[0], "- ")

									var prefix string
									if hasDash {
										prefix = "- "
									}

									// Build replacement with array values
									var arrayValues []string
									for _, item := range valueSlice {
										if str, ok := item.(string); ok {
											arrayValues = append(arrayValues, fmt.Sprintf("%s    - %s", indent, str))
										}
									}

									replacement := fmt.Sprintf("%s%s%s:\n%s", indent, prefix, field, strings.Join(arrayValues, "\n"))
									lines[i] = replacement
									q = strings.Join(lines, "\n")
									break
								}
							}
						}
						continue
					}
				}

				// Default replacement for non-array fields
				var valueStr string
				switch v := value.(type) {
				case string:
					valueStr = v
				case []interface{}:
					// Convert array to comma-separated string for non-special fields
					var strItems []string
					for _, item := range v {
						if str, ok := item.(string); ok {
							strItems = append(strItems, str)
						}
					}
					valueStr = strings.Join(strItems, ",")
				default:
					valueStr = fmt.Sprintf("%v", v)
				}

				q = strings.ReplaceAll(q, variable, valueStr)
			}

			question.FilledQuery = q
		}
	}
}

// buildQuestionRange builds a date range string for a question based on the event timestamp and range specification
// Range format examples: "+/-3d", "-1h", "30m", "2s"
// Returns a formatted date range string like "2024/01/01 12:00:00 PM - 2024/01/01 01:00:00 PM"
func buildQuestionRange(eventTime time.Time, rangeStr string, timezone string) string {
	if rangeStr == "" {
		return ""
	}

	if eventTime.IsZero() {
		return ""
	}

	// Load timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	eventTime = eventTime.In(loc)

	// Parse range specification
	plusMinus := false
	lookingBack := false

	if strings.HasPrefix(rangeStr, "+/-") {
		plusMinus = true
		rangeStr = rangeStr[3:]
	} else if strings.HasPrefix(rangeStr, "-") {
		lookingBack = true
		rangeStr = rangeStr[1:]
	}

	if len(rangeStr) < 2 {
		return ""
	}

	// Extract unit and value
	unit := strings.ToLower(rangeStr[len(rangeStr)-1:])
	valueStr := rangeStr[:len(rangeStr)-1]

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return ""
	}

	duration := util.UnitToDuration(unit)
	if duration == 0 {
		return ""
	}

	duration *= time.Duration(value)

	// Calculate time range
	var t1, t2 time.Time
	timeFormat := time.RFC3339

	if plusMinus {
		t1 = eventTime.Add(-duration)
		t2 = eventTime.Add(duration)
	} else if lookingBack {
		t1 = eventTime.Add(-duration)
		t2 = eventTime
	} else {
		t1 = eventTime
		t2 = eventTime.Add(duration)
	}

	return fmt.Sprintf("%s - %s", t1.Format(timeFormat), t2.Format(timeFormat))
}

// getEventTimestamp extracts the timestamp from an event record
// Mirrors the JavaScript getEventTimestamp function logic
func getEventTimestamp(event *model.EventRecord) time.Time {
	// Try different timestamp fields in order of preference
	timestampFields := []string{
		"event_data.@timestamp",
		"@timestamp",
		"soc_timestamp",
	}

	for _, field := range timestampFields {
		if value, exists := event.Payload[field]; exists {
			if timeStr, ok := value.(string); ok && timeStr != "" {
				// Try parsing various time formats
				formats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05.000Z",
					"2006-01-02T15:04:05Z",
					"2006-01-02 15:04:05",
				}

				for _, format := range formats {
					if t, err := time.Parse(format, timeStr); err == nil {
						return t
					}
				}
			}
		}
	}

	// Fallback to event's Time field if available
	if !event.Time.IsZero() {
		return event.Time
	}

	return time.Time{}
}

func isQuestionAggregate(query string) bool {
	m := struct {
		Aggregation bool `yaml:"aggregation"`
	}{}

	err := yaml.Unmarshal([]byte(query), &m)
	if err != nil {
		return false
	}

	return m.Aggregation
}
