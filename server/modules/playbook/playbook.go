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
	"github.com/security-onion-solutions/securityonion-soc/web"

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

	PlaybooksByDetectionId map[string][]string
	PlaybooksByCategory    map[string][]string
	PlaybooksByEngine      map[string][]string
	playbooksOnDisk        map[string]string
	playbookTypes          map[string]string // Maps playbook ID to detection type

	// Custom playbooks storage
	customPlaybooks      map[string]*model.Playbook
	customPlaybooksFile  string
	customPlaybooksMutex sync.RWMutex

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

	// Initialize custom playbooks storage
	pdm.customPlaybooks = make(map[string]*model.Playbook)
	pdm.customPlaybooksFile = filepath.Join(pdm.playbookRepoPath, "custom_playbooks.json")

	// Load existing custom playbooks
	if err := pdm.loadCustomPlaybooks(); err != nil {
		log.WithError(err).Warn("unable to load custom playbooks, starting with empty set")
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
	// Use file paths as unique identifiers instead of playbook IDs
	// This allows multiple files with the same playbook ID to coexist
	// (e.g., one detection-specific and one category-specific with the same ID)
	byDetId := make(map[string][]string)   // detection_id -> []filePath
	byCategory := make(map[string][]string) // category -> []filePath
	byEngine := make(map[string][]string)   // engine -> []filePath
	onDisk := make(map[string]string)       // playbookId -> filePath (for GetPlaybookById)
	types := make(map[string]string)        // filePath -> detectionType

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

			// Store detection type by file path
			if pb.DetectionType != "" {
				types[p] = strings.ToLower(pb.DetectionType)
			}

			// Index by detection ID - use file path as value
			if pb.DetectionId != "" {
				detId := strings.ToLower(pb.DetectionId)
				byDetId[detId] = append(byDetId[detId], p)
			}

			// Index by category - use file path as value
			if pb.DetectionCategory != "" {
				category := strings.ToLower(pb.DetectionCategory)
				byCategory[category] = append(byCategory[category], p)
			}

			// Index by engine for generic playbooks
			if pb.DetectionId == "" && pb.DetectionCategory == "" {
				switch strings.ToLower(pb.DetectionType) {
				case "sigma":
					byEngine[string(model.EngineNameElastAlert)] = append(byEngine[string(model.EngineNameElastAlert)], p)
				case "strelka":
					byEngine[string(model.EngineNameStrelka)] = append(byEngine[string(model.EngineNameStrelka)], p)
				case "nids":
					byEngine[string(model.EngineNameSuricata)] = append(byEngine[string(model.EngineNameSuricata)], p)
				default:
					logger.Warn("unexpected playbook detection_type: " + pb.DetectionType)
				}
			}

			// Keep playbook ID -> path mapping for GetPlaybookById
			// (if duplicate IDs exist, last one wins - this is acceptable for ID-based lookups)
			if existingPath, ok := onDisk[id]; ok {
				logger.WithFields(log.Fields{
					"playbookId":   id,
					"existingPath": existingPath,
					"newPath":      p,
				}).Warn("duplicate playbook id found; using newer file for ID-based lookups")
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

	// Maps now store file paths directly instead of playbook IDs
	forDetectionPaths := pdm.PlaybooksByDetectionId[publicId]
	forCategoryPaths := []string{}

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

		for _, playbookPath := range matches {
			playbookType, ok := pdm.playbookTypes[playbookPath]
			if !ok || playbookType == expectedType {
				// Include playbooks with matching type or no type specified
				forCategoryPaths = append(forCategoryPaths, playbookPath)
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
				for _, playbookPath := range matches {
					playbookType, ok := pdm.playbookTypes[playbookPath]
					if ok && playbookType == "nids" {
						forCategoryPaths = append(forCategoryPaths, playbookPath)
					}
				}
			}
		}
	}

	// Combine paths from detection-specific and category-level
	allPaths := append([]string{}, forDetectionPaths...)
	allPaths = append(allPaths, forCategoryPaths...)

	// Deduplicate paths - a playbook file with both detection_id and detection_category
	// would be indexed in both maps and appear twice
	seen := make(map[string]bool)
	dedupedPaths := make([]string, 0, len(allPaths))
	for _, path := range allPaths {
		if !seen[path] {
			seen[path] = true
			dedupedPaths = append(dedupedPaths, path)
		}
	}

	// Fall back to engine-level playbooks if no matches
	if len(dedupedPaths) == 0 {
		dedupedPaths = pdm.PlaybooksByEngine[string(detectEngine)]
	}

	// Load playbooks from file paths
	pbs := make([]*model.Playbook, 0, len(dedupedPaths))
	for _, path := range dedupedPaths {
		raw, err := pdm.ReadFile(path)
		if err != nil {
			logger.WithFields(log.Fields{
				"detectionPublicId": publicId,
				"playbookPath":      path,
			}).Error("unable to read playbook from disk")
			continue
		}

		pb := &model.Playbook{}

		err = yaml.Unmarshal(raw, &pb)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"playbookPath": path,
			}).Error("unable to parse playbook from disk")
			continue
		}

		pb.IsCommunity = true
		pbs = append(pbs, pb)
	}

	// Also get custom playbooks for this detection
	customPbs := pdm.getCustomPlaybooksForDetection(publicId, detectCategory, detectEngine)
	pbs = append(pbs, customPbs...)

	logger.WithFields(log.Fields{
		"playbookCount":       len(pbs),
		"communityCount":      len(dedupedPaths),
		"customCount":         len(customPbs),
		"detectionPublicId":   publicId,
		"detectCategory":      detectCategory,
		"detectEngine":        detectEngine,
		"forDetectionPaths":   forDetectionPaths,
		"forCategoryPaths":    forCategoryPaths,
		"communityPaths":      dedupedPaths,
	}).Info("retrieving playbooks for detection")

	return pbs, nil
}

// GetPlaybooksForDetectionGrouped returns playbooks grouped by their match level
// This allows the UI to display detection-specific, category-level, and engine-level playbooks separately
func (pdm *PlaybookDiskManager) GetPlaybooksForDetectionGrouped(ctx context.Context, publicId string, detectCategory string, detectEngine model.EngineName) (*model.GroupedPlaybooks, error) {
	logger := log.FromContext(ctx)

	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return nil, err
	}

	publicId = strings.ToLower(publicId)
	detectCategory = strings.ToLower(detectCategory)

	pdm.pbUpdateMutex.RLock()
	defer pdm.pbUpdateMutex.RUnlock()

	result := &model.GroupedPlaybooks{
		DetectionLevel: []*model.Playbook{},
		CategoryLevel:  []*model.Playbook{},
		EngineLevel:    []*model.Playbook{},
	}

	// Track paths we've already loaded to avoid duplicates
	loadedPaths := make(map[string]bool)

	// Helper function to load a playbook from path
	loadPlaybook := func(path string) *model.Playbook {
		raw, err := pdm.ReadFile(path)
		if err != nil {
			logger.WithFields(log.Fields{
				"detectionPublicId": publicId,
				"playbookPath":      path,
			}).Error("unable to read playbook from disk")
			return nil
		}

		pb := &model.Playbook{}
		err = yaml.Unmarshal(raw, &pb)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"playbookPath": path,
			}).Error("unable to parse playbook from disk")
			return nil
		}

		pb.IsCommunity = true
		return pb
	}

	// Get expected detection type for engine filtering
	expectedType := ""
	switch detectEngine {
	case model.EngineNameSuricata:
		expectedType = "nids"
	case model.EngineNameElastAlert:
		expectedType = "sigma"
	case model.EngineNameStrelka:
		expectedType = "yara"
	}

	// 1. Load detection-specific playbooks
	for _, path := range pdm.PlaybooksByDetectionId[publicId] {
		if loadedPaths[path] {
			continue
		}
		if pb := loadPlaybook(path); pb != nil {
			result.DetectionLevel = append(result.DetectionLevel, pb)
			loadedPaths[path] = true
		}
	}

	// 2. Load category-level playbooks (filtered by engine type)
	categoryPaths := []string{}

	// Exact category match
	if matches := pdm.PlaybooksByCategory[detectCategory]; len(matches) > 0 {
		for _, path := range matches {
			playbookType, ok := pdm.playbookTypes[path]
			if !ok || playbookType == expectedType {
				categoryPaths = append(categoryPaths, path)
			}
		}
	}

	// For NIDS engine, try base category without prefix (e.g., "SCAN" from "ET SCAN")
	if detectEngine == model.EngineNameSuricata && detectCategory != "" {
		parts := strings.Fields(detectCategory)
		if len(parts) > 1 {
			baseCategory := strings.ToLower(parts[len(parts)-1])
			if matches := pdm.PlaybooksByCategory[baseCategory]; len(matches) > 0 {
				for _, path := range matches {
					playbookType, ok := pdm.playbookTypes[path]
					if ok && playbookType == "nids" {
						categoryPaths = append(categoryPaths, path)
					}
				}
			}
		}
	}

	for _, path := range categoryPaths {
		if loadedPaths[path] {
			continue
		}
		if pb := loadPlaybook(path); pb != nil {
			result.CategoryLevel = append(result.CategoryLevel, pb)
			loadedPaths[path] = true
		}
	}

	// 3. Load engine-level playbooks only if no detection or category matches
	if len(result.DetectionLevel) == 0 && len(result.CategoryLevel) == 0 {
		for _, path := range pdm.PlaybooksByEngine[string(detectEngine)] {
			if loadedPaths[path] {
				continue
			}
			if pb := loadPlaybook(path); pb != nil {
				result.EngineLevel = append(result.EngineLevel, pb)
				loadedPaths[path] = true
			}
		}
	}

	// 4. Add custom playbooks to appropriate levels
	customPbs := pdm.getCustomPlaybooksForDetection(publicId, detectCategory, detectEngine)
	for _, pb := range customPbs {
		// Determine which level based on the playbook's fields
		if pb.DetectionId != "" && strings.ToLower(pb.DetectionId) == publicId {
			result.DetectionLevel = append(result.DetectionLevel, pb)
		} else if pb.DetectionCategory != "" {
			result.CategoryLevel = append(result.CategoryLevel, pb)
		} else {
			result.EngineLevel = append(result.EngineLevel, pb)
		}
	}

	logger.WithFields(log.Fields{
		"detectionLevelCount": len(result.DetectionLevel),
		"categoryLevelCount":  len(result.CategoryLevel),
		"engineLevelCount":    len(result.EngineLevel),
		"detectionPublicId":   publicId,
		"detectCategory":      detectCategory,
		"detectEngine":        detectEngine,
	}).Info("retrieving grouped playbooks for detection")

	return result, nil
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

	// First check custom playbooks
	pdm.customPlaybooksMutex.RLock()
	if customPb, exists := pdm.customPlaybooks[id]; exists {
		pdm.customPlaybooksMutex.RUnlock()
		return customPb, nil
	}
	pdm.customPlaybooksMutex.RUnlock()

	// Then check community playbooks on disk
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

	pb.IsCommunity = true
	return pb, nil
}

func (pdm *PlaybookDiskManager) GetEventSpecificPlaybook(ctx context.Context, id string) ([]*model.Playbook, error) {
	logger := log.FromContext(ctx)

	query := fmt.Sprintf(`log.id.uid:"%[1]s" OR event.id:"%[1]s" OR _id:"%[1]s"`, id)
	criteria := model.NewEventSearchCriteria()

	dateRange := "1970-01-01T00:00:00Z - " + time.Now().Format(time.RFC3339)

	err := criteria.Populate(query, dateRange, time.RFC3339, "", "0", "1")
	if err != nil {
		return nil, err
	}

	events, err := pdm.srv.Eventstore.Search(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for alert: %w", err)
	}
	if events.TotalEvents == 0 || len(events.Events) == 0 {
		return nil, fmt.Errorf("no alert found with ID %s", id)
	}

	event := events.Events[0]

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

	playbooks, err := pdm.srv.Playbookstore.GetPlaybooksForDetection(ctx, detection.PublicID, detection.Category, detection.Engine)
	if err != nil || len(playbooks) == 0 {
		return nil, fmt.Errorf("failed to get playbooks for detection %s: %w", detection.PublicID, err)
	}

	err = pdm.srv.Playbookstore.ExecutePlaybookSearches(ctx, event, playbooks)
	if err != nil {
		return nil, fmt.Errorf("failed to execute playbook searches: %w", err)
	}

	return playbooks, nil
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

func (pdm *PlaybookDiskManager) ExecutePlaybookSearches(ctx context.Context, event *model.EventRecord, pbs []*model.Playbook) error {
	logger := log.FromContext(ctx)

	err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		return err
	}

	queryVariableSubstitution(event, pbs)

	for _, pb := range pbs {
		filled := lo.Map(pb.Questions, func(q *model.Question, _ int) string {
			return q.FilledQuery
		})

		converted, err := pdm.ConvertQuestions(ctx, filled)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{"playbookId": pb.Id, "eventId": event.Id}).Warn("unable to convert questions")
			return err
		}

		for i := 0; i < len(pb.Questions); i++ {
			if pb.Questions[i].Range == nil {
				pb.Questions[i].QueryResults = []*model.EventRecord{event}
			} else {
				dateRange := buildQuestionRange(event, *pb.Questions[i].Range, "UTC")

				criteria := model.NewEventSearchCriteria()

				query := converted[i].Query
				isAgg := isQuestionAggregate(pb.Questions[i].Query)

				if !isAgg {
					query += " | sortby @timestamp"
				}

				err = criteria.Populate(query, dateRange, time.RFC3339, "", "5", "5")
				if err != nil {
					logger.WithError(err).WithFields(log.Fields{"playbookId": pb.Id, "eventId": event.Id}).Warn("unable to populate search criteria")
					return err
				}

				searchResults, err := pdm.srv.Eventstore.Search(ctx, criteria)
				if err != nil {
					logger.WithError(err).WithFields(log.Fields{"playbookId": pb.Id, "eventId": event.Id}).Warn("unable to execute search")
					return err
				}

				if isAgg {
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
						for k, v := range converted[i].Fields {
							m[v] = metric.Keys[k]
						}

						e := model.EventRecord{
							Payload: m,
						}

						events = append(events, &e)
					}

					pb.Questions[i].QueryResults = events
				} else {
					pb.Questions[i].QueryResults = searchResults.Events
				}
			}

			pb.Questions[i].OqlQuery = converted[i].Query
			pb.Questions[i].QueryFields = converted[i].Fields
		}
	}

	return nil
}

// queryVariableSubstitution substitutes variables in playbook queries with values from the provided event data
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

// BuildQuestionRange builds a date range string for a question based on event timestamp and range specification
// Range format examples: "+/-3d", "-1h", "30m", "2s"
// Returns a formatted date range string like "2024/01/01 12:00:00 PM - 2024/01/01 01:00:00 PM"
func buildQuestionRange(event *model.EventRecord, rangeStr string, timezone string) string {
	if rangeStr == "" {
		return ""
	}

	// Get event timestamp
	eventTime := getEventTimestamp(event)
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

// ============================================================================
// Custom Playbook CRUD Operations
// ============================================================================

// loadCustomPlaybooks loads custom playbooks from the JSON file
func (pdm *PlaybookDiskManager) loadCustomPlaybooks() error {
	pdm.customPlaybooksMutex.Lock()
	defer pdm.customPlaybooksMutex.Unlock()

	data, err := os.ReadFile(pdm.customPlaybooksFile)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's okay
			return nil
		}
		return fmt.Errorf("failed to read custom playbooks file: %w", err)
	}

	var playbooks []*model.Playbook
	if err := json.Unmarshal(data, &playbooks); err != nil {
		return fmt.Errorf("failed to unmarshal custom playbooks: %w", err)
	}

	pdm.customPlaybooks = make(map[string]*model.Playbook)
	for _, pb := range playbooks {
		pdm.customPlaybooks[pb.Id] = pb
	}

	return nil
}

// saveCustomPlaybooks saves custom playbooks to the JSON file
func (pdm *PlaybookDiskManager) saveCustomPlaybooks() error {
	pdm.customPlaybooksMutex.RLock()
	playbooks := make([]*model.Playbook, 0, len(pdm.customPlaybooks))
	for _, pb := range pdm.customPlaybooks {
		playbooks = append(playbooks, pb)
	}
	pdm.customPlaybooksMutex.RUnlock()

	data, err := json.MarshalIndent(playbooks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal custom playbooks: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(pdm.customPlaybooksFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for custom playbooks: %w", err)
	}

	if err := os.WriteFile(pdm.customPlaybooksFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write custom playbooks file: %w", err)
	}

	return nil
}

// CreatePlaybook creates a new custom playbook
func (pdm *PlaybookDiskManager) CreatePlaybook(ctx context.Context, playbook *model.Playbook) (*model.Playbook, error) {
	logger := log.FromContext(ctx)

	if err := pdm.srv.CheckAuthorized(ctx, "write", "playbooks"); err != nil {
		return nil, err
	}

	// Validate playbook
	if err := playbook.Validate(); err != nil {
		return nil, err
	}

	// Ensure no ID is set for new playbooks
	if playbook.Id != "" {
		return nil, errors.New("unexpected ID found in new playbook")
	}

	// Cannot create community playbooks via API
	if playbook.IsCommunity {
		return nil, errors.New("cannot create community playbooks via API")
	}

	// Set custom ruleset
	playbook.Ruleset = model.PLAYBOOK_RULESET_CUSTOM
	playbook.IsCommunity = false

	// Set timestamps
	now := time.Now()
	playbook.CreateTime = &now

	// Generate ID
	playbook.Id = uuid.New().String()

	// Set kind
	playbook.Kind = "playbook"

	// Get user ID from context
	if userID, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		playbook.UserId = userID
	}

	// Save to custom playbooks
	pdm.customPlaybooksMutex.Lock()
	pdm.customPlaybooks[playbook.Id] = playbook
	pdm.customPlaybooksMutex.Unlock()

	if err := pdm.saveCustomPlaybooks(); err != nil {
		// Rollback
		pdm.customPlaybooksMutex.Lock()
		delete(pdm.customPlaybooks, playbook.Id)
		pdm.customPlaybooksMutex.Unlock()
		return nil, err
	}

	logger.WithFields(log.Fields{
		"playbookId":   playbook.Id,
		"playbookName": playbook.Name,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
		"userId":       playbook.UserId,
	}).Info("Playbook created")

	return playbook, nil
}

// UpdatePlaybook updates an existing custom playbook
func (pdm *PlaybookDiskManager) UpdatePlaybook(ctx context.Context, playbook *model.Playbook) (*model.Playbook, error) {
	logger := log.FromContext(ctx)

	if err := pdm.srv.CheckAuthorized(ctx, "write", "playbooks"); err != nil {
		return nil, err
	}

	// Validate playbook
	if err := playbook.Validate(); err != nil {
		return nil, err
	}

	// Require ID for updates
	if playbook.Id == "" {
		return nil, errors.New("missing playbook ID")
	}

	// Get existing playbook
	pdm.customPlaybooksMutex.RLock()
	existing, exists := pdm.customPlaybooks[playbook.Id]
	pdm.customPlaybooksMutex.RUnlock()

	if !exists {
		return nil, errors.New("playbook not found")
	}

	// Cannot update community playbooks
	if existing.IsCommunity {
		return nil, errors.New("cannot update community playbooks")
	}

	// Preserve read-only fields
	playbook.CreateTime = existing.CreateTime
	playbook.IsCommunity = existing.IsCommunity
	playbook.Ruleset = existing.Ruleset

	// Update timestamp
	now := time.Now()
	playbook.UpdateTime = &now

	// Get user ID from context
	if userID, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		playbook.UserId = userID
	}

	// Save to custom playbooks
	pdm.customPlaybooksMutex.Lock()
	oldPlaybook := pdm.customPlaybooks[playbook.Id]
	pdm.customPlaybooks[playbook.Id] = playbook
	pdm.customPlaybooksMutex.Unlock()

	if err := pdm.saveCustomPlaybooks(); err != nil {
		// Rollback
		pdm.customPlaybooksMutex.Lock()
		pdm.customPlaybooks[playbook.Id] = oldPlaybook
		pdm.customPlaybooksMutex.Unlock()
		return nil, err
	}

	logger.WithFields(log.Fields{
		"playbookId":   playbook.Id,
		"playbookName": playbook.Name,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
		"userId":       playbook.UserId,
	}).Info("Playbook updated")

	return playbook, nil
}

// DeletePlaybook deletes a custom playbook
func (pdm *PlaybookDiskManager) DeletePlaybook(ctx context.Context, playbookId string) error {
	logger := log.FromContext(ctx)

	if err := pdm.srv.CheckAuthorized(ctx, "write", "playbooks"); err != nil {
		return err
	}

	// Get existing playbook
	pdm.customPlaybooksMutex.RLock()
	existing, exists := pdm.customPlaybooks[playbookId]
	pdm.customPlaybooksMutex.RUnlock()

	if !exists {
		return errors.New("playbook not found")
	}

	// Cannot delete community playbooks
	if existing.IsCommunity {
		return errors.New("cannot delete community playbooks")
	}

	// Delete from custom playbooks
	pdm.customPlaybooksMutex.Lock()
	delete(pdm.customPlaybooks, playbookId)
	pdm.customPlaybooksMutex.Unlock()

	if err := pdm.saveCustomPlaybooks(); err != nil {
		// Rollback
		pdm.customPlaybooksMutex.Lock()
		pdm.customPlaybooks[playbookId] = existing
		pdm.customPlaybooksMutex.Unlock()
		return err
	}

	logger.WithFields(log.Fields{
		"playbookId":   playbookId,
		"playbookName": existing.Name,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
		"userId":       ctx.Value(web.ContextKeyRequestorId),
	}).Info("Playbook deleted")

	return nil
}

// GetAllPlaybooks returns all playbooks (both community and custom)
func (pdm *PlaybookDiskManager) GetAllPlaybooks(ctx context.Context) ([]*model.Playbook, error) {
	if err := pdm.srv.CheckAuthorized(ctx, "read", "playbooks"); err != nil {
		return nil, err
	}

	playbooks := []*model.Playbook{}

	// Get community playbooks from disk
	pdm.pbUpdateMutex.RLock()
	for id, path := range pdm.playbooksOnDisk {
		contents, err := pdm.ReadFile(path)
		if err != nil {
			log.WithError(err).WithField("playbookId", id).Warn("failed to read playbook file")
			continue
		}

		pb := &model.Playbook{}
		if err := yaml.Unmarshal(contents, pb); err != nil {
			log.WithError(err).WithField("playbookId", id).Warn("failed to unmarshal playbook")
			continue
		}

		pb.IsCommunity = true
		playbooks = append(playbooks, pb)
	}
	pdm.pbUpdateMutex.RUnlock()

	// Get custom playbooks
	pdm.customPlaybooksMutex.RLock()
	for _, pb := range pdm.customPlaybooks {
		playbooks = append(playbooks, pb)
	}
	pdm.customPlaybooksMutex.RUnlock()

	return playbooks, nil
}

// getCustomPlaybooksForDetection returns custom playbooks matching the given detection criteria
func (pdm *PlaybookDiskManager) getCustomPlaybooksForDetection(detectionId string, detectCategory string, detectEngine model.EngineName) []*model.Playbook {
	pdm.customPlaybooksMutex.RLock()
	defer pdm.customPlaybooksMutex.RUnlock()

	var results []*model.Playbook
	detectionIdLower := strings.ToLower(detectionId)
	categoryLower := strings.ToLower(detectCategory)

	// Map engine to detection type
	var detectType string
	switch detectEngine {
	case model.EngineNameElastAlert:
		detectType = "sigma"
	case model.EngineNameStrelka:
		detectType = "yara"
	case model.EngineNameSuricata:
		detectType = "nids"
	}

	for _, pb := range pdm.customPlaybooks {
		// Match by detection ID
		if pb.DetectionId != "" && strings.ToLower(pb.DetectionId) == detectionIdLower {
			results = append(results, pb)
			continue
		}

		// Match by category
		if pb.DetectionCategory != "" && strings.ToLower(pb.DetectionCategory) == categoryLower {
			// Also check detection type if specified
			if pb.DetectionType == "" || strings.ToLower(pb.DetectionType) == detectType {
				results = append(results, pb)
				continue
			}
		}

		// Match by engine type (for generic playbooks)
		if pb.DetectionId == "" && pb.DetectionCategory == "" {
			if strings.ToLower(pb.DetectionType) == detectType {
				results = append(results, pb)
			}
		}
	}

	return results
}
