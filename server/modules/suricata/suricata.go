// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

var sidExtracter = regexp.MustCompile(`(?i)\bsid: ?['"]?(.*?)['"]?;`)

const modifyFromTo = `"flowbits" "noalert; flowbits"`

var errModuleStopped = fmt.Errorf("module has stopped running")

var licenseBySource = map[string]string{
	"etopen": model.LicenseBSD,
	"etpro":  model.LicenseCommercial,
}

type SuricataEngine struct {
	srv                                  *server.Server
	communityRulesFile                   string
	rulesFingerprintFile                 string
	communityRulesImportFrequencySeconds int
	isRunning                            bool
	thread                               *sync.WaitGroup
}

func NewSuricataEngine(srv *server.Server) *SuricataEngine {
	return &SuricataEngine{
		srv: srv,
	}
}

func (s *SuricataEngine) PrerequisiteModules() []string {
	return nil
}

func (s *SuricataEngine) Init(config module.ModuleConfig) (err error) {
	s.communityRulesFile = module.GetStringDefault(config, "communityRulesFile", "/nsm/rules/suricata/emerging-all.rules")
	s.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", "/opt/so/conf/soc/emerging-all.fingerprint")
	s.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", 5)

	return nil
}

func (s *SuricataEngine) Start() error {
	s.srv.DetectionEngines[model.EngineNameSuricata] = s
	s.thread = &sync.WaitGroup{}
	s.thread.Add(1)
	s.isRunning = true

	go s.watchCommunityRules()

	return nil
}

func (s *SuricataEngine) Stop() error {
	s.isRunning = false
	s.thread.Wait()

	return nil
}

func (s *SuricataEngine) IsRunning() bool {
	return s.isRunning
}

func (s *SuricataEngine) ConvertRule(ctx context.Context, detect *model.Detection) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (s *SuricataEngine) watchCommunityRules() {
	defer func() {
		s.thread.Done()
		s.isRunning = false
	}()

	ctx := s.srv.Context

	for s.isRunning {
		time.Sleep(time.Duration(s.communityRulesImportFrequencySeconds) * time.Second)
		if !s.isRunning {
			break
		}

		start := time.Now()

		rules, hash, err := readAndHash(s.communityRulesFile)
		if err != nil {
			log.WithError(err).Error("unable to read community rules file")
			continue
		}

		fingerprint, haveFP, err := readFingerprint(s.rulesFingerprintFile)
		if err != nil {
			log.WithError(err).Error("unable to read rules fingerprint file")
			continue
		}

		if haveFP && strings.EqualFold(*fingerprint, hash) {
			// if we have a fingerprint and the hashes are equal, there's nothing to do
			continue
		}

		allSettings, err := s.srv.Configstore.GetSettings(ctx)
		if err != nil {
			log.WithError(err).Error("unable to get settings")
			continue
		}

		ruleset := settingByID(allSettings, "idstools.config.ruleset")

		commDetections, err := s.parseRules(rules, ruleset.Value)
		if err != nil {
			log.WithError(err).Error("unable to parse community rules")
			continue
		}

		errMap, err := s.syncCommunityDetections(ctx, commDetections)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of suricata community detections due to module stopping")
				return
			}

			log.WithError(err).Error("unable to sync suricata community detections")
			continue
		}

		if len(errMap) > 0 {
			// there were errors, don't save the fingerprint.
			// idempotency means we might fix it if we try again later.
			log.WithFields(log.Fields{
				"errors": errMap,
			}).Error("unable to sync all community detections")
		} else {
			err = os.WriteFile(s.rulesFingerprintFile, []byte(hash), 0644)
			if err != nil {
				log.WithError(err).WithField("path", s.rulesFingerprintFile).Error("unable to write rules fingerprint file")
			}
		}

		dur := time.Since(start)

		log.WithFields(log.Fields{
			"durationSeconds": dur.Seconds(),
		}).Info("suricata community rules synced")
	}
}

func readAndHash(path string) (content string, sha256Hash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	hasher := sha256.New()
	data := io.TeeReader(f, hasher)

	raw, err := io.ReadAll(data)
	if err != nil {
		return "", "", err
	}

	return string(raw), hex.EncodeToString(hasher.Sum(nil)), nil
}

func readFingerprint(path string) (fingerprint *string, ok bool, err error) {
	_, err = os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}

		return nil, false, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	fingerprint = util.Ptr(strings.TrimSpace(string(raw)))

	return fingerprint, true, nil
}

func (s *SuricataEngine) ValidateRule(rule string) (string, error) {
	parsed, err := ParseSuricataRule(rule)
	if err != nil {
		return rule, err
	}

	return parsed.String(), nil
}

func (s *SuricataEngine) parseRules(content string, ruleset string) ([]*model.Detection, error) {
	// expecting one rule per line
	lines := strings.Split(content, "\n")
	dets := []*model.Detection{}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			// empty or commented line, ignore
			continue
		}

		line, err := s.ValidateRule(line)
		if err != nil {
			return nil, fmt.Errorf("unable to parse line %d: %w", i+1, err)
		}

		parsed, err := ParseSuricataRule(line)
		if err != nil {
			return nil, fmt.Errorf("unable to parse line %d: %w", i+1, err)
		}

		// extract details
		sidOpt, ok := parsed.GetOption("sid")
		if !ok || sidOpt == nil || len(*sidOpt) == 0 {
			return nil, fmt.Errorf("unable to parse line %d: rule does not contain a SID", i+1)
		}

		sid, err := strconv.Unquote(*sidOpt)
		if err != nil {
			sid = *sidOpt
		}

		msg := sid

		msgOpt, ok := parsed.GetOption("msg")
		if ok && msgOpt != nil && len(*msgOpt) != 0 {
			msg = *msgOpt
		}

		msg = strings.ReplaceAll(msg, `\;`, `;`)

		title, err := strconv.Unquote(msg)
		if err != nil {
			title = msg
		}

		title = strings.ReplaceAll(title, `\"`, `"`)
		title = strings.ReplaceAll(title, `\\`, `\`)

		severity := model.SeverityUnknown // TODO: Default severity?

		md := parsed.ParseMetaData()
		if md != nil {
			sigsev, ok := lo.Find(md, func(m *MetaData) bool {
				return strings.EqualFold(m.Key, "signature_severity")
			})
			if ok {
				switch strings.ToUpper(sigsev.Value) {
				case "INFORMATIONAL":
					severity = model.SeverityInformational
				case "MINOR":
					severity = model.SeverityLow
				case "MAJOR":
					severity = model.SeverityHigh
				case "CRITICAL":
					severity = model.SeverityCritical
				}
			}
		}

		dets = append(dets, &model.Detection{
			PublicID:    sid,
			Title:       title,
			Severity:    severity,
			Content:     line,
			IsCommunity: true,
			Engine:      model.EngineNameSuricata,
			Language:    model.SigLangSuricata,
			Ruleset:     util.Ptr(ruleset),
			License:     lookupLicense(ruleset),
		})
	}

	return dets, nil
}

func (s *SuricataEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	allSettings, err := s.srv.Configstore.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	local := settingByID(allSettings, "idstools.rules.local__rules")
	if local == nil {
		return nil, fmt.Errorf("unable to find local rules setting")
	}

	enabled := settingByID(allSettings, "idstools.sids.enabled")
	if enabled == nil {
		return nil, fmt.Errorf("unable to find enabled setting")
	}

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	if disabled == nil {
		return nil, fmt.Errorf("unable to find disabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return nil, fmt.Errorf("unable to find modify setting")
	}

	threshold := settingByID(allSettings, "suricata.thresholding.sids__yaml")

	localLines := strings.Split(local.Value, "\n")
	enabledLines := strings.Split(enabled.Value, "\n")
	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")

	localIndex := indexLocal(localLines)
	enabledIndex := indexEnabled(enabledLines, false)
	disabledIndex := indexEnabled(disabledLines, false)
	modifyIndex := indexModify(modifyLines)

	thresholdIndex, err := indexThreshold(threshold.Value)
	if err != nil {
		return nil, err
	}

	errMap = map[string]string{} // map[sid]error

	for _, detect := range detections {
		parsedRule, err := ParseSuricataRule(detect.Content)
		if err != nil {
			errMap[detect.PublicID] = fmt.Sprintf("unable to parse rule; reason=%s", err.Error())
			continue
		}

		opt, ok := parsedRule.GetOption("sid")
		if !ok || opt == nil {
			errMap[detect.PublicID] = fmt.Sprintf("rule does not contain a SID; rule=%s", detect.Content)
			continue
		}

		sid := *opt
		_, isFlowbits := parsedRule.GetOption("flowbits")

		lineNum, inLocal := localIndex[sid]
		if !inLocal {
			localLines = append(localLines, detect.Content)
			lineNum = len(localLines) - 1
			localIndex[sid] = lineNum
		} else {
			localLines[lineNum] = detect.Content
		}

		lineNum, inEnabled := enabledIndex[sid]
		if !inEnabled {
			line := detect.PublicID
			if !detect.IsEnabled && !isFlowbits {
				line = "# " + line
			}

			enabledLines = append(enabledLines, line)
			lineNum = len(enabledLines) - 1
			enabledIndex[sid] = lineNum
		} else {
			line := detect.PublicID
			if !detect.IsEnabled && !isFlowbits {
				line = "# " + line
			}

			enabledLines[lineNum] = line
		}

		if !isFlowbits {
			lineNum, inDisabled := disabledIndex[sid]
			if !inDisabled {
				line := detect.PublicID
				if detect.IsEnabled {
					line = "# " + line
				}

				disabledLines = append(disabledLines, line)
				lineNum = len(disabledLines) - 1
				disabledIndex[sid] = lineNum
			} else {
				line := detect.PublicID
				if detect.IsEnabled {
					line = "# " + line
				}

				disabledLines[lineNum] = line
			}
		}

		if isFlowbits {
			lineNum, inModify := modifyIndex[sid]
			if !inModify && !detect.IsEnabled {
				// not in the modify file, but should be
				line := fmt.Sprintf("%s %s", detect.PublicID, modifyFromTo)
				modifyLines = append(modifyLines, line)
				lineNum = len(modifyLines) - 1
				modifyIndex[sid] = lineNum
			} else if inModify && detect.IsEnabled {
				// in modify, but shouldn't be
				var after []string
				before := modifyLines[:lineNum]

				if lineNum+1 < len(modifyLines) {
					after = modifyLines[lineNum+1:]
				}

				modifyLines = append(before, after...)
				delete(modifyIndex, sid)
			}
		}

		// tuning
		delete(thresholdIndex, detect.PublicID)
		detOverrides := lo.Filter(detect.Overrides, func(o *model.Override, _ int) bool {
			return o.IsEnabled
		})

		if len(detOverrides) > 0 {
			// the only place we care about genID, we don't get it from the user except
			// through the content of the rule. Default to 1 if we can't find it.
			genID := 1

			gid, ok := parsedRule.GetOption("gid")
			if ok && gid != nil {
				id, err := strconv.Atoi(*gid)
				if err != nil {
					genID = id
				}
			}

			for _, o := range detOverrides {
				if o.Type == model.OverrideTypeSuppress || o.Type == model.OverrideTypeThreshold {
					o.GenID = util.Ptr(genID)
				}
			}

			thresholdIndex[detect.PublicID] = detOverrides
		}
	}

	local.Value = strings.Join(localLines, "\n")
	enabled.Value = strings.Join(enabledLines, "\n")
	disabled.Value = strings.Join(disabledLines, "\n")
	modify.Value = strings.Join(modifyLines, "\n")

	yamlThreshold, err := yaml.Marshal(thresholdIndex)
	if err != nil {
		return errMap, err
	}

	threshold.Value = string(yamlThreshold)

	err = s.srv.Configstore.UpdateSetting(ctx, local, false)
	if err != nil {
		return errMap, err
	}

	err = s.srv.Configstore.UpdateSetting(ctx, enabled, false)
	if err != nil {
		return errMap, err
	}

	err = s.srv.Configstore.UpdateSetting(ctx, disabled, false)
	if err != nil {
		return errMap, err
	}

	err = s.srv.Configstore.UpdateSetting(ctx, modify, false)
	if err != nil {
		return errMap, err
	}

	err = s.srv.Configstore.UpdateSetting(ctx, threshold, false)
	if err != nil {
		return errMap, err
	}

	return errMap, nil
}

func (s *SuricataEngine) syncCommunityDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()
	errMap = map[string]string{}

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
	}{}

	allSettings, err := s.srv.Configstore.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	if disabled == nil {
		return nil, fmt.Errorf("unable to find disabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return nil, fmt.Errorf("unable to find modify setting")
	}

	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")

	disabledIndex := indexEnabled(disabledLines, true)
	modifyIndex := indexModify(modifyLines)

	commSIDs, err := s.srv.Detectionstore.GetAllCommunitySIDs(ctx, util.Ptr(model.EngineNameSuricata))
	if err != nil {
		return nil, err
	}

	toDelete := map[string]struct{}{}
	for sid := range commSIDs {
		toDelete[sid] = struct{}{}
	}

	for _, detect := range detections {
		if !s.isRunning {
			return errMap, errModuleStopped
		}

		_, disabled := disabledIndex[detect.PublicID]
		_, modified := modifyIndex[detect.PublicID]
		detect.IsEnabled = !(disabled || modified)

		orig, exists := commSIDs[detect.PublicID]
		if exists {
			if orig.Content != detect.Content {
				detect.Id = orig.Id
				detect.Overrides = orig.Overrides

				_, err = s.srv.Detectionstore.UpdateDetection(ctx, detect)
				if err != nil {
					errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
				} else {
					results.Updated++
					delete(toDelete, detect.PublicID)
				}
			} else {
				results.Unchanged++
				delete(toDelete, detect.PublicID)
			}
		} else {
			_, err = s.srv.Detectionstore.CreateDetection(ctx, detect)
			if err != nil {
				errMap[detect.PublicID] = fmt.Sprintf("unable to create detection; reason=%s", err.Error())
			} else {
				results.Added++
			}
		}
	}

	for sid := range toDelete {
		_, err = s.srv.Detectionstore.DeleteDetection(ctx, commSIDs[sid].Id)
		if err != nil {
			errMap[sid] = fmt.Sprintf("unable to delete detection; reason=%s", err.Error())
		} else {
			results.Removed++
		}
	}

	log.WithFields(log.Fields{
		"added":     results.Added,
		"updated":   results.Updated,
		"removed":   results.Removed,
		"unchanged": results.Unchanged,
		"errors":    errMap,
	}).Info("suricata community diff")

	return errMap, nil
}

func settingByID(all []*model.Setting, id string) *model.Setting {
	found, ok := lo.Find(all, func(s *model.Setting) bool {
		return s.Id == id
	})
	if !ok {
		return nil
	}

	return found
}

func extractSID(rule string) *string {
	sids := sidExtracter.FindAllStringSubmatch(rule, 2)
	if len(sids) != 1 { // 1 match = 1 sid
		return nil
	}

	return util.Ptr(strings.TrimSpace(sids[0][1]))
}

func indexLocal(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		sid := extractSID(line)
		if sid == nil {
			continue
		}

		index[*sid] = i
	}

	return index
}

func indexEnabled(lines []string, ignoreComments bool) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") && ignoreComments {
			continue
		}

		line = strings.TrimLeft(line, "# \t")
		if line != "" {
			index[line] = i
		}
	}

	return index
}

func indexModify(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		line = strings.TrimSpace(strings.TrimLeft(line, "# \t"))

		if strings.HasSuffix(line, modifyFromTo) {
			parts := strings.SplitN(line, " ", 2)
			index[parts[0]] = i
		}
	}

	return index
}

func indexThreshold(content string) (map[string][]*model.Override, error) {
	index := map[string][]*model.Override{}

	err := yaml.Unmarshal([]byte(content), &index)
	if err != nil {
		return nil, err
	}

	return index, nil
}

func lookupLicense(ruleset string) string {
	license, ok := licenseBySource[strings.ToLower(ruleset)]
	if !ok {
		license = "Unknown"
	}

	return license
}
