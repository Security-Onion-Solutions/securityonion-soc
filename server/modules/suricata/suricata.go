package suricata

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

var sidExtracter = regexp.MustCompile(`(?i)\bsid: ?['"]?(.*?)['"]?;`)

const modifyFromTo = `"flowbits" "noalert; flowbits"`

type SuricataEngine struct {
	srv *server.Server
}

func NewSuricataEngine(srv *server.Server) *SuricataEngine {
	return &SuricataEngine{
		srv: srv,
	}
}

func (s *SuricataEngine) PrerequisiteModules() []string {
	return nil
}

func (s *SuricataEngine) Init(config module.ModuleConfig) error {
	return nil
}

func (s *SuricataEngine) Start() error {
	s.srv.DetectionEngines[model.EngineNameSuricata] = s
	return nil
}

func (s *SuricataEngine) Stop() error {
	return nil
}

func (s *SuricataEngine) IsRunning() bool {
	return false
}

func (s *SuricataEngine) ValidateRule(rule string) (string, error) {
	parsed, err := ParseSuricataRule(rule)
	if err != nil {
		return rule, err
	}

	return parsed.String(), nil
}

func (s *SuricataEngine) ParseRules(content string) ([]*model.Detection, error) {
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
					severity = model.SeverityMinor
				case "MAJOR":
					severity = model.SeverityMajor
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
			IsEnabled:   true, // is this true?
			IsCommunity: true,
			Engine:      model.EngineNameSuricata,
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

	localLines := strings.Split(local.Value, "\n")
	enabledLines := strings.Split(enabled.Value, "\n")
	disabledLines := strings.Split(disabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")

	localIndex := indexLocal(localLines)
	enabledIndex := indexEnabled(enabledLines)
	disabledIndex := indexEnabled(disabledLines)
	modifyIndex := indexModify(modifyLines)

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
				modifyLines = append(modifyLines[:lineNum], modifyLines[lineNum+1:]...)
				delete(modifyIndex, sid)
			}
		}
	}

	local.Value = strings.Join(localLines, "\n")
	enabled.Value = strings.Join(enabledLines, "\n")
	disabled.Value = strings.Join(disabledLines, "\n")
	modify.Value = strings.Join(modifyLines, "\n")

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

	return errMap, nil
}

func (s *SuricataEngine) SyncCommunityDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()
	errMap = map[string]string{}

	results := struct {
		Added   int
		Updated int
		Removed int
	}{}

	commSIDs, err := s.srv.Detectionstore.GetAllCommunitySIDs(ctx)
	if err != nil {
		return nil, err
	}

	toDelete := map[string]struct{}{}
	for sid := range commSIDs {
		toDelete[sid] = struct{}{}
	}

	for _, detect := range detections {
		id, exists := commSIDs[detect.PublicID]
		if exists {
			detect.Id = id

			_, err = s.srv.Detectionstore.UpdateDetection(ctx, detect)
			if err != nil {
				errMap[detect.PublicID] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
			} else {
				results.Updated++
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
		_, err = s.srv.Detectionstore.DeleteDetection(ctx, sid)
		if err != nil {
			errMap[sid] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
		} else {
			results.Removed++
		}
	}

	log.WithFields(log.Fields{
		"added":   results.Added,
		"updated": results.Updated,
		"removed": results.Removed,
		"errors":  errMap,
	}).Info("Suricata community detections synced")

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

func indexEnabled(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		line = strings.TrimSpace(strings.TrimLeft(line, "# \t"))
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
