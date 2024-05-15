package suricata

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"gopkg.in/yaml.v3"
)

const (
	idstoolsYaml = "/nsm/backup/detections-migration/idstools/soc_idstools.sls"       // enabled/disabled
	sidsYaml     = "/nsm/backup/detections-migration/suricata/thresholding/sids.yaml" // thresholds
)

func (e *SuricataEngine) Migration2470(statePath string) error {
	shouldMigrate, err := e.m2470ReadStateFile(statePath)
	if err != nil {
		return err
	}

	if !shouldMigrate {
		log.Info("state file indicates that the migration to 2.4.70 has already been performed")
		return nil
	}

	log.Info("suricata is now migrating to 2.4.70") // for support

	// read in idstools.yaml
	enabled, disabled, err := e.m2470LoadEnabledDisabled()
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"enabledCount":  len(enabled),
		"disabledCount": len(disabled),
	}).Info("successfully read in enabled/disabled sids")

	dirty := map[string]struct{}{} // map[sid]X

	// retrieve all suricata rules
	detects, err := e.srv.Detectionstore.GetAllDetections(e.srv.Context, util.Ptr(model.EngineNameSuricata), nil)
	if err != nil {
		return err
	}

	// disable
	toDisable, err := e.m2470ApplyList(disabled, detects)
	if err != nil {
		return err
	}

	e.m2470ToggleEnabled(detects, toDisable, false)

	for sid := range toDisable {
		dirty[sid] = struct{}{}
	}

	log.WithField("detectionsEnabledCount", len(toDisable)).Info("successfully disabled detections")

	// enable
	toEnable, err := e.m2470ApplyList(enabled, detects)
	if err != nil {
		return err
	}

	e.m2470ToggleEnabled(detects, toEnable, true)

	for sid := range toEnable {
		dirty[sid] = struct{}{}
	}

	log.WithField("detectionsEnabledCount", len(toEnable)).Info("successfully enabled detections")

	// suppressions
	overrides, err := e.m2470LoadOverrides()
	if err != nil {
		return err
	}

	e.m2470ApplyOverrides(detects, overrides)

	for sid := range overrides {
		dirty[sid] = struct{}{}
	}

	// update dirty detections
	dirtyDets := make([]*model.Detection, 0, len(dirty))
	for sid := range dirty {
		det, ok := detects[sid]
		if !ok {
			continue
		}

		det.Kind = ""

		_, err := e.srv.Detectionstore.UpdateDetection(e.srv.Context, det)
		if err != nil {
			return err
		}

		dirtyDets = append(dirtyDets, det)
	}

	// sync suricata
	errMap, err := e.srv.DetectionEngines[model.EngineNameSuricata].SyncLocalDetections(e.srv.Context, dirtyDets)
	if err != nil {
		return err
	}

	err = e.m2470WriteStateFileSuccess(statePath)
	if err != nil {
		return err
	}

	log.WithField("errMap", errMap).Info("suricata has successfully migrated to 2.4.70") // for support

	return nil
}

func (e *SuricataEngine) m2470ReadStateFile(path string) (shouldMigrate bool, err error) {
	state, err := e.ReadFile(path)
	if err != nil {
		return false, err
	}

	log.WithField("stateFileContent", string(state)).Info("reading state file for migration to 2.4.70")

	s := strings.TrimSpace(string(state))
	if s == "1" {
		return false, nil
	}

	if s == "0" {
		return true, nil
	}

	return false, fmt.Errorf("unexpected state file content: %s", s)
}

func (e *SuricataEngine) m2470WriteStateFileSuccess(path string) (err error) {
	return e.WriteFile(path, []byte("1"), 0644)
}

func (e *SuricataEngine) m2470LoadEnabledDisabled() (enabled []string, disabled []string, err error) {
	// read in idstools.yaml
	raw, err := e.ReadFile(idstoolsYaml)
	if err != nil {
		return nil, nil, err
	}

	root := map[string]interface{}{}

	err = yaml.Unmarshal(raw, &root)
	if err != nil {
		return nil, nil, err
	}

	idstools, ok := root["idstools"].(map[string]interface{})
	if !ok {
		return nil, nil, nil
	}

	sids, ok := idstools["sids"].(map[string]interface{})
	if !ok {
		return nil, nil, nil
	}

	en, ok := sids["enabled"].([]interface{})
	if ok {
		enabled = make([]string, 0, len(en))
		for _, v := range en {
			enabled = append(enabled, v.(string))
		}
	}

	dis, ok := sids["disabled"].([]interface{})
	if ok {
		disabled = make([]string, 0, len(dis))
		for _, v := range dis {
			disabled = append(disabled, v.(string))
		}
	}

	return enabled, disabled, nil
}

func (e *SuricataEngine) m2470ApplyList(process []string, detects map[string]*model.Detection) (sids map[string]struct{}, err error) {
	set := map[string]struct{}{}

	for _, sid := range process {
		sid = strings.TrimSpace(sid)
		if strings.HasPrefix(strings.ToLower(sid), "re:") {
			// regex
			re, err := regexp.Compile(sid[3:])
			if err != nil {
				// bad regex, can't filter
				continue
			}

			// apply regex to rule content
			for pid, d := range detects {
				if re.MatchString(d.Content) {
					set[pid] = struct{}{}
				}
			}

			continue
		}

		// single sid
		_, ok := detects[sid]
		if ok {
			set[sid] = struct{}{}
		}
	}

	return set, nil
}

func (e *SuricataEngine) m2470ToggleEnabled(detects map[string]*model.Detection, sids map[string]struct{}, enable bool) {
	for sid := range sids {
		d, ok := detects[sid]
		if ok {
			d.IsEnabled = enable
		}
	}
}

func (e *SuricataEngine) m2470LoadOverrides() (overrides map[string][]*model.Override, err error) {
	raw, err := e.ReadFile(sidsYaml)
	if err != nil {
		return nil, err
	}

	overrides = map[string][]*model.Override{}

	err = yaml.Unmarshal(raw, &overrides)
	if err != nil {
		return nil, err
	}

	return overrides, nil
}

func (e *SuricataEngine) m2470ApplyOverrides(detects map[string]*model.Detection, overrides map[string][]*model.Override) {
	for pid, overrides := range overrides {
		d, ok := detects[pid]
		if ok {
			for _, o := range overrides {
				o.IsEnabled = true
			}

			d.Overrides = append(d.Overrides, overrides...)
		}
	}
}
