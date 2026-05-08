// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/salt/options"
	"github.com/security-onion-solutions/securityonion-soc/syntax"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"gopkg.in/yaml.v3"
)

type Saltstore struct {
	server             *server.Server
	client             *web.Client
	timeoutMs          int
	longRelayTimeoutMs int
	saltstackDir       string
	queueDir           string
	bypassEnabled      bool
	annotations        map[string]map[string]interface{}
}

func NewSaltstore(server *server.Server) *Saltstore {
	return &Saltstore{
		server: server,
	}
}

func (store *Saltstore) Init(timeoutMs int, longRelayTimeoutMs int, saltstackDir string, queueDir string, bypassEnabled bool) error {
	store.timeoutMs = timeoutMs
	store.longRelayTimeoutMs = longRelayTimeoutMs
	store.saltstackDir = strings.TrimSuffix(saltstackDir, "/")
	store.queueDir = queueDir
	store.bypassEnabled = bypassEnabled

	if store.bypassEnabled {
		go store.PreloadConfiguration()
	} else {
		return store.PreloadConfiguration()
	}

	return nil
}

func (store *Saltstore) PreloadConfiguration() error {
	// Pre-load annotations and default settings from the default pillar directory
	var err error
	defaultDir := store.saltstackDir + "/default"
	if _, statErr := os.Stat(defaultDir); statErr == nil {
		var defaults map[string]string
		store.annotations, defaults, err = LoadStaticConfiguration(defaultDir, store.parseYaml)
		if err == nil {
			HydrateAnnotations(store.annotations, defaults, func(id string) (string, bool) {
				relpath := RelPathFromId(id)
				content, err := store.readFile(fmt.Sprintf("%s/default/salt/%s", store.saltstackDir, relpath))
				return content, err == nil
			})
		}
	}

	if err != nil {
		log.WithError(err).Warn("Failed to load pillar data")
		if !store.bypassEnabled {
			return err
		}
	}

	return nil
}

func (store *Saltstore) execCommand(ctx context.Context, args map[string]string) (string, error) {
	logger := log.FromContext(ctx)

	reqId := ctx.Value(web.ContextKeyRequestId).(string)
	cmd := args["command"]
	id := reqId + "_" + cmd
	args["command_id"] = id

	filename := filepath.Join(store.queueDir, id)
	logger.WithFields(log.Fields{
		"filename": filename,
	}).Info("Executing command via salt relay")

	err := json.WriteJsonFile(filename, args)
	if err != nil {
		logger.WithFields(log.Fields{
			"filename": filename,
		}).WithError(err).Error("Unable to write to file")

		return "", err
	}

	responseFilename := filename + ".response"
	logger.WithFields(log.Fields{
		"responseFilename": responseFilename,
		"timeoutMs":        store.timeoutMs,
	}).Info("Waiting for response")

	timeoutMs := store.timeoutMs
	optTimeoutMs := options.GetTimeoutMs(ctx)

	if optTimeoutMs > timeoutMs {
		timeoutMs = optTimeoutMs
	}

	var response string
	expiration := time.Duration(timeoutMs) * time.Millisecond
	for timeoutTime := time.Now().Add(expiration); time.Now().Before(timeoutTime); {
		if _, err = os.Stat(responseFilename); err == nil {
			var data []byte
			data, err = os.ReadFile(responseFilename)
			if err != nil {
				logger.WithFields(log.Fields{
					"filename": responseFilename,
				}).WithError(err).Error("Failed to read file")
			} else {
				response = strings.TrimSpace(string(data))
				os.Remove(responseFilename)
				break
			}
		}

		// Assume very short timeouts are used for testing, where the response is already mocked
		if store.timeoutMs > 10 {
			time.Sleep(1000 * time.Millisecond)
		}
	}

	if response == "" {
		return "", errors.New("ERROR_SALT_RELAY_DOWN")
	}

	logger.WithFields(log.Fields{
		"filename": responseFilename,
		"response": response,
	}).Debug("Finished reading response")

	return response, err
}

func (store *Saltstore) getFilteredSettings(ctx context.Context, filterId string) ([]*model.Setting, error) {
	logger := log.FromContext(ctx)
	settings := make([]*model.Setting, 0)

	paths := []string{store.saltstackDir + "/local/pillar"}
	if filterId != "" {
		sections := strings.Split(filterId, ".")
		paths = []string{
			fmt.Sprintf("%s/local/pillar/%s", store.saltstackDir, sections[0]),
			fmt.Sprintf("%s/local/pillar/minions", store.saltstackDir),
		}
	}

	var err error
	for _, walkPath := range paths {
		if filterId != "" {
			if _, statErr := os.Stat(walkPath); statErr != nil {
				continue
			}
		}

		walkErr := store.traversePillars(walkPath, &settings)
		if walkErr != nil {
			err = walkErr
			if !store.bypassEnabled {
				return nil, err
			}
		}
	}

	logger.Info("Loaded settings, preparing to apply annotations")
	// Apply the static pillar annotations, to provide supporting details to the parsed settings above.
	fileLoader := func(id string) (string, string, bool) {
		relpath := RelPathFromId(id)
		// Default is already pre-loaded in the annotations, so we only need to load the local override here.
		value, _ := store.readFile(fmt.Sprintf("%s/local/salt/%s", store.saltstackDir, relpath))
		return "", value, true
	}

	if filterId != "" {
		if ann, ok := store.annotations[filterId]; ok {
			found := false
			for _, setting := range settings {
				if setting.Id == filterId {
					ApplyAnnotations(setting, ann, fileLoader)
					ApplySensitiveMask(setting)
					found = true
				}
			}
			if !found {
				// Add a new setting since there is no existing setting for this annotation
				setting := model.NewSetting(filterId)
				ApplyAnnotations(setting, ann, fileLoader)
				ApplySensitiveMask(setting)
				settings = append(settings, setting)
			}
		}
		// If a filterId was provided, narrow the result to only that ID.
		settings = slices.DeleteFunc(settings, func(s *model.Setting) bool {
			return s.Id != filterId
		})
	} else {
		for id, ann := range store.annotations {
			found := false
			for _, setting := range settings {
				if setting.Id == id {
					ApplyAnnotations(setting, ann, fileLoader)
					ApplySensitiveMask(setting)
					found = true
				}
			}
			if !found {
				// Add a new setting since there is no existing setting for this annotation
				setting := model.NewSetting(id)
				ApplyAnnotations(setting, ann, fileLoader)
				ApplySensitiveMask(setting)
				settings = append(settings, setting)
			}
		}
	}

	PostProcess(settings)
	return settings, err
}

func (store *Saltstore) traversePillars(basePath string, settings *[]*model.Setting) error {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(basePath, entry.Name())
		if entry.IsDir() {
			subEntries, err := os.ReadDir(path)
			if err != nil {
				if !store.bypassEnabled {
					return err
				}
				continue
			}
			for _, subEntry := range subEntries {
				if !subEntry.IsDir() && strings.HasSuffix(subEntry.Name(), ".sls") {
					subPath := filepath.Join(path, subEntry.Name())
					info, _ := subEntry.Info()
					store.processPillarFile(subPath, info, settings)
				}
			}
		} else if strings.HasSuffix(entry.Name(), ".sls") {
			info, _ := entry.Info()
			store.processPillarFile(path, info, settings)
		}
	}
	return nil
}

func (store *Saltstore) processPillarFile(path string, info os.FileInfo, settings *[]*model.Setting) {
	setting_id := strings.TrimSuffix(info.Name(), ".sls")
	minion_id := ""

	is_minion := strings.Contains(path, "/minions/")

	if strings.HasPrefix(setting_id, "adv_") {
		setting_id = strings.TrimPrefix(setting_id, "adv_")

		if is_minion {
			minion_id = setting_id
			setting_id = "advanced"
		} else {
			setting_id = setting_id + ".advanced"
		}

		if info.Size() == 0 {
			// Optimization: avoid reading 0-byte file, just create the empty setting
			setting := model.NewSetting(setting_id)
			if minion_id != "" {
				setting.Global = false
				setting.Node = true
			} else {
				setting.Global = true
				setting.Node = false
			}
			setting.Value = ""
			setting.NodeId = minion_id
			setting.Multiline = true
			setting.Syntax = "yaml"
			*settings = append(*settings, setting)
		} else {
			*settings = store.parseAdvanced(path, *settings, minion_id, setting_id)
		}
	} else if (strings.HasPrefix(setting_id, "soc_") || is_minion) && info.Size() > 0 {
		if is_minion {
			minion_id = setting_id
		}
		var mapped map[string]interface{}
		mapped, _ = store.parseYaml(path)
		if mapped != nil {
			*settings = store.recursivelyParseSettings(path, *settings, mapped, "", minion_id, true)
		}
	}
}

func (store *Saltstore) findSetting(settings []*model.Setting, id string) *model.Setting {
	for _, setting := range settings {
		if setting.Id == id {
			return setting
		}
	}
	return nil
}

func (store *Saltstore) GetSetting(ctx context.Context, id string) (*model.Setting, error) {
	settings, err := store.getFilteredSettings(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(settings) > 0 {
		return settings[0], nil
	}
	return nil, nil
}

func (store *Saltstore) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	var err error
	if err = store.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}

	settings, err := store.getFilteredSettings(ctx, "")
	if err != nil {
		return nil, err
	}

	return Sort(Filter(settings, advanced)), err
}

func (store *Saltstore) parseYaml(path string) (map[string]interface{}, error) {
	var mapped map[string]interface{}
	content, err := os.ReadFile(path)
	if err != nil {
		log.WithFields(log.Fields{
			"path": path,
		}).WithError(err).Error("Unable to read YAML file")
	} else {
		log.WithFields(log.Fields{
			"path":   path,
			"length": len(content),
		}).Debug("Parsing YAML file")
		mapped = make(map[string]interface{})
		err = yaml.Unmarshal(content, &mapped)
		if err != nil {
			log.WithFields(log.Fields{
				"path": path,
			}).WithError(err).Error("Unable to parse YAML file")
		}
	}

	return mapped, err
}

func (store *Saltstore) writeYaml(path string, mapped map[string]interface{}) error {
	contents, err := yaml.Marshal(mapped)
	if err != nil {
		log.WithFields(log.Fields{
			"path": path,
		}).WithError(err).Error("Unable to convert map to YAML")
	} else {
		log.WithFields(log.Fields{
			"path":   path,
			"length": len(contents),
		}).Debug("Writing YAML file")
		err = os.WriteFile(path, contents, 0600)
		if err != nil {
			log.WithFields(log.Fields{
				"path": path,
			}).WithError(err).Error("Unable to write YAML file")
		}
	}

	return err
}

func (store *Saltstore) convertToJson(item interface{}) string {
	bytes, err := json.WriteJson(item)
	if err == nil {
		return string(bytes)
	}

	log.WithField("item", item).WithError(err).Error("Failed to convert map to JSON; setting will be blank")
	return ""
}

func (store *Saltstore) recursivelyParseSettings(
	path string,
	settings []*model.Setting,
	mapped map[string]interface{},
	prefix string,
	minion string,
	merge bool,
) []*model.Setting {

	for id, value := range mapped {
		foundSetting := true
		newValue := ""
		multiline := false

		newPrefix := prefix
		if newPrefix != "" {
			newPrefix = newPrefix + "."
		}

		switch val := value.(type) {
		case map[string]interface{}:
			foundSetting = false
			settings = store.recursivelyParseSettings(path, settings, val, newPrefix+id, minion, merge)
		case []interface{}:
			multiline = true
			for _, item := range val {

				var str string
				switch item.(type) {
				case []interface{}:
					str = store.convertToJson(item)
				case map[string]interface{}:
					str = store.convertToJson(item)
				default:
					str = fmt.Sprintf("%v", item)
				}

				if str != "" {
					newValue = newValue + str + "\n"
				}
			}
		default:
			newValue = fmt.Sprintf("%v", value)
		}

		if foundSetting {
			newId := newPrefix + id

			merged := false
			if minion == "" {
				for _, existing := range settings {
					if existing.Id == newId && existing.NodeId == "" {
						existing.Value = newValue
						if existing.Multiline != multiline {
							log.WithFields(log.Fields{
								"newId":        newId,
								"newMultiline": multiline,
								"oldMultiline": existing.Multiline,
							}).Warn("Existing/Default setting's multiline attribute conflicts with override multiline attribute")
							existing.Multiline = multiline
						}
						merged = true
					}
				}
			}

			if !merged {
				setting := model.NewSetting(newId)
				setting.Value = newValue
				setting.NodeId = minion
				setting.Multiline = multiline
				settings = append(settings, setting)
			}
		}
	}
	return settings
}

func (store *Saltstore) readFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		log.WithFields(log.Fields{
			"path": path,
		}).WithError(err).Debug("Unable to read config file")
	} else {
		log.WithFields(log.Fields{
			"path":   path,
			"length": len(content),
		}).Debug("Reading config file")
		return string(content), nil
	}
	return "", err
}

func (store *Saltstore) parseAdvanced(path string, settings []*model.Setting, minion string, id string) []*model.Setting {
	content, err := store.readFile(path)
	if err == nil {
		setting := model.NewSetting(id)
		if minion != "" {
			setting.Global = false
			setting.Node = true
		} else {
			setting.Global = true
			setting.Node = false
		}
		setting.Value = content
		setting.NodeId = minion
		setting.Multiline = true
		setting.Syntax = "yaml"
		settings = append(settings, setting)
	}

	return settings
}

func (store *Saltstore) updateSetting(mapped map[string]interface{}, sections []string, setting *model.Setting) error {
	if mapped == nil || len(sections) == 0 {
		return errors.New("Settings map to section id mismatch")
	}

	name := sections[0]
	child := mapped[name]
	if child == nil && len(sections) > 1 {
		// This is a new override so the parent hierarchy doesn't yet exist. Create it.
		child = make(map[string]interface{})
		mapped[name] = child
	}

	if child != nil {
		switch child := child.(type) {
		case map[string]interface{}:
			if len(sections) == 1 {
				return errors.New("Unexpected setting value of map type during update")
			}
			return store.updateSetting(child, sections[1:], setting)
		}
	}

	value := setting.Value

	var err error
	if len(sections) == 1 {
		log.WithFields(log.Fields{
			"settingName":      name,
			"settingLength":    len(value),
			"alreadyExists":    mapped[name] != nil,
			"defaultAvailable": setting.DefaultAvailable,
		}).Debug("Updating setting value")

		if setting.ForcedType != "" {
			log.WithFields(log.Fields{
				"settingName": name,
				"forcedType":  setting.ForcedType,
			}).Info("Forcing setting type")
			mapped[name], err = ForceType(value, setting.ForcedType)
			if err == nil && setting.ForcedType == "[]{}" {
				if mapList, ok := mapped[name].([]map[string]any); ok {
					mapped[name], err = CoerceMapListFieldTypes(mapList, setting.UiElements)
				}
			}
		} else {
			currentValue := mapped[name]
			if currentValue == nil && setting.DefaultAvailable {
				currentValue = AlignBestGuess(setting.Default)
			}
			value = strings.TrimSpace(value)
			mapped[name], err = AlignType(currentValue, value)
		}
	}

	return err
}

func (store *Saltstore) deleteSetting(mapped map[string]interface{}, sections []string) (bool, error) {
	if mapped == nil || len(sections) == 0 {
		return false, errors.New("Settings map to section id mismatch")
	}

	var err error
	name := sections[0]
	child := mapped[name]
	if child != nil {
		switch child := child.(type) {
		case map[string]interface{}:
			if len(sections) == 1 {
				return false, errors.New("Unexpected setting value of map type during delete")
			}

			var empty bool
			empty, err = store.deleteSetting(child, sections[1:])
			if empty && err == nil {
				log.WithFields(log.Fields{
					"settingName": name,
				}).Debug("Deleting empty parent")
				delete(mapped, name)
			}
		default:
			log.WithFields(log.Fields{
				"settingName": name,
			}).Debug("Deleting setting from parent")
			delete(mapped, name)
		}
	}

	empty := len(mapped) == 0

	return empty, err
}

func (store *Saltstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) (err error) {
	logger := log.FromContext(ctx)

	if err = store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	sections := strings.Split(setting.Id, ".")

	if len(sections) == 0 {
		return errors.New("Invalid setting id: " + setting.Id)
	}

	settingDef, err := store.GetSetting(ctx, setting.Id)
	if err != nil {
		return err
	} else {
		if settingDef == nil {
			logger.WithFields(log.Fields{
				"settingId": setting.Id,
			}).Info("Setting definition not found; assuming new, undefined setting")
		} else {
			if settingDef.Readonly {
				return errors.New("Unable to modify or remove a readonly setting")
			}
			setting.Syntax = settingDef.Syntax
			setting.Description = settingDef.Description
			setting.Title = settingDef.Title
			setting.Multiline = settingDef.Multiline
			setting.Advanced = settingDef.Advanced
			setting.ForcedType = settingDef.ForcedType
			setting.Default = settingDef.Default
			setting.DefaultAvailable = settingDef.DefaultAvailable
			setting.File = settingDef.File
			setting.JinjaEscaped = settingDef.JinjaEscaped
			setting.UiElements = settingDef.UiElements
		}
	}

	if !remove {
		if setting.SupportsJinja() {
			setting.Value = syntax.EscapeJinja(setting.Value)
		}

		if !strings.HasPrefix(setting.ForcedType, "[]") && !setting.File {
			// Do not attempt to validate settings with array values, as those have \n separators and will be
			// validated during the type alignment stage later in this update.
			// Files can be excluded since the salt state for those files can disable Jinja rendering if needed.
			log.WithFields(log.Fields{
				"settingSyntax": setting.Syntax,
				"settingId":     setting.Id,
			}).Debug("Preparing to validating setting")
			err = syntax.Validate(setting.Value, setting.Syntax)
			if err != nil {
				return err
			}
		}
	}

	if len(sections) <= 2 && sections[len(sections)-1] == "advanced" {
		var path string
		if setting.NodeId == "" {
			path = fmt.Sprintf("%s/local/pillar/%s/adv_%s.sls", store.saltstackDir, sections[0], sections[0])
		} else {
			path = fmt.Sprintf("%s/local/pillar/minions/adv_%s.sls", store.saltstackDir, setting.NodeId)
		}

		logger.WithFields(log.Fields{
			"settingId":     setting.Id,
			"minionId":      setting.NodeId,
			"settingPath":   path,
			"settingLength": len(setting.Value),
		}).Info("Updating advanced settings to new value")
		os.WriteFile(path, []byte(setting.Value), 0600)

	} else if setting.File {
		path := fmt.Sprintf("%s/local/salt/%s", store.saltstackDir, RelPathFromId(setting.Id))
		if !remove {
			logger.WithFields(log.Fields{
				"settingId":     setting.Id,
				"settingPath":   path,
				"settingLength": len(setting.Value),
			}).Info("Updating custom file setting to new value")

			err = os.WriteFile(path, []byte(setting.Value), 0600)
		} else {
			logger.WithFields(log.Fields{
				"settingId":     setting.Id,
				"settingPath":   path,
				"settingLength": len(setting.Value),
			}).Info("Deleting custom file")

			err = os.Remove(path)
		}
	} else {
		var path string
		if setting.NodeId == "" {
			path = fmt.Sprintf("%s/local/pillar/%s/soc_%s.sls", store.saltstackDir, sections[0], sections[0])
		} else {
			path = fmt.Sprintf("%s/local/pillar/minions/%s.sls", store.saltstackDir, setting.NodeId)
		}

		var mapped map[string]interface{}
		mapped, err = store.parseYaml(path)
		if err == nil {
			if !remove {
				logger.WithFields(log.Fields{
					"settingId":     setting.Id,
					"settingPath":   path,
					"settingLength": len(setting.Value),
				}).Info("Updating setting to new value")
				err = store.updateSetting(mapped, sections, setting)
			} else {
				logger.WithFields(log.Fields{
					"settingId":   setting.Id,
					"settingPath": path,
				}).Info("Deleting setting")
				_, err = store.deleteSetting(mapped, sections)
			}

			if err == nil {
				err = store.writeYaml(path, mapped)
			}
		}
	}

	return err
}

type ListResponse struct {
	Accepted   map[string]string `json:"minions"`
	Unaccepted map[string]string `json:"minions_pre"`
	Rejected   map[string]string `json:"minions_rejected"`
	Denied     map[string]string `json:"minions_denied"`
}

func getMembersFromJson(err error, output []byte) ([]*model.GridMember, error) {
	var members []*model.GridMember

	if err == nil {
		response := &ListResponse{}
		err = json.LoadJson(output, response)
		if err == nil {
			members = make([]*model.GridMember, 0)
			for id, fingerprint := range response.Accepted {
				members = append(members, model.NewGridMember(id, model.GridMemberAccepted, fingerprint))
			}
			for id, fingerprint := range response.Unaccepted {
				members = append(members, model.NewGridMember(id, model.GridMemberUnaccepted, fingerprint))
			}
			for id, fingerprint := range response.Rejected {
				members = append(members, model.NewGridMember(id, model.GridMemberRejected, fingerprint))
			}
			for id, fingerprint := range response.Denied {
				members = append(members, model.NewGridMember(id, model.GridMemberDenied, fingerprint))
			}
		}
	}

	return members, err
}

func (store *Saltstore) GetMembers(ctx context.Context) ([]*model.GridMember, error) {
	if err := store.server.CheckAuthorized(ctx, "read", "grid"); err != nil {
		return nil, err
	}

	var members []*model.GridMember
	args := make(map[string]string)
	args["command"] = "list-minions"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_MEMBER")
		}

		members, err = getMembersFromJson(err, []byte(output))
	}

	return members, err
}

func (store *Saltstore) ManageMember(ctx context.Context, operation string, id string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "grid"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-minion"
	args["operation"] = operation
	args["id"] = id
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_MEMBER")
		}
	}

	return err
}

func (store *Saltstore) SendFile(ctx context.Context, node string, from string, to string, cleanup bool) error {
	// TODO: re-evaluate necessary permissions when this feature is used for more
	// than importing pcap/evtx.
	if err := store.server.CheckAuthorized(ctx, "write", "events"); err != nil {
		return err
	}

	args := map[string]string{
		"command": "send-file",
		"node":    node,
		"from":    from,
		"to":      to,
		"cleanup": strconv.FormatBool(cleanup),
	}

	ctxTimeout := options.WithTimeoutMs(ctx, store.longRelayTimeoutMs)

	output, err := store.execCommand(ctxTimeout, args)
	if err == nil && output == "false" {
		err = errors.New("ERROR_SALT_SEND_FILE")
	}

	return err
}

func (store *Saltstore) Import(ctx context.Context, node string, file string, importer string) (*string, error) {
	if err := store.server.CheckAuthorized(ctx, "write", "events"); err != nil {
		return nil, err
	}

	args := map[string]string{
		"command":  "import-file",
		"node":     node,
		"file":     file,
		"importer": importer,
	}

	ctxTimeout := options.WithTimeoutMs(ctx, store.longRelayTimeoutMs)

	output, err := store.execCommand(ctxTimeout, args)
	if err == nil && output == "false" {
		err = errors.New("ERROR_SALT_IMPORT")
		return nil, err
	}

	return &output, err
}

func (store *Saltstore) lookupEmailFromId(ctx context.Context, id string) string {
	user, _ := store.server.Userstore.GetUserById(ctx, id)
	if user != nil && user.Id == id {
		return user.Email
	}
	return ""
}

func (store *Saltstore) AddUser(ctx context.Context, user *model.User) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "add"
	args["email"] = user.Email
	if len(user.Roles) > 0 {
		args["role"] = user.Roles[0]
	}
	args["firstName"] = user.FirstName
	args["lastName"] = user.LastName
	args["note"] = user.Note
	args["password"] = user.Password
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) DeleteUser(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "delete", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "delete"
	args["email"] = store.lookupEmailFromId(ctx, id)
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) UpdateProfile(ctx context.Context, user *model.User) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "profile"
	args["email"] = store.lookupEmailFromId(ctx, user.Id)
	args["firstName"] = user.FirstName
	args["lastName"] = user.LastName
	args["note"] = user.Note
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) ResetPassword(ctx context.Context, id string, password string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "password"
	args["email"] = store.lookupEmailFromId(ctx, id)
	args["password"] = password
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) EnableUser(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "enable"
	args["email"] = store.lookupEmailFromId(ctx, id)
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) DisableUser(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "disable"
	args["email"] = store.lookupEmailFromId(ctx, id)
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) AddRole(ctx context.Context, id string, role string, bypassAuthCheck bool) error {
	if bypassAuthCheck {
		logger := log.FromContext(ctx)
		logger.Debug("Adding role to user without authorization check")
	} else {
		if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
			return err
		}
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "addrole"
	args["email"] = store.lookupEmailFromId(ctx, id)
	args["role"] = role
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) DeleteRole(ctx context.Context, id string, role string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "delrole"
	args["email"] = store.lookupEmailFromId(ctx, id)
	args["role"] = role
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) SyncUsers(ctx context.Context) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "sync"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) SyncSettings(ctx context.Context) error {
	if err := store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-salt"
	args["operation"] = "highstate"
	args["minion"] = "*"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_STATE")
		}
	}

	return err
}

func (store *Saltstore) SyncModule(ctx context.Context, module string, async bool) error {
	if err := store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-salt"
	args["operation"] = "state"
	args["state"] = module
	if async {
		args["async"] = strconv.FormatBool(async)
	}
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if matched, _ := regexp.MatchString("^ERROR_[A-Z_]+$", output); matched {
			err = errors.New(output)
		} else if output == "false" {
			err = errors.New("ERROR_SALT_STATE")
		}
	}

	return err
}
