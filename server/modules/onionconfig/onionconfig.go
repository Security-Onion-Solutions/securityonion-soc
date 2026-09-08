// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type OnionConfig struct {
	server        *server.Server
	saltstackDir  string
	bypassEnabled bool
	annotations   map[string]map[string]interface{}
	store         storeProvider
	ready         chan struct{}

	// callbacks maps a setting ID to the handlers registered for it. Guarded by
	// callbacksMu. Handlers are invoked after a setting update is persisted.
	callbacks   map[string][]server.ConfigSettingCallbackHandler
	callbacksMu sync.RWMutex
}

// storeProvider abstracts all database operations for onionconfig.
type storeProvider interface {
	dbSettingsLoader
	dbSettingsMutator
	GetAuditHistory(ctx context.Context, settingID, nodeID string, limit, offset int, sort, order string) ([]database.AuditEntry, int, error)
	GetAllAuditHistory(ctx context.Context, limit, offset int, sort, order string) ([]database.AuditEntry, int, error)
	GetAuditEntryAtTimestamp(ctx context.Context, settingID, nodeID string, ts time.Time) (*database.AuditEntry, error)
	GetRevertState(ctx context.Context, ts time.Time) ([]database.SettingRow, error)
}

func NewOnionConfig(server *server.Server) *OnionConfig {
	// callbacks is created lazily on first registration (see
	// RegisterConfigSettingCallback) to avoid referencing the server package here,
	// where the "server" parameter name shadows the package identifier.
	return &OnionConfig{
		server: server,
		ready:  make(chan struct{}),
	}
}

// RegisterConfigSettingCallback registers handler to be notified whenever the
// setting with the given settingID is updated. Implements
// server.ConfigSettingCallbackRegistrar.
func (c *OnionConfig) RegisterConfigSettingCallback(settingID string, handler server.ConfigSettingCallbackHandler) {
	if handler == nil || settingID == "" {
		return
	}

	c.callbacksMu.Lock()
	defer c.callbacksMu.Unlock()

	if c.callbacks == nil {
		c.callbacks = map[string][]server.ConfigSettingCallbackHandler{}
	}
	c.callbacks[settingID] = append(c.callbacks[settingID], handler)
}

// notifyConfigSettingCallbacks invokes every handler registered for the given
// setting's ID. Each handler is called inline (config updates are infrequent),
// but a panicking handler is recovered so it cannot break the config write path.
func (c *OnionConfig) notifyConfigSettingCallbacks(ctx context.Context, setting *model.Setting, removed bool) {
	if setting == nil {
		return
	}

	c.callbacksMu.RLock()
	handlers := c.callbacks[setting.Id]
	c.callbacksMu.RUnlock()

	for _, handler := range handlers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.FromContext(ctx).WithField("setting", setting.Id).Errorf("config setting callback panicked: %v", r)
				}
			}()
			handler.OnConfigSettingUpdated(ctx, setting, removed)
		}()
	}
}

func (c *OnionConfig) Init(saltstackDir string, bypassEnabled bool) {
	c.saltstackDir = strings.TrimSuffix(saltstackDir, "/")
	c.bypassEnabled = bypassEnabled
}

func (c *OnionConfig) Start(store *database.Store) error {
	if store != nil {
		c.store = store
	}
	err := c.PreloadConfiguration()
	close(c.ready)
	return err
}

func (c *OnionConfig) waitReady(ctx context.Context) error {
	select {
	case <-c.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *OnionConfig) PreloadConfiguration() error {
	var err error
	defaultDir := c.saltstackDir + "/default"
	if _, statErr := os.Stat(defaultDir); statErr == nil {
		var defaults map[string]interface{}
		c.annotations, defaults, err = LoadStaticConfiguration(defaultDir, ParseYaml)
		if err == nil {
			HydrateAnnotations(c.annotations, defaults, func(id string) (string, bool) {
				relpath := RelPathFromId(id)
				content, err := ReadFile(fmt.Sprintf("%s/default/salt/%s", c.saltstackDir, relpath))
				return content, err == nil
			})
		}
	}

	if err != nil {
		log.WithError(err).Warn("Failed to load pillar data")
		if !c.bypassEnabled {
			return err
		}
	}

	return nil
}

func (c *OnionConfig) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	if err := c.waitReady(ctx); err != nil {
		return nil, err
	}
	if err := c.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}

	settings, err := c.loadAllSettings(ctx, "")
	if err != nil {
		return nil, err
	}

	return Sort(Filter(settings, advanced)), err
}

func (c *OnionConfig) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) (err error) {
	if err = c.waitReady(ctx); err != nil {
		return err
	}
	logger := log.FromContext(ctx)

	if err = c.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	allSettings, err := c.loadAllSettings(ctx, setting.Id)
	if err != nil {
		return err
	}

	settingDef, oldValue := resolveExistingSetting(allSettings, setting.Id, setting.NodeId)

	if settingDef == nil && setting.DuplicatedFromID != "" {
		origSettings, origErr := c.loadAllSettings(ctx, setting.DuplicatedFromID)
		if origErr == nil {
			settingDef, _ = resolveExistingSetting(origSettings, setting.DuplicatedFromID, setting.NodeId)
		}
	}

	if settingDef == nil {
		logger.WithFields(log.Fields{
			"settingId": setting.Id,
		}).Info("Setting definition not found; assuming new, undefined setting")
		// Strip client-provided metadata for unknown settings to prevent unauthorized control of server behavior.
		setting.Syntax = ""
		setting.Description = ""
		setting.Title = ""
		setting.Multiline = false
		setting.Advanced = false
		setting.ForcedType = ""
		setting.Default = ""
		setting.DefaultAvailable = false
		setting.File = false
		setting.JinjaEscaped = false
		setting.UiElements = nil
		setting.UiElementsDeleteMessage = ""
		setting.Readonly = false
		setting.ReadonlyUi = false
		setting.Sensitive = false
		setting.Regex = ""
		setting.RegexFailureMessage = ""
		setting.Required = false
		setting.Duplicates = false
		setting.HelpLink = ""
		setting.Options = nil
		setting.OptionSeparator = ""
		setting.AllowedNodeTypes = nil
		setting.Origin = model.SettingOriginYaml
	} else {
		if settingDef.Readonly {
			return errors.New("Unable to modify or remove a readonly setting")
		}
		if err := c.validateAllowedNodeTypes(ctx, setting, settingDef); err != nil {
			return err
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
		setting.UiElementsDeleteMessage = settingDef.UiElementsDeleteMessage
		setting.Readonly = settingDef.Readonly
		setting.ReadonlyUi = settingDef.ReadonlyUi
		setting.Sensitive = settingDef.Sensitive
		setting.Regex = settingDef.Regex
		setting.RegexFailureMessage = settingDef.RegexFailureMessage
		setting.Required = settingDef.Required
		setting.Duplicates = settingDef.Duplicates
		setting.HelpLink = settingDef.HelpLink
		setting.Options = settingDef.Options
		setting.OptionSeparator = settingDef.OptionSeparator
		setting.AllowedNodeTypes = settingDef.AllowedNodeTypes
		// Carry the origin forward so we know where to route the write.
		setting.Origin = settingDef.Origin
		if setting.DuplicatedFromID == "" {
			setting.DuplicatedFromID = settingDef.DuplicatedFromID
		}
	}

	if err := c.routeUpdate(ctx, setting, oldValue, remove, logger); err != nil {
		return err
	}

	// Notify any registered listeners now that the change has been persisted.
	c.notifyConfigSettingCallbacks(ctx, setting, remove)

	return nil
}

func (c *OnionConfig) routeUpdate(ctx context.Context, setting *model.Setting, oldValue string, remove bool, logger log.Interface) error {
	userID := userIDFromContext(ctx)

	if setting.Origin == model.SettingOriginDB {
		if c.store == nil {
			return errors.New("database not configured; cannot update DB setting")
		}
		return updateSettingInDB(ctx, c.store, setting, oldValue, remove, userID)
	}

	err := UpdatePillarSetting(c.saltstackDir, setting, remove)
	if err == nil && c.store != nil {
		if auditErr := auditSettingOnly(ctx, c.store, setting, oldValue, remove, userID); auditErr != nil {
			logger.WithError(auditErr).Warn("Failed to record YAML setting update audit")
		}
	}
	return err
}

func (c *OnionConfig) GetAuditHistory(ctx context.Context, settingID, nodeID string, limit, offset int, sort, order string) (*server.ConfigHistory, error) {
	if err := c.waitReady(ctx); err != nil {
		return nil, err
	}
	if err := c.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}
	if c.store == nil {
		return nil, errors.New("database not configured")
	}

	isSensitive := c.isSensitive(settingID)

	entries, total, err := c.store.GetAuditHistory(ctx, settingID, nodeID, limit, offset, sort, order)
	if err != nil {
		return nil, err
	}

	history := make([]model.AuditHistory, 0, len(entries))
	for _, e := range entries {
		oldVal, newVal := decodeAndMaskAuditValues(isSensitive, e.OldValue, e.NewValue)
		history = append(history, model.AuditHistory{
			Timestamp:        e.Timestamp.Format(time.RFC3339),
			UserID:           e.UserID,
			OldValue:         oldVal,
			NewValue:         newVal,
			Note:             e.Note,
			SettingID:        e.SettingID,
			NodeID:           e.NodeID,
			DuplicatedFromID: e.DuplicatedFromID,
		})
	}

	return &server.ConfigHistory{History: history, Total: total}, nil
}

func (c *OnionConfig) GetAllAuditHistory(ctx context.Context, limit, offset int, sort, order string) (*server.ConfigHistory, error) {
	if err := c.waitReady(ctx); err != nil {
		return nil, err
	}
	if err := c.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}
	if c.store == nil {
		return nil, errors.New("database not configured")
	}

	entries, total, err := c.store.GetAllAuditHistory(ctx, limit, offset, sort, order)
	if err != nil {
		return nil, err
	}

	history := make([]model.AuditHistory, 0, len(entries))
	for _, e := range entries {
		oldVal, newVal := decodeAndMaskAuditValues(c.isSensitive(e.SettingID), e.OldValue, e.NewValue)
		history = append(history, model.AuditHistory{
			Timestamp:        e.Timestamp.Format(time.RFC3339),
			UserID:           e.UserID,
			OldValue:         oldVal,
			NewValue:         newVal,
			Note:             e.Note,
			SettingID:        e.SettingID,
			NodeID:           e.NodeID,
			DuplicatedFromID: e.DuplicatedFromID,
		})
	}

	return &server.ConfigHistory{History: history, Total: total}, nil
}

func (c *OnionConfig) RevertSetting(ctx context.Context, settingID, nodeID string, ts time.Time, note string) error {
	if err := c.waitReady(ctx); err != nil {
		return err
	}
	if err := c.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}
	if c.store == nil {
		return errors.New("database not configured")
	}

	entry, err := c.store.GetAuditEntryAtTimestamp(ctx, settingID, nodeID, ts)
	if err != nil {
		return err
	}

	revertValue := decodeJSONBValue(entry.OldValue)

	allSettings, err := c.loadAllSettings(ctx, settingID)
	if err != nil {
		return err
	}
	_, currentValue := resolveExistingSetting(allSettings, settingID, nodeID)

	if revertValue == currentValue {
		return nil
	}

	setting := model.NewSetting(settingID)
	setting.NodeId = nodeID
	setting.Value = revertValue
	setting.Note = note
	setting.DuplicatedFromID = entry.DuplicatedFromID

	return c.UpdateSetting(ctx, setting, entry.OldValue == nil)
}

func (c *OnionConfig) RevertAllSettings(ctx context.Context, ts time.Time, note string) (int, error) {
	if err := c.waitReady(ctx); err != nil {
		return 0, err
	}
	if err := c.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return 0, err
	}
	if c.store == nil {
		return 0, errors.New("database not configured")
	}

	rows, err := c.store.GetRevertState(ctx, ts)
	if err != nil {
		return 0, err
	}

	filtered, err := c.filterUnchangedReverts(ctx, rows)
	if err != nil {
		return 0, err
	}

	changedCount := 0
	for _, r := range filtered {
		setting := model.NewSetting(r.SettingID)
		setting.NodeId = r.NodeID
		setting.Value = decodeJSONBValue(r.Value)
		setting.Note = note
		setting.DuplicatedFromID = r.DuplicatedFromID

		if err := c.UpdateSetting(ctx, setting, r.Value == nil); err != nil {
			return changedCount, err
		}
		changedCount++
	}

	return changedCount, nil
}

func (c *OnionConfig) GetRevertCount(ctx context.Context, ts time.Time) (int, error) {
	if err := c.waitReady(ctx); err != nil {
		return 0, err
	}
	if err := c.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return 0, err
	}
	if c.store == nil {
		return 0, errors.New("database not configured")
	}

	rows, err := c.store.GetRevertState(ctx, ts)
	if err != nil {
		return 0, err
	}

	filtered, err := c.filterUnchangedReverts(ctx, rows)
	if err != nil {
		return 0, err
	}
	return len(filtered), nil
}

func (c *OnionConfig) filterUnchangedReverts(ctx context.Context, rows []database.SettingRow) ([]database.SettingRow, error) {
	allSettings, err := c.loadAllSettings(ctx, "")
	if err != nil {
		return nil, err
	}

	currentValues := make(map[string]string)
	for _, s := range allSettings {
		currentValues[s.Id+"\x00"+s.NodeId] = s.Value
	}

	var filtered []database.SettingRow
	for _, r := range rows {
		if decodeJSONBValue(r.Value) == currentValues[r.SettingID+"\x00"+r.NodeID] {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered, nil
}

// isSensitive returns true if the given setting ID is marked as sensitive in the static annotations.
func (c *OnionConfig) isSensitive(id string) bool {
	if ann, ok := c.annotations[id]; ok {
		if s, ok := ann["sensitive"].(bool); ok {
			return s
		}
	}
	return false
}

// loadAllSettings merges DB settings on top of yaml settings then applies annotations.
func (c *OnionConfig) loadAllSettings(ctx context.Context, filterId string) ([]*model.Setting, error) {
	// 1. Load yaml settings (existing flow).
	yamlSettings, err := LoadLocalSettings(c.saltstackDir, filterId, c.annotations, c.bypassEnabled)
	if err != nil {
		return nil, err
	}

	// 2. Load DB settings (if available) and merge on top of yaml.
	if c.store != nil {
		dbSettings, dbErr := loadDBSettings(ctx, c.store)
		if dbErr != nil {
			log.WithError(dbErr).Warn("Failed to load settings from database; falling back to yaml-only")
		} else {
			// Filter DB settings when a specific ID is requested.
			if filterId != "" {
				filtered := dbSettings[:0]
				for _, s := range dbSettings {
					if s.Id == filterId {
						filtered = append(filtered, s)
					}
				}
				dbSettings = filtered
			}
			yamlSettings = mergeDBIntoYaml(dbSettings, yamlSettings)
		}
	}

	// 3. Re-apply annotations and masks to all settings to ensure DB-sourced values
	// are properly decorated and sensitive values are masked.
	for _, s := range yamlSettings {
		if ann, ok := c.annotations[s.Id]; ok {
			ApplyAnnotations(s, ann, nil)
		} else if s.Origin != model.SettingOriginDB && s.DuplicatedFromID == "" && c.store != nil && !strings.HasSuffix(s.Id, ".advanced") {
			log.WithFields(log.Fields{
				"id":     s.Id,
				"nodeId": s.NodeId,
			}).Debug("Checking unexpected setting's audit history for duplicated setting ID")
			entries, _, err := c.store.GetAuditHistory(ctx, s.Id, "", 1, 0, "timestamp", "desc")
			if err == nil && len(entries) > 0 {
				if entries[0].DuplicatedFromID != "" {
					s.DuplicatedFromID = entries[0].DuplicatedFromID
				}
			}
		}
		if s.DuplicatedFromID != "" {
			if ann, ok := c.annotations[s.DuplicatedFromID]; ok {
				ApplyAnnotations(s, ann, nil)
			}
		}
		ApplySensitiveMask(s)
	}

	PostProcess(yamlSettings)

	return yamlSettings, nil
}

// userIDFromContext extracts a user identifier from the context, returning "unknown" if unavailable.
func userIDFromContext(ctx context.Context) string {
	if uid, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok && uid != "" {
		return uid
	}
	return "unknown"
}

func decodeAndMaskAuditValues(isSensitive bool, oldVal, newVal *string) (string, string) {
	o := decodeJSONBValue(oldVal)
	n := decodeJSONBValue(newVal)
	if isSensitive {
		if oldVal != nil {
			o = "******"
		}
		if newVal != nil {
			n = "******"
		}
	}
	return o, n
}

func resolveExistingSetting(allSettings []*model.Setting, settingID, nodeID string) (settingDef *model.Setting, oldValue string) {
	for _, s := range allSettings {
		if s.Id == settingID {
			if settingDef == nil {
				settingDef = s
			}
			if s.NodeId == nodeID && s.Value != s.Default {
				oldValue = s.Value
			}
		}
	}
	return
}

func (c *OnionConfig) validateAllowedNodeTypes(ctx context.Context, setting *model.Setting, settingDef *model.Setting) error {
	allowedTypes := settingDef.AllowedNodeTypes
	if allowedTypes == nil || len(allowedTypes) == 0 {
		return nil
	}

	if setting.NodeId == "" {
		return nil
	}

	if c.server == nil || c.server.GridMembersstore == nil {
		return nil
	}

	members, err := c.server.GridMembersstore.GetMembers(ctx)
	if err != nil {
		return nil
	}

	for _, member := range members {
		if member.Id == setting.NodeId {
			for _, allowedType := range allowedTypes {
				if member.Role == allowedType {
					return nil
				}
			}
			return fmt.Errorf("node %s has role %q which is not in the allowedNodeTypes [%v] for setting %s", setting.NodeId, member.Role, allowedTypes, setting.Id)
		}
	}

	return nil
}
