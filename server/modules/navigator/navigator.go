package navigator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"gopkg.in/yaml.v3"
)

const DEFAULT_INTERVAL_MINUTES = 60
const DEFAULT_OUTPUT_PATH = "/opt/sensoroni/navigator"
const DEFAULT_LOOKBACK_DAYS = 7
const ALERT_EXTRACTION_TIMEOUT = 3 * time.Minute

var (
	// suricataTechniqueRegex matches MITRE technique IDs in Suricata rules
	suricataTechniqueRegex = regexp.MustCompile(`mitre_technique_id\s+([^,;\s]+)`)
	// sigmaTechniqueRegex matches MITRE technique IDs in Sigma rules
	sigmaTechniqueRegex = regexp.MustCompile(`(?i)t\d{4}(?:\.\d{3})?`)
)

// techniqueMap is a helper type for storing unique technique IDs
type techniqueMap map[string]struct{}

// navigatorLayer represents the structure for generating ATT&CK Navigator layers
type navigatorLayer struct {
	name       string
	techniques techniqueMap
}

// layerConfig represents the configuration for a navigator layer including its output path
type layerConfig struct {
	name       string
	techniques techniqueMap
	filePath   string
}

type Navigator struct {
	config       module.ModuleConfig
	server       *server.Server
	interval     time.Duration
	outputPath   string
	lookbackDays int
	stopChan     chan bool
	techniques   techniqueMap
	running      bool
}

func NewNavigator(srv *server.Server) *Navigator {
	return &Navigator{
		server:     srv,
		techniques: make(techniqueMap),
		stopChan:   make(chan bool),
	}
}

func (nav *Navigator) PrerequisiteModules() []string {
	return nil
}

func (nav *Navigator) Init(cfg module.ModuleConfig) error {
	nav.config = cfg
	intervalMinutes := module.GetIntDefault(cfg, "intervalMinutes", DEFAULT_INTERVAL_MINUTES)
	nav.interval = time.Duration(intervalMinutes) * time.Minute
	nav.outputPath = module.GetStringDefault(cfg, "outputPath", DEFAULT_OUTPUT_PATH)
	nav.lookbackDays = module.GetIntDefault(cfg, "lookbackDays", DEFAULT_LOOKBACK_DAYS)
	return nil
}

func (nav *Navigator) Start() error {
	nav.running = true
	go nav.run()
	return nil
}

func (nav *Navigator) Stop() error {
	nav.stopChan <- true
	nav.running = false
	return nil
}

func (nav *Navigator) IsRunning() bool {
	return nav.running
}

func (nav *Navigator) run() {
	ticker := time.NewTicker(nav.interval)
	defer ticker.Stop()

	logger := log.WithField("component", "navigator")

	// Generate initial set of layers
	if err := nav.generateNavigatorLayer(nav.server.Context, logger); err != nil {
		logger.WithError(err).Error("Failed to generate initial navigator layers")
	}

	for {
		select {
		case <-nav.stopChan:
			return
		case <-ticker.C:
			if err := nav.generateNavigatorLayer(nav.server.Context, logger); err != nil {
				logger.WithError(err).Error("Failed to generate navigator layers")
			}
		}
	}
}

func createLayer(name string, techniques techniqueMap) (map[string]interface{}, error) {
	var layer map[string]interface{}
	if err := json.Unmarshal([]byte(DefaultNavigatorLayer), &layer); err != nil {
		return nil, fmt.Errorf("failed to parse navigator layer template: %w", err)
	}

	layer["name"] = name

	// Convert techniques to array format
	techArray := make([]map[string]interface{}, 0, len(techniques))
	for techniqueID := range techniques {
		techArray = append(techArray, map[string]interface{}{
			"techniqueID": techniqueID,
			"score":       100,
			"enabled":     true,
		})
	}
	layer["techniques"] = techArray

	return layer, nil
}

// writeLayer writes the layer to a file and logs the operation
func (nav *Navigator) writeLayer(layer map[string]interface{}, filePath string, logger *log.Entry) error {
	jsonData, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal navigator layer: %w", err)
	}

	logger.WithField("nav_navigator_layer", string(jsonData)).Debug("generated navigator layer")

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write navigator layer to file: %w", err)
	}

	logger.WithField("nav_file_path", filePath).Info("wrote navigator layer to file")
	return nil
}

// extractSuricataTechniques extracts technique IDs from Suricata rules
func extractSuricataTechniques(rules map[string]*model.Detection, logger *log.Entry) techniqueMap {
	techniques := make(techniqueMap)

	for _, rule := range rules {
		if rule.Content == "" {
			logger.WithField("nav_rule.uuid", rule.PublicID).Debug("skipping rule with empty content")
			continue
		}

		if match := suricataTechniqueRegex.FindStringSubmatch(rule.Content); len(match) > 1 {
			techniqueID := strings.ToUpper(match[1])
			techniques[techniqueID] = struct{}{}
			logger.WithFields(log.Fields{
				"nav_rule.uuid":    rule.PublicID,
				"nav_technique_id": techniqueID,
			}).Debug("extracted technique ID from Suricata rule")
		} else {
			logger.WithField("nav_rule.uuid", rule.PublicID).Debug("no technique ID found in rule")
		}
	}

	return techniques
}

// extractSigmaTechniques extracts technique IDs from Sigma rules
func extractSigmaTechniques(rules map[string]*model.Detection, logger *log.Entry) techniqueMap {
	techniques := make(techniqueMap)

	for _, rule := range rules {
		if rule.Content == "" {
			continue
		}

		var content struct {
			Tags []string `yaml:"tags"`
		}
		if err := yaml.Unmarshal([]byte(rule.Content), &content); err != nil {
			logger.WithError(err).WithField("nav_rule.uuid", rule.PublicID).Warn("failed to parse rule content")
			continue
		}

		for _, tag := range content.Tags {
			if match := sigmaTechniqueRegex.FindString(tag); match != "" {
				baseTechnique := strings.ToUpper(strings.Split(match, ".")[0])
				techniques[baseTechnique] = struct{}{}
			}
		}
	}

	return techniques
}

// extractAlertTechniques extracts technique IDs from alerts in the last N days
func (nav *Navigator) extractAlertTechniques(ctx context.Context, logger *log.Entry) techniqueMap {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, ALERT_EXTRACTION_TIMEOUT)
	defer cancel()

	techniques := make(techniqueMap)

	// Query alerts from the last N days
	lookback := time.Duration(nav.lookbackDays) * 24 * time.Hour
	startTime := time.Now().Add(-lookback)

	// Build the search criteria
	criteria := model.NewEventSearchCriteria()
	criteria.RawQuery = "*"
	criteria.BeginTime = startTime
	criteria.EndTime = time.Now()
	criteria.EventLimit = 10000 // Keep within Elasticsearch limit
	criteria.SortFields = []*model.SortCriteria{{Field: "@timestamp", Order: "desc"}}
	criteria.SearchAfter = []interface{}{time.Now().UnixNano() / int64(time.Millisecond)}

	// Create the query to filter by index
	if err := criteria.ParsedQuery.Parse("event.dataset:suricata.alert AND _exists_:rule.metadata.mitre_technique_id"); err != nil {
		logger.WithError(err).Error("failed to parse query")
		return techniques
	}

	logger.WithFields(log.Fields{
		"nav_rawQuery":   criteria.RawQuery,
		"nav_beginTime":  criteria.BeginTime.Format(time.RFC3339),
		"nav_endTime":    criteria.EndTime.Format(time.RFC3339),
		"nav_eventLimit": criteria.EventLimit,
	}).Info("Executing Suricata alert search query")

	var totalProcessed int

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				logger.WithField("nav_processed_events", totalProcessed).Warn("alert extraction timed out")
			}
			return techniques
		default:
			// Execute the search
			searchResult, err := nav.server.Eventstore.Search(ctx, criteria)
			if err != nil {
				logger.WithError(err).Error("failed to search alerts")
				return techniques
			}

			logger.WithFields(log.Fields{
				"nav_totalEvents": searchResult.TotalEvents,
				"nav_batchSize":   len(searchResult.Events),
				"nav_processed":   totalProcessed,
			}).Info("Processing batch of Suricata alerts for navigator layer")

			for _, event := range searchResult.Events {
				techniqueIDs, ok := event.Payload["rule.metadata.mitre_technique_id"].([]interface{})
				if !ok {
					continue
				}

				for _, id := range techniqueIDs {
					if techID, ok := id.(string); ok {
						techniques[strings.ToUpper(techID)] = struct{}{}
					}
				}
			}

			totalProcessed += len(searchResult.Events)

			// Check if we've processed all events or got an empty batch
			if totalProcessed >= searchResult.TotalEvents || len(searchResult.Events) == 0 {
				return techniques
			}

			// Get the sort values from the last event for the next search
			lastEvent := searchResult.Events[len(searchResult.Events)-1]
			criteria.SearchAfter = lastEvent.Sort
		}
	}
}

// mergeTechniques combines multiple technique maps into a single map
func mergeTechniques(maps ...techniqueMap) techniqueMap {
	combined := make(techniqueMap)
	for _, m := range maps {
		for k := range m {
			combined[k] = struct{}{}
		}
	}
	return combined
}

// getDetections retrieves detections for a specific engine
func (nav *Navigator) getDetections(ctx context.Context, engineName model.EngineName) (map[string]*model.Detection, error) {
	detections, err := nav.server.Detectionstore.GetAllDetections(ctx,
		model.WithEngine(engineName),
		model.WithEnabled(true))
	if err != nil {
		return nil, fmt.Errorf("failed to get %s Detections: %w", engineName, err)
	}
	return detections, nil
}

func (nav *Navigator) generateNavigatorLayer(ctx context.Context, logger *log.Entry) error {
	// Get Detections
	suricataRules, err := nav.getDetections(ctx, model.EngineNameSuricata)
	if err != nil {
		return err
	}

	sigmaRules, err := nav.getDetections(ctx, model.EngineNameElastAlert)
	if err != nil {
		return err
	}

	// Extract techniques from rule sets and alerts
	suricataTechniques := extractSuricataTechniques(suricataRules, logger)
	sigmaTechniques := extractSigmaTechniques(sigmaRules, logger)
	alertTechniques := nav.extractAlertTechniques(ctx, logger)

	// Create combined techniques map
	combinedTechniques := mergeTechniques(suricataTechniques, sigmaTechniques)

	// Define layers to generate
	layers := []layerConfig{
		{
			name:       "Detections Coverage - Suricata",
			techniques: suricataTechniques,
			filePath:   nav.outputPath + "/navigator_layer_suricata.json",
		},
		{
			name:       "Detections Coverage - Sigma",
			techniques: sigmaTechniques,
			filePath:   nav.outputPath + "/navigator_layer_sigma.json",
		},
		{
			name:       "Detections Coverage - All Detections",
			techniques: combinedTechniques,
			filePath:   nav.outputPath + "/navigator_layer_all_detections.json",
		},
		{
			name:       fmt.Sprintf("Alerts (Last %d Days)", nav.lookbackDays),
			techniques: alertTechniques,
			filePath:   nav.outputPath + "/navigator_layer_alerts.json",
		},
	}

	// Generate and write all layers
	for _, l := range layers {
		layer, err := createLayer(l.name, l.techniques)
		if err != nil {
			return fmt.Errorf("failed to create %s layer: %w", l.name, err)
		}

		if err := nav.writeLayer(layer, l.filePath, logger); err != nil {
			return fmt.Errorf("failed to write %s layer: %w", l.name, err)
		}
	}

	return nil
}
