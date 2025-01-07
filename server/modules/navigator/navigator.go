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
		stopChan:   make(chan bool),
		techniques: make(techniqueMap),
	}
}

func (nav *Navigator) PrerequisiteModules() []string {
	return []string{"elastic", "suricataengine", "elastalertengine"}
}

func (nav *Navigator) Init(cfg module.ModuleConfig) error {
	if cfg == nil || len(cfg) == 0 {
		return fmt.Errorf("empty configuration provided")
	}

	if _, ok := cfg["outputPath"]; !ok {
		return fmt.Errorf("outputPath is required")
	}

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
			logger.Info("Navigator loop exiting")
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
			// Extract base technique ID by splitting on '.' and taking the first part
			baseTechniqueID := strings.Split(techniqueID, ".")[0]
			techniques[baseTechniqueID] = struct{}{}
			logger.WithFields(log.Fields{
				"nav_rule.uuid":    rule.PublicID,
				"nav_technique_id": baseTechniqueID,
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

func (nav *Navigator) extractAlertTechniques(ctx context.Context, logger *log.Entry) (techniqueMap, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, ALERT_EXTRACTION_TIMEOUT)
	defer cancel()

	techniques := make(techniqueMap, 1000)

	// Query alerts from the last N days
	lookback := time.Duration(nav.lookbackDays) * 24 * time.Hour
	now := time.Now()
	startTime := now.Add(-lookback)

	// Build the search criteria
	criteria := model.NewEventSearchCriteria()
	criteria.EventLimit = 0     // We don't need any hits, just the aggregation
	criteria.MetricLimit = 1000 // Total number of unique technique IDs to return
	criteria.ParsedQuery = model.NewQuery()

	// Set up the query to find alerts with technique IDs and group by them
	criteria.RawQuery = "event.dataset:suricata.alert AND _exists_:rule.metadata.mitre_technique_id | groupby rule.metadata.mitre_technique_id"
	criteria.BeginTime = startTime
	criteria.EndTime = now

	err := criteria.ParsedQuery.Parse(criteria.RawQuery)
	if err != nil {
		logger.WithError(err).Error("failed to parse query")
		return nil, err
	}

	// Log the parsed query segments
	segments := criteria.ParsedQuery.NamedSegments(model.SegmentKind_GroupBy)
	logger.WithFields(log.Fields{
		"nav_query":           criteria.RawQuery,
		"nav_parsed_segments": len(segments),
		"nav_beginTime":       criteria.BeginTime.Format(time.RFC3339),
		"nav_endTime":         criteria.EndTime.Format(time.RFC3339),
	}).Debug("Executing Suricata alert aggregation query")

	// Execute the search
	searchResult, err := nav.server.Eventstore.Search(ctx, criteria)
	if err != nil {
		logger.WithError(err).Error("failed to search alerts")
		return nil, err
	}

	// Log the search results
	logger.WithFields(log.Fields{
		"nav_total_metrics":     len(searchResult.Metrics),
		"nav_total_events":      len(searchResult.Events),
		"nav_available_metrics": searchResult.Metrics != nil,
	}).Debug("Received search results")

	// Process the metrics results to get unique technique IDs
	if searchResult.Metrics == nil {
		return techniques, nil
	}

	for metricName, metrics := range searchResult.Metrics {
		if !strings.Contains(metricName, "rule.metadata.mitre_technique_id") {
			continue
		}
		for _, metric := range metrics {
			if len(metric.Keys) == 0 {
				continue
			}
			key, ok := metric.Keys[0].(string)
			if !ok || key == "" {
				continue
			}
			// Strip sub-technique ID (anything after the dot)
			if dotIndex := strings.Index(key, "."); dotIndex != -1 {
				key = key[:dotIndex]
			}
			techniques[strings.ToUpper(key)] = struct{}{}
			logger.WithFields(log.Fields{
				"nav_technique_id": key,
			}).Debug("Found technique")
		}
	}

	logger.WithField("nav_unique_techniques", len(techniques)).Info("Processed unique technique IDs")
	return techniques, nil
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
	alertTechniques, err := nav.extractAlertTechniques(ctx, logger)
	if err != nil {
		return err
	}

	// Create combined techniques map
	combinedTechniques := mergeTechniques(suricataTechniques, sigmaTechniques, alertTechniques)

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
