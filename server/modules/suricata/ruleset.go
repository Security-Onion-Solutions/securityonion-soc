// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
)

// RulesetSyncResult represents the result of syncing a single ruleset
type RulesetSyncResult struct {
	Detections []*model.Detection
	Success    bool
	Error      error
	// Additional metadata for better observability
	SourceName string        // Name of the ruleset source
	Duration   time.Duration // Time taken to sync
	RuleCount  int           // Number of rules fetched (convenience field)
	Timestamp  time.Time     // When the sync started
}

// RulesetSource represents a source of Suricata rules
//
// Source types:
//   - url: Downloads rules from HTTP/HTTPS URLs (tar.gz, zip, or plain text)
//   - directory: Reads .rules files from local filesystem directory
//   - elasticsearch: Queries existing user-created rules from Elasticsearch
//
// The elasticsearch source type is different - it doesn't download
// or fetch new rules. Instead, it queries user-created rules that already exist
// in Elasticsearch to include them in the Suricata rules files
//
// Required fields: name, sourceType, sourcePath, license, enabled
type RulesetSource struct {
	Name               string   `json:"name"`                   // "ETOPEN", "ETPRO", "local" (this becomes the ruleset name)
	SourceType         string   `json:"sourceType"`             // "url", "directory", "elasticsearch"
	SourcePath         string   `json:"sourcePath"`             // URL, file/directory path, or ES query format (e.g., "so_detection.ruleset:__custom__")
	ReadOnly           bool     `json:"readOnly"`               // If true, rules cannot be modified by users
	DeleteUnreferenced bool     `json:"deleteUnreferenced"`     // If true, remove rules not in source (not applicable for ES sources)
	License            string   `json:"license"`                // License type for the ruleset
	Enabled            *bool    `json:"enabled"`                // Whether this ruleset is active
	ExcludeFiles       []string `json:"excludeFiles,omitempty"` // File patterns to exclude from tar.gz/directory sources

	// Hash verification for URL sources
	URLHash string `json:"urlHash,omitempty"` // URL to download hash file (e.g., .md5 or .sha256 file)

	// Proxy configuration for URL sources
	ProxyURL      string `json:"proxyUrl,omitempty"`      // HTTP/HTTPS/SOCKS5 proxy URL
	ProxyUsername string `json:"proxyUsername,omitempty"` // Proxy authentication username
	ProxyPassword string `json:"proxyPassword,omitempty"` // Proxy authentication password

	// TLS/Certificate configuration for URL sources
	ProxyCACert        string `json:"proxyCACert,omitempty"`        // Path to CA certificate file for MITM proxy
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"` // Skip TLS cert validation

	// Filters to apply to this ruleset
	EnableRegex  []string `json:"enableRegex,omitempty"`  // Regex patterns to force-enable rules
	DisableRegex []string `json:"disableRegex,omitempty"` // Regex patterns to force-disable rules
}

// Validate validates the RulesetSource configuration
func (s *RulesetSource) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if s.SourceType == "" {
		return fmt.Errorf("sourceType is required")
	}
	if s.SourceType != "url" && s.SourceType != "directory" && s.SourceType != "elasticsearch" {
		return fmt.Errorf("invalid sourceType: %s (must be 'url', 'directory', or 'elasticsearch')", s.SourceType)
	}
	if s.SourcePath == "" {
		return fmt.Errorf("sourcePath is required")
	}
	if s.License == "" {
		return fmt.Errorf("license is required")
	}
	if s.Enabled == nil {
		return fmt.Errorf("enabled is required")
	}
	return nil
}

// GetRulesetSourcesFromConfig parses ruleset sources from configuration
func GetRulesetSourcesFromConfig(cfg map[string]interface{}, field string, dflt []*RulesetSource) ([]*RulesetSource, error) {
	cfgInter, ok := cfg[field]
	if !ok {
		if dflt == nil {
			// No fallback provided and no config - require explicit configuration
			return nil, fmt.Errorf("configuration field '%s' is required", field)
		}
		// config doesn't have any rulesetSources, no error, return defaults
		return dflt, nil
	}

	// Convert to JSON then unmarshal to structs
	// This handles type conversions more cleanly than manual parsing
	jsonBytes, err := json.Marshal(cfgInter)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config field '%s': %w", field, err)
	}

	var rulesets []*RulesetSource
	if err := json.Unmarshal(jsonBytes, &rulesets); err != nil {
		return nil, fmt.Errorf("failed to parse '%s' as ruleset sources: %w", field, err)
	}

	// Check for duplicate ruleset names
	namesSeen := make(map[string]bool)
	for _, r := range rulesets {
		if namesSeen[r.Name] {
			log.WithFields(log.Fields{
				"duplicateName": r.Name,
				"component":     "suricata-config",
			}).Warn("duplicate ruleset name found - this will cause sync failures")
		}
		namesSeen[r.Name] = true
	}

	// Validate each ruleset configuration
	for i, r := range rulesets {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("ruleset %d (%s) validation failed: %w", i, r.Name, err)
		}
	}

	return rulesets, nil
}

// RulesetManager handles downloading and processing of rulesets
type RulesetManager struct {
	sources   []*RulesetSource
	ioManager detections.IOManager
	logger    *nidsLogger
}

// NewRulesetManager creates a new ruleset manager with the provided sources.
// Sources should not be modified after the manager is created.
func NewRulesetManager(ioManager detections.IOManager, logger *nidsLogger, sources ...*RulesetSource) *RulesetManager {
	return &RulesetManager{
		sources:   sources,
		ioManager: ioManager,
		logger:    logger,
	}
}

// GetSources returns all configured ruleset sources
func (rm *RulesetManager) GetSources() []*RulesetSource {
	return rm.sources
}

// SyncAll synchronizes all enabled ruleset sources
func (rm *RulesetManager) SyncAll(ctx context.Context, detStore server.Detectionstore) map[string]*RulesetSyncResult {
	results := make(map[string]*RulesetSyncResult)

	for _, source := range rm.sources {
		if source.Enabled == nil || !*source.Enabled {
			rm.logger.WithFields(log.Fields{
				"component":    "RulesetManager",
				"ruleset": source.Name,
			}).Debug("skipping disabled ruleset")
			continue
		}

		rm.logger.WithFields(log.Fields{
			"component":    "RulesetManager",
			"ruleset": source.Name,
		}).Info("syncing ruleset")

		startTime := time.Now()
		detections, err := rm.syncSource(ctx, detStore, source)
		duration := time.Since(startTime)

		result := &RulesetSyncResult{
			SourceName: source.Name,
			Timestamp:  startTime,
			Duration:   duration,
		}

		if err != nil {
			rm.logger.WithError(err).WithFields(log.Fields{
				"component":     "RulesetManager",
				"ruleset":  source.Name,
				"duration": duration.Seconds(),
				"success":  false,
			}).Error("failed to sync ruleset")

			result.Success = false
			result.Error = err
		} else {
			result.Success = true
			result.Detections = detections
			result.RuleCount = len(detections)

			rm.logger.WithFields(log.Fields{
				"component":      "RulesetManager",
				"ruleset":   source.Name,
				"ruleCount": len(detections),
				"duration":  duration.Seconds(),
				"success":   true,
			}).Info("successfully synced ruleset")
		}

		results[source.Name] = result
	}

	return results
}

// syncSource synchronizes a single ruleset source
func (rm *RulesetManager) syncSource(ctx context.Context, detStore server.Detectionstore, source *RulesetSource) ([]*model.Detection, error) {
	// Elasticsearch is fundamentally different - queries existing rules
	if source.SourceType == "elasticsearch" {
		return rm.queryElasticsearch(ctx, detStore, source)
	}

	// Fetch rules files (URL extracts archive, directory reads files)
	files, err := rm.fetchRulesFiles(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ruleset: %w", err)
	}

	// Concatenate all rules into single string
	rules := rm.concatenateRulesFiles(files, source)

	// Parse rules into detections
	detections, err := ParseSuricataRules(ctx, rules, source.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}

	// Apply source-specific settings
	for _, det := range detections {
		det.IsCommunity = source.ReadOnly
		det.License = source.License
		det.Ruleset = source.Name
	}

	return detections, nil
}

// getHTTPClient creates an HTTP client with proxy and TLS configuration for the given source
func (rm *RulesetManager) getHTTPClient(source *RulesetSource) (*http.Client, error) {
	transport := &http.Transport{}

	// Configure proxy if specified
	if source.ProxyURL != "" {
		proxyURL, err := url.Parse(source.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", source.ProxyURL, err)
		}

		// Add proxy authentication if provided
		if source.ProxyUsername != "" {
			proxyURL.User = url.UserPassword(source.ProxyUsername, source.ProxyPassword)
		}

		transport.Proxy = http.ProxyURL(proxyURL)
		rm.logger.WithFields(log.Fields{
			"ruleset": source.Name,
			"proxy.url":    source.ProxyURL,
		}).Debug("configured HTTP proxy for ruleset download")
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		InsecureSkipVerify: source.InsecureSkipVerify,
	}

	// Add custom CA certificate if provided
	if source.ProxyCACert != "" {
		caCert, err := rm.ioManager.ReadFile(source.ProxyCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %q: %w", source.ProxyCACert, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %q", source.ProxyCACert)
		}

		tlsConfig.RootCAs = caCertPool
		rm.logger.WithFields(log.Fields{
			"ruleset": source.Name,
			"ca.cert":      source.ProxyCACert,
		}).Debug("loaded custom CA certificate for ruleset download")
	}

	// Log warning if certificate verification is disabled
	if source.InsecureSkipVerify {
		rm.logger.WithFields(log.Fields{
			"ruleset": source.Name,
		}).Warn("TLS certificate verification disabled - this is insecure and should only be used for testing")
	}

	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   5 * time.Minute,
		Transport: transport,
	}, nil
}

// downloadURL is a helper function that downloads content from a URL using the source's HTTP configuration
func (rm *RulesetManager) downloadURL(ctx context.Context, source *RulesetSource, url string, description string) ([]byte, error) {
	// Create HTTP client with proxy and TLS configuration
	client, err := rm.getHTTPClient(source)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	rm.logger.WithFields(log.Fields{
		"ruleset": source.Name,
		"url":     url,
		"type":    description,
	}).Debug("starting HTTP download")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", description, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s download failed with HTTP %d: %s", description, resp.StatusCode, resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response: %w", description, err)
	}

	rm.logger.WithFields(log.Fields{
		"ruleset":   source.Name,
		"type":      description,
		"sizeBytes": len(content),
	}).Debug("completed HTTP download")

	return content, nil
}

// downloadRuleset downloads rules from a URL and optionally verifies the hash
func (rm *RulesetManager) downloadRuleset(ctx context.Context, source *RulesetSource) ([]byte, error) {
	downloadStart := time.Now()

	// Download the ruleset file
	content, err := rm.downloadURL(ctx, source, source.SourcePath, "ruleset")
	if err != nil {
		return nil, err
	}

	rm.logger.WithFields(log.Fields{
		"ruleset":           source.Name,
		"downloadSizeBytes": len(content),
		"totalDownloadTime": time.Since(downloadStart).Seconds(),
	}).Info("completed ruleset download")

	// Verify hash if configured
	if source.URLHash != "" {
		hashStart := time.Now()

		expectedHash, err := rm.downloadHashFile(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("failed to download hash file: %w", err)
		}

		if err := rm.verifyContentHash(content, expectedHash); err != nil {
			return nil, fmt.Errorf("hash verification failed: %w", err)
		}

		rm.logger.WithFields(log.Fields{
			"ruleset":          source.Name,
			"hashVerification": "success",
			"hashDuration":     time.Since(hashStart).Seconds(),
		}).Info("hash verification completed")
	}

	return content, nil
}

// downloadHashFile downloads and parses a hash file from the given URL
func (rm *RulesetManager) downloadHashFile(ctx context.Context, source *RulesetSource) (string, error) {
	if source.URLHash == "" {
		return "", nil
	}

	// Download hash file
	content, err := rm.downloadURL(ctx, source, source.URLHash, "hash file")
	if err != nil {
		return "", err
	}

	// Parse the hash from the file content (expect a single line with just the hash)
	hashStr := strings.TrimSpace(string(content))
	if hashStr == "" {
		return "", fmt.Errorf("hash file is empty")
	}

	// Validate that it looks like a hex hash
	if _, err := hex.DecodeString(hashStr); err != nil {
		return "", fmt.Errorf("invalid hash format: %w", err)
	}

	return hashStr, nil
}

// verifyContentHash verifies the content against the expected hash
// Auto-detects hash type based on hash length (32 chars = MD5, 64 chars = SHA256)
func (rm *RulesetManager) verifyContentHash(content []byte, expectedHash string) error {
	if expectedHash == "" {
		return nil // No hash to verify
	}

	var computedHash string

	switch len(expectedHash) {
	case 32: // MD5 hash (128 bits = 32 hex chars)
		hash := md5.Sum(content)
		computedHash = hex.EncodeToString(hash[:])
	case 64: // SHA256 hash (256 bits = 64 hex chars)
		hash := sha256.Sum256(content)
		computedHash = hex.EncodeToString(hash[:])
	default:
		return fmt.Errorf("unsupported hash length %d (expected 32 for MD5 or 64 for SHA256)", len(expectedHash))
	}

	if !strings.EqualFold(computedHash, expectedHash) {
		return fmt.Errorf("hash verification failed: expected %s, got %s", expectedHash, computedHash)
	}

	rm.logger.WithFields(log.Fields{
		"hashType": map[int]string{32: "MD5", 64: "SHA256"}[len(expectedHash)],
		"hash":     expectedHash,
	}).Debug("hash verification successful")

	return nil
}

// extractArchive auto-detects archive format and extracts .rules files.
// Takes a path (URL or file path) to determine format, and raw content bytes.
// Returns a map of filename -> content for all .rules files found.
func (rm *RulesetManager) extractArchive(path string, content []byte) (map[string][]byte, error) {
	// Auto-detect and extract based on file extension
	switch {
	case strings.HasSuffix(path, ".tar.gz"), strings.HasSuffix(path, ".tgz"):
		return rm.extractTarGzFiles(content)
	case strings.HasSuffix(path, ".gz"):
		return rm.extractGzipFiles(content, path)
	case strings.HasSuffix(path, ".rules"):
		// Single .rules file - use filename as key
		return map[string][]byte{filepath.Base(path): content}, nil
	default:
		// Plain text rules - treat as single rules file
		return map[string][]byte{"rules.rules": content}, nil
	}
}

// fetchRulesFiles fetches rules files from a URL or directory source.
// Returns a map of filename -> content for all .rules files found.
func (rm *RulesetManager) fetchRulesFiles(ctx context.Context, source *RulesetSource) (map[string][]byte, error) {
	switch source.SourceType {
	case "url":
		content, err := rm.downloadRuleset(ctx, source)
		if err != nil {
			return nil, err
		}
		return rm.extractArchive(source.SourcePath, content)
	case "directory":
		return rm.readDirectoryRulesFiles(source)
	default:
		return nil, fmt.Errorf("unsupported source type for fetchRulesFiles: %s", source.SourceType)
	}
}

// concatenateRulesFiles combines all .rules files into a single string.
// Applies exclusion filters and consistent trimming.
func (rm *RulesetManager) concatenateRulesFiles(files map[string][]byte, source *RulesetSource) string {
	var rules strings.Builder
	var excludedCount int

	for filename, content := range files {
		// Only process .rules files
		if !strings.HasSuffix(filename, ".rules") {
			continue
		}

		// Check if file should be excluded
		if rm.shouldExcludeFile(filename, source.ExcludeFiles) {
			rm.logger.WithFields(log.Fields{
				"ruleset":  source.Name,
				"filename": filename,
			}).Info("excluding rules file")
			excludedCount++
			continue
		}

		rules.Write(content)
		rules.WriteString("\n")
	}

	if excludedCount > 0 {
		rm.logger.WithFields(log.Fields{
			"ruleset":       source.Name,
			"excludedCount": excludedCount,
		}).Info("excluded rules files")
	}

	// Consistent trimming for all sources
	return strings.TrimSuffix(rules.String(), "\n")
}

// extractTarGzFiles extracts files from a tar.gz archive
func (rm *RulesetManager) extractTarGzFiles(content []byte) (map[string][]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	files := make(map[string][]byte)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Only extract .rules files
		if strings.HasSuffix(header.Name, ".rules") {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}
			files[header.Name] = content
		}
	}

	return files, nil
}

// extractGzipFiles extracts a gzip-compressed file.
// Takes raw gzip content and the original path (for deriving filename).
func (rm *RulesetManager) extractGzipFiles(content []byte, path string) (map[string][]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, err
	}

	// Derive filename from path, stripping .gz extension
	filename := filepath.Base(path)
	filename = strings.TrimSuffix(filename, ".gz")
	if !strings.HasSuffix(filename, ".rules") {
		filename += ".rules"
	}

	return map[string][]byte{
		filename: decompressed,
	}, nil
}

// readDirectoryRulesFiles reads rules from a path which can be:
// - A directory containing .rules files
// - A single .rules file
// - A single archive file (.tar.gz, .gz)
// Returns a map of filename -> content for all .rules files found.
func (rm *RulesetManager) readDirectoryRulesFiles(source *RulesetSource) (map[string][]byte, error) {
	path := source.SourcePath
	files := make(map[string][]byte)

	// Check if path is a file or directory
	info, err := rm.ioManager.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %q: %w", path, err)
	}

	if !info.IsDir() {
		// Single file - read and potentially extract
		content, err := rm.ioManager.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q: %w", path, err)
		}
		return rm.extractArchive(path, content)
	}

	// Directory - walk and read all .rules files
	err = rm.ioManager.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && strings.HasSuffix(filePath, ".rules") {
			content, err := rm.ioManager.ReadFile(filePath)
			if err != nil {
				return err
			}
			// Use relative path as key for consistent naming
			relPath, err := filepath.Rel(path, filePath)
			if err != nil {
				relPath = d.Name()
			}
			files[relPath] = content
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// shouldExcludeFile checks if a filename should be excluded based on patterns.
// Patterns are matched against the basename only (e.g., "retired.rules" not "/nsm/rules/retired.rules"),
// so a pattern like "*retired*" will match files at any directory depth.
func (rm *RulesetManager) shouldExcludeFile(filename string, excludePatterns []string) bool {
	basename := filepath.Base(filename)
	for _, pattern := range excludePatterns {
		matched, err := filepath.Match(pattern, basename)
		if err != nil {
			rm.logger.WithError(err).WithField("pattern", pattern).Warn("invalid exclude pattern")
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// queryElasticsearch queries Elasticsearch for existing user-created rules.
// Unlike URL/directory sources, this doesn't fetch external rules but instead
// retrieves rules that users created via the web interface. These rules are
// included in the sync to ensure they're written to Suricata's rules files.
//
// The SourcePath format is "index.field:value" (e.g., "so_detection.ruleset:__custom__").
func (rm *RulesetManager) queryElasticsearch(ctx context.Context, detStore server.Detectionstore, source *RulesetSource) ([]*model.Detection, error) {
	rm.logger.WithField("query", source.SourcePath).Debug("querying Elasticsearch for existing user-created rules")

	if detStore == nil {
		rm.logger.WithField("ruleset", source.Name).Error("detection store is nil")
		return nil, fmt.Errorf("detection store not available")
	}

	// Query Elasticsearch for enabled custom rules using the available detStore
	detections, err := detStore.GetAllDetections(ctx,
		model.WithEngine(model.EngineNameSuricata),
		model.WithEnabled(true),
		model.WithCommunity(false), // Local/custom rules are not community rules
	)
	if err != nil {
		// Return error so this ruleset is marked as failed
		rm.logger.WithError(err).Error("failed to query Elasticsearch for custom rules")
		return nil, fmt.Errorf("elasticsearch unavailable: %w", err)
	}

	rm.logger.WithField("count", len(detections)).Info("retrieved custom rules from Elasticsearch")

	// Filter out deleted rules and non-custom rules
	customDetections := make([]*model.Detection, 0, len(detections))
	for _, det := range detections {
		if !det.PendingDelete && det.Ruleset == "__custom__" {
			customDetections = append(customDetections, det)
		}
	}

	rm.logger.WithField("customCount", len(customDetections)).Debug("filtered enabled custom rules")

	return customDetections, nil
}
