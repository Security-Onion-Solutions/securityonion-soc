// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/fsnotify/fsnotify"
	"github.com/security-onion-solutions/securityonion-soc/agent"
	"github.com/security-onion-solutions/securityonion-soc/module"
)

const (
	DEFAULT_CONCURRENCY       = 8
	DEFAULT_MAX_DEPTH         = 15
	DEFAULT_DEDUP_MAX_ENTRIES = 100000
	DEFAULT_DEDUP_TTL_SECONDS = 3600
	DEFAULT_RECYCLE_SECONDS   = 300
	DEFAULT_LOG_FILE          = "/var/log/strelka/strelka.log"
	DEFAULT_PROCESSED_DIR     = "/nsm/strelka/processed"
	DEFAULT_HISTORY_DIR       = "/nsm/strelka/history"
	DEFAULT_SCANNER_TIMEOUT   = 150
)

type FileAnalyze struct {
	agent        *agent.Agent
	config       module.ModuleConfig
	running      bool
	stopChan     chan struct{}
	wg           sync.WaitGroup
	watchDirs    []string
	processedDir string
	historyDir   string
	logFile      string
	concurrency  int
	maxDepth     int
	recycleSecs  int
	dedup        *Dedup
	registry     *ScannerRegistry
	pipeline     *Pipeline
}

func NewFileAnalyze(agt *agent.Agent) *FileAnalyze {
	return &FileAnalyze{
		agent:    agt,
		stopChan: make(chan struct{}),
	}
}

func (fa *FileAnalyze) PrerequisiteModules() []string {
	return nil
}

func (fa *FileAnalyze) Init(cfg module.ModuleConfig) error {
	fa.config = cfg

	fa.watchDirs = module.GetStringArrayDefault(cfg, "watchDirs", []string{"/nsm/zeek/extracted/complete"})
	fa.processedDir = module.GetStringDefault(cfg, "processedDir", DEFAULT_PROCESSED_DIR)
	fa.historyDir = module.GetStringDefault(cfg, "historyDir", DEFAULT_HISTORY_DIR)
	fa.logFile = module.GetStringDefault(cfg, "logFile", DEFAULT_LOG_FILE)
	fa.concurrency = module.GetIntDefault(cfg, "concurrency", DEFAULT_CONCURRENCY)
	fa.maxDepth = module.GetIntDefault(cfg, "maxDepth", DEFAULT_MAX_DEPTH)
	fa.recycleSecs = module.GetIntDefault(cfg, "recycleSeconds", DEFAULT_RECYCLE_SECONDS)

	dedupMaxEntries := module.GetIntDefault(cfg, "dedupMaxEntries", DEFAULT_DEDUP_MAX_ENTRIES)
	dedupTTL := module.GetIntDefault(cfg, "dedupTTLSeconds", DEFAULT_DEDUP_TTL_SECONDS)
	fa.dedup = NewDedup(dedupMaxEntries, dedupTTL, fa.historyDir)

	// Ensure directories exist
	for _, dir := range []string{fa.processedDir, fa.historyDir, filepath.Dir(fa.logFile)} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// Initialize scanner registry
	fa.registry = NewScannerRegistry()
	fa.registerScanners(cfg)

	// Initialize result writer and pipeline
	resultWriter := NewResultWriter(fa.logFile)
	fa.pipeline = NewPipeline(fa.registry, resultWriter, fa.maxDepth)

	log.WithFields(log.Fields{
		"watchDirs":   fa.watchDirs,
		"concurrency": fa.concurrency,
		"maxDepth":    fa.maxDepth,
	}).Info("FileAnalyze module initialized")

	return nil
}

func (fa *FileAnalyze) registerScanners(cfg module.ModuleConfig) {
	yaraRulesPath := module.GetStringDefault(cfg, "yaraRulesPath", DEFAULT_YARA_RULES_PATH)

	passwordsPath := module.GetStringDefault(cfg, "passwordsPath", DEFAULT_PASSWORDS_PATH)

	allScanners := []Scanner{
		// Phase 1 — Core
		NewHashScanner(),
		NewEntropyScanner(),
		NewHeaderScanner(),
		// Phase 2 — YARA + Archives
		&YaraScanner{rulesPath: yaraRulesPath, compiled: true, timeout: DEFAULT_YARA_TIMEOUT},
		NewZipScanner(),
		NewGzipScanner(),
		NewBzip2Scanner(),
		NewTarScanner(),
		NewZlibScanner(),
		NewSevenZipScanner(),
		NewLzmaScanner(),
		// Phase 3 — Documents + Macros
		NewDocxScanner(),
		NewOleScanner(),
		NewVbaScanner(),
		NewRtfScanner(),
		NewPdfScanner(),
		NewEmailScanner(),
		NewTnefScanner(),
		NewOnenoteScanner(),
		&EncryptedZipScanner{passwordsPath: passwordsPath, timeout: DEFAULT_SCANNER_TIMEOUT},
		&EncryptedDocScanner{passwordsPath: passwordsPath, timeout: DEFAULT_SCANNER_TIMEOUT},
		// Phase 4 — Executables + Scripts
		NewPeScanner(),
		NewElfScanner(),
		NewMachoScanner(),
		NewJavascriptScanner(),
		NewPhpScanner(),
		NewVbScanner(),
		NewBatchScanner(),
		NewBase64PeScanner(),
		NewDonutScanner(),
		NewSwfScanner(),
		NewUpxScanner(),
		// Phase 5 — Images + Crypto + Markup + Metadata
		NewJpegScanner(),
		NewGifScanner(),
		NewBmpEofScanner(),
		NewPngEofScanner(),
		NewLsbScanner(),
		NewOcrScanner(),
		NewQrScanner(),
		NewTranscodeScanner(),
		NewX509Scanner(),
		NewPkcs7Scanner(),
		NewPgpScanner(),
		NewExiftoolScanner(),
		NewHtmlScanner(),
		NewXmlScanner(),
		NewJsonScanner(),
		NewIniScanner(),
		NewLnkScanner(),
		NewManifestScanner(),
		NewJarManifestScanner(),
		NewUrlScanner(),
		NewIqyScanner(),
		NewVstoScanner(),
	}

	for _, s := range allScanners {
		if err := s.Init(nil); err != nil {
			log.WithField("scanner", s.Name()).WithError(err).Warn("Failed to initialize scanner")
			continue
		}
		fa.registry.Register(s)
		log.WithField("scanner", s.Name()).Info("Registered scanner")
	}
}

func (fa *FileAnalyze) Start() error {
	fa.running = true

	// Process existing files on startup (like filecheck's checkexisting)
	fa.wg.Add(1)
	go func() {
		defer fa.wg.Done()
		fa.processExisting()
	}()

	// Start watcher loop with periodic recycling
	fa.wg.Add(1)
	go func() {
		defer fa.wg.Done()
		fa.watchLoop()
	}()

	log.Info("FileAnalyze module started")
	return nil
}

func (fa *FileAnalyze) Stop() error {
	log.Info("FileAnalyze module stopping")
	fa.running = false
	close(fa.stopChan)
	fa.wg.Wait()
	log.Info("FileAnalyze module stopped")
	return nil
}

func (fa *FileAnalyze) IsRunning() bool {
	return fa.running
}

func (fa *FileAnalyze) processExisting() {
	log.Info("Checking for existing files")
	for _, dir := range fa.watchDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors
			}
			if info.IsDir() {
				return nil
			}
			fa.handleFile(path)
			return nil
		})
		if err != nil {
			log.WithField("dir", dir).WithError(err).Warn("Error walking directory")
		}
	}
}

func (fa *FileAnalyze) watchLoop() {
	for {
		if err := fa.runWatcher(); err != nil {
			log.WithError(err).Error("Watcher error")
		}

		select {
		case <-fa.stopChan:
			return
		case <-time.After(time.Duration(fa.recycleSecs) * time.Second):
			log.Info("Recycling file watcher to pick up new subdirectories")
		}
	}
}

func (fa *FileAnalyze) runWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Add all watch dirs and their subdirectories
	for _, dir := range fa.watchDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if watchErr := watcher.Add(path); watchErr != nil {
					log.WithField("path", path).WithError(watchErr).Warn("Failed to watch directory")
				}
			}
			return nil
		})
		if err != nil {
			log.WithField("dir", dir).WithError(err).Warn("Error setting up watches")
		}
	}

	// Use a semaphore channel for concurrency limiting
	sem := make(chan struct{}, fa.concurrency)

	recycleTicker := time.NewTicker(time.Duration(fa.recycleSecs) * time.Second)
	defer recycleTicker.Stop()

	for {
		select {
		case <-fa.stopChan:
			return nil
		case <-recycleTicker.C:
			return nil // Return to trigger watcher recycle
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) != 0 {
				// Check if it's a directory (add to watcher) or file (process)
				info, err := os.Stat(event.Name)
				if err != nil {
					continue
				}
				if info.IsDir() {
					watcher.Add(event.Name)
					continue
				}

				sem <- struct{}{}
				fa.wg.Add(1)
				go func(path string) {
					defer fa.wg.Done()
					defer func() { <-sem }()
					fa.handleFile(path)
				}(event.Name)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.WithError(err).Error("File watcher error")
		}
	}
}

func (fa *FileAnalyze) handleFile(path string) {
	// Skip temp files
	if filepath.Base(path) == "" {
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}

	// Small delay to ensure file is fully written
	time.Sleep(100 * time.Millisecond)

	// Dedup check
	isDup, hash, err := fa.dedup.IsDuplicate(path)
	if err != nil {
		log.WithField("file", path).WithError(err).Warn("Dedup check failed")
		return
	}
	if isDup {
		log.WithField("file", path).Debug("Duplicate file, removing")
		os.Remove(path)
		return
	}

	// Mark as seen
	if err := fa.dedup.MarkSeen(hash); err != nil {
		log.WithField("file", path).WithError(err).Warn("Failed to mark file as seen")
	}

	// Process through scanner pipeline
	log.WithFields(log.Fields{
		"file": path,
		"hash": hash,
	}).Info("Processing file")

	if err := fa.pipeline.ProcessFile(path, hash, 0); err != nil {
		log.WithField("file", path).WithError(err).Error("Failed to process file")
		return
	}

	// Move to processed directory
	destPath := filepath.Join(fa.processedDir, filepath.Base(path))
	if err := os.Rename(path, destPath); err != nil {
		// Cross-device move fallback not needed for same filesystem
		log.WithField("file", path).WithError(err).Warn("Failed to move file to processed dir")
	}
}
