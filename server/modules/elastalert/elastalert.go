package elastalert

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/google/go-github/v56/github"
)

var errModuleStopped = fmt.Errorf("module has stopped running")

type ElastAlertEngine struct {
	srv                                  *server.Server
	communityRulesImportFrequencySeconds int
	sigmaRepo                            string
	elastAlertRulesFolder                string
	rulesFingerprintFile                 string
	sigconverterUrl                      string
	sigmaRulePackages                    []string
	isRunning                            bool
	thread                               *sync.WaitGroup
}

func NewElastAlertEngine(srv *server.Server) *ElastAlertEngine {
	return &ElastAlertEngine{
		srv: srv,
	}
}

func (e *ElastAlertEngine) PrerequisiteModules() []string {
	return nil
}

func (e *ElastAlertEngine) Init(config module.ModuleConfig) error {
	e.communityRulesImportFrequencySeconds = module.GetIntDefault(config, "communityRulesImportFrequencySeconds", 600)
	e.sigmaRepo = module.GetStringDefault(config, "sigmaRepo", "https://github.com/SigmaHQ/sigma")
	e.elastAlertRulesFolder = module.GetStringDefault(config, "elastAlertRulesFolder", "/opt/so/rules/elastalert")
	e.rulesFingerprintFile = module.GetStringDefault(config, "rulesFingerprintFile", "/opt/so/conf/soc/sigma.fingerprint")
	e.sigconverterUrl = module.GetStringDefault(config, "sigconverterUrl", "http://manager:8000/sigma")

	pkgs := module.GetStringDefault(config, "sigmaRulePackages", "core")
	e.parseSigmaPackages(pkgs)

	return nil
}

func (e *ElastAlertEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameElastAlert] = e
	e.isRunning = true

	go e.startCommunityRuleImport()

	return nil
}

func (e *ElastAlertEngine) Stop() error {
	e.isRunning = false

	return nil
}

func (e *ElastAlertEngine) IsRunning() bool {
	return e.isRunning
}

func (e *ElastAlertEngine) ValidateRule(data string) (string, error) {
	_, err := ParseElastAlertRule([]byte(data))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *ElastAlertEngine) parseSigmaPackages(cfg string) {
	pkgs := strings.Split(strings.ToLower(cfg), "\n")
	set := map[string]struct{}{}

	for _, pkg := range pkgs {
		switch pkg {
		case "all":
			set["all_rules"] = struct{}{}
		case "emerging_threats_addon":
			set["emerging_threats"] = struct{}{}
		default:
			pkg = strings.TrimSpace(pkg)
			if pkg != "" {
				set[pkg] = struct{}{}
			}
		}
	}

	_, ok := set["all_rules"]
	if ok {
		delete(set, "core++")
		delete(set, "core+")
		delete(set, "core")
		delete(set, "emerging_threats")
	}

	_, ok = set["core++"]
	if ok {
		delete(set, "core+")
		delete(set, "core")
	}

	_, ok = set["core+"]
	if ok {
		delete(set, "core")
	}

	e.sigmaRulePackages = make([]string, 0, len(set))
	for pkg := range set {
		e.sigmaRulePackages = append(e.sigmaRulePackages, pkg)
	}
}

func (e *ElastAlertEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	return nil, nil
}

func (e *ElastAlertEngine) startCommunityRuleImport() {
	defer func() {
		e.thread.Done()
		e.isRunning = false
	}()

	ctx := e.srv.Context

	for e.isRunning {
		time.Sleep(time.Duration(e.communityRulesImportFrequencySeconds) * time.Second)
		if !e.isRunning {
			return
		}

		start := time.Now()

		zips, errMap := e.downloadSigmaPackages(ctx)
		if len(errMap) != 0 {
			log.WithField("errorMap", errMap).Error("something went wrong downloading sigma packages")
			continue
		}

		zipHashes := map[string]string{}
		for pkg, data := range zips {
			h := sha256.Sum256(data)
			zipHashes[pkg] = base64.StdEncoding.EncodeToString(h[:])
		}

		raw, err := os.ReadFile(e.rulesFingerprintFile)
		if err != nil && !os.IsNotExist(err) {
			log.WithError(err).WithField("path", e.rulesFingerprintFile).Error("unable to read rules fingerprint file")
			continue
		} else if err == nil {
			oldHashes := map[string]string{}

			err = json.Unmarshal(raw, &oldHashes)
			if err != nil {
				log.WithError(err).Error("unable to unmarshal rules fingerprint file")
				continue
			}

			if reflect.DeepEqual(oldHashes, zipHashes) {
				// only an exact match means no work needs to be done.
				// If there's extra hashes in the old file, we need to remove them.
				// If there's extra hashes in the new file, we need to add them.
				// If there's a mix of new and old hashes, we need to include them all
				// or the old ones would be removed.
				log.Info("no sigma package changes to sync")
				continue
			}
		}

		detections, errMap := e.parseRules(zips)
		if errMap != nil {
			log.WithField("error", errMap).Error("something went wrong while parsing sigma rule files")
			continue
		}

		errMap, err = e.syncCommunityDetections(ctx, detections)
		if err != nil {
			if err == errModuleStopped {
				log.Info("incomplete sync of elastalert community detections due to module stopping")
				return
			}

			log.WithError(err).Error("unable to sync elastalert community detections")
			continue
		}

		if len(errMap) > 0 {
			// there were errors, don't save the fingerprint.
			// idempotency means we might fix it if we try again later.
			log.WithFields(log.Fields{
				"errors": errMap,
			}).Error("unable to sync all community detections")
		} else {
			fingerprints, err := json.Marshal(zipHashes)
			if err != nil {
				log.WithError(err).Error("unable to marshal rules fingerprints")
			} else {
				err = os.WriteFile(e.rulesFingerprintFile, fingerprints, 0644)
				if err != nil {
					log.WithError(err).WithField("path", e.rulesFingerprintFile).Error("unable to write rules fingerprint file")
				}
			}
		}

		dur := time.Since(start)

		log.WithFields(log.Fields{
			"durationSeconds": dur.Seconds(),
		}).Info("elastalert community rules synced")
	}
}

func (e *ElastAlertEngine) parseRules(pkgZips map[string][]byte) (detections []*model.Detection, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName|fileName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	acceptedExtensions := map[string]bool{
		".yml":  true,
		".yaml": true,
	}

	for pkg, zipData := range pkgZips {
		reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err != nil {
			errMap[pkg] = err
			continue
		}

		for _, file := range reader.File {
			if file.FileInfo().IsDir() || !acceptedExtensions[strings.ToLower(filepath.Ext(file.Name))] {
				continue
			}

			f, err := file.Open()
			if err != nil {
				errMap[file.Name] = err
				continue
			}

			data, err := io.ReadAll(f)
			if err != nil {
				f.Close()
				errMap[file.Name] = err
				continue
			}

			f.Close()

			rule, err := ParseElastAlertRule(data)
			if err != nil {
				errMap[file.Name] = err
				continue
			}

			id := rule.Title

			if rule.ID != nil {
				id = *rule.ID
			} else {
				fmt.Println()
			}

			sev := model.SeverityUnknown

			if rule.Level != nil {
				switch strings.ToLower(string(*rule.Level)) {
				case "informational":
					sev = model.SeverityInformational
				case "low":
					sev = model.SeverityLow
				case "medium":
					sev = model.SeverityMedium
				case "high":
					sev = model.SeverityHigh
				case "critical":
					sev = model.SeverityCritical
				}
			}

			detections = append(detections, &model.Detection{
				PublicID:    id,
				Title:       rule.Title,
				Severity:    sev,
				Content:     string(data),
				IsCommunity: true,
				Engine:      model.EngineNameElastAlert,
			})
		}
	}

	return detections, errMap
}

func (e *ElastAlertEngine) syncCommunityDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]error, err error) {
	index, err := e.indexExistingRules()
	if err != nil {
		return nil, err
	}

	community, err := e.srv.Detectionstore.GetAllCommunitySIDs(ctx, util.Ptr(model.EngineNameElastAlert))
	if err != nil {
		return nil, err
	}

	toDelete := map[string]struct{}{} // map[publicID]struct{}
	for _, det := range community {
		toDelete[det.PublicID] = struct{}{}
	}

	results := struct {
		Added     int
		Updated   int
		Removed   int
		Unchanged int
	}{}

	errMap = map[string]error{} // map[publicID]error

	// detections = []*model.Detection{}
	for _, det := range detections {
		path, ok := index[det.PublicID]
		if !ok {
			path = index[det.Title]
		}

		det.IsEnabled = path != ""

		// 1. Save sigma Detection to ElasticSearch
		oldDet, exists := community[det.PublicID]
		if exists {
			det.Id = oldDet.Id
			if oldDet.Content != det.Content {
				_, err = e.srv.Detectionstore.UpdateDetection(ctx, det)
				if err != nil {
					errMap[det.PublicID] = fmt.Errorf("unable to update detection: %s", err)
					continue
				}

				delete(toDelete, det.PublicID)
				results.Updated++
			} else {
				delete(toDelete, det.PublicID)
				results.Unchanged++
			}
		} else {
			_, err = e.srv.Detectionstore.CreateDetection(ctx, det)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to create detection: %s", err)
				continue
			}

			delete(toDelete, det.PublicID)
			results.Added++
		}

		if det.IsEnabled {
			// 2. if enabled, send data to docker container to get converted to query

			rule, err := e.sigmaToElastAlert(ctx, det.Content) // get sigma from docker container
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to convert sigma to elastalert: %s", err)
				continue
			}

			_ = rule
			// 3. put query in /opt/so/rules/sigma for salt to pick up

			err = nil // os.WriteFile(path, []byte(rule), 0644)
			if err != nil {
				errMap[det.PublicID] = fmt.Errorf("unable to write enabled detection file: %s", err)
				continue
			}
		}
	}

	for publicId := range toDelete {
		_, err = e.srv.Detectionstore.DeleteDetection(ctx, community[publicId].Id)
		if err != nil {
			errMap[publicId] = fmt.Errorf("unable to delete detection: %s", err)
			continue
		}

		results.Removed++
	}

	log.WithFields(log.Fields{
		"added":     results.Added,
		"updated":   results.Updated,
		"removed":   results.Removed,
		"unchanged": results.Unchanged,
		"errors":    errMap,
	}).Info("elastalert community diff")

	return errMap, nil
}

func (e *ElastAlertEngine) downloadSigmaPackages(ctx context.Context) (zipData map[string][]byte, errMap map[string]error) {
	errMap = map[string]error{} // map[pkgName]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	gh := github.NewClient(nil)

	release, _, err := gh.Repositories.GetLatestRelease(ctx, "SigmaHQ", "sigma")
	if err != nil {
		errMap["sigma"] = err
		return nil, errMap
	}

	pkgs := map[string]string{} // map[pkgName]downloadUrl

	// organize assets
	for _, asset := range release.Assets {
		name := strings.ToLower(asset.GetName())
		if !strings.HasSuffix(name, ".zip") {
			continue
		}

		link := asset.GetBrowserDownloadURL()

		// Must be if/else-if so the order is correct.
		// A switch statement might check "core" before "core++"
		if strings.Contains(name, "all_rules") {
			pkgs["all_rules"] = link
		} else if strings.Contains(name, "core++") {
			pkgs["core++"] = link
		} else if strings.Contains(name, "core+") {
			pkgs["core+"] = link
		} else if strings.Contains(name, "core") {
			pkgs["core"] = link
		} else if strings.Contains(name, "emerging_threats") {
			pkgs["emerging_threats"] = link
		}
	}

	stats := map[string]int{} // map[pkgName]fileSize
	zipData = map[string][]byte{}

	for _, pkg := range e.sigmaRulePackages {
		download, ok := pkgs[pkg]
		if !ok {
			log.WithField("package", pkg).Warn("unknown sigma package")
			continue
		}

		resp, err := http.Get(download)
		if err != nil {
			errMap[pkg] = err
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			errMap[pkg] = fmt.Errorf("non-200 status code during download: %d", resp.StatusCode)
			continue
		}

		zipData[pkg], err = io.ReadAll(resp.Body)
		if err != nil {
			errMap[pkg] = err
			continue
		}

		stats[pkg] = len(zipData[pkg])
	}

	log.WithField("downloadSizes", stats).Info("downloaded sigma packages")

	return zipData, nil
}

func (e *ElastAlertEngine) indexExistingRules() (index map[string]string, err error) {
	index = map[string]string{} // map[id | title]path

	rules, err := os.ReadDir(e.elastAlertRulesFolder)
	if err != nil {
		return nil, fmt.Errorf("unable to read elastalert rules directory: %w", err)
	}

	for _, rule := range rules {
		if rule.IsDir() {
			continue
		}

		filename := filepath.Join(e.elastAlertRulesFolder, rule.Name())

		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("unable to read elastalert rule file %s: %w", filename, err)
		}

		rule, err := ParseElastAlertRule(data)
		if err != nil {
			return nil, fmt.Errorf("unable to parse elastalert rule file %s: %w", filename, err)
		}

		id := rule.Title

		if rule.ID != nil {
			id = *rule.ID
		}

		index[id] = filename
	}

	return index, nil
}

func (e *ElastAlertEngine) sigmaToElastAlert(ctx context.Context, sigma string) (string, error) {
	// wrapper for the payload
	ruleWrapper := struct {
		Rule     string   `json:"rule"`
		Pipeline []string `json:"pipeline"`
		Target   string   `json:"target"`
		Format   string   `json:"format"`
	}{
		Rule:     base64.StdEncoding.EncodeToString([]byte(sigma)),
		Pipeline: []string{},
		Target:   "eql",
		Format:   "default",
	}

	payload, err := json.Marshal(ruleWrapper)
	if err != nil {
		return "", err
	}

	// build request
	req, err := http.NewRequest(http.MethodPost, e.sigconverterUrl, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	req = req.WithContext(ctx)
	req.Header.Add("Content-Type", "application/json")

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("sigconverter returned non-200 status code: %d", resp.StatusCode)
	}

	elastRule, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(elastRule), nil
}
