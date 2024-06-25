// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

var doubleQuoteEscaper = regexp.MustCompile(`\\([\s\S])|(")`)
var templateMutex = &sync.Mutex{}
var templateFound = false

type GetterByPublicId interface {
	GetDetectionByPublicId(ctx context.Context, publicId string) (*model.Detection, error)
}

// go install go.uber.org/mock/mockgen@latest
//go:generate mockgen -destination mock/mock_iomanager.go -package mock . IOManager

func DetermineWaitTime(iom IOManager, path string, importFrequency time.Duration) (*uint64, time.Duration) {
	lastImport, err := readStateFile(iom, path)
	if err != nil {
		log.WithError(err).Error("unable to read state file, deleting it")

		derr := iom.DeleteFile(path)
		if derr != nil {
			log.WithError(derr).WithField("path", path).Error("unable to remove state file, ignoring it")
		}
		lastImport = nil
	}

	var timerDur time.Duration

	if lastImport != nil {
		lastImportTime := time.Unix(int64(*lastImport), 0)
		nextImportTime := lastImportTime.Add(importFrequency)

		timerDur = time.Until(nextImportTime)
	} else {
		log.Info("no engine state file found, waiting 20 mins for first import")
		timerDur = time.Duration(time.Minute * 20)
	}

	return lastImport, timerDur
}

func readStateFile(iom IOManager, path string) (lastImport *uint64, err error) {
	raw, err := iom.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("unable to read engine state file: %w", err)
	}

	unix, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to parse engine state file: %w", err)
	}

	return &unix, nil
}

func TruncateMap(originalMap map[string]error, limit int) map[string]error {
	if len(originalMap) <= limit {
		return originalMap // Return the original map if it's already within the limit
	}

	truncatedMap := make(map[string]error, limit)
	count := 0
	for key, value := range originalMap {
		if count >= limit {
			break
		}
		truncatedMap[key] = value
		count++
	}
	return truncatedMap
}

func WriteStateFile(iom IOManager, path string) {
	unix := time.Now().Unix()
	sUnix := strconv.FormatInt(unix, 10)

	err := iom.WriteFile(path, []byte(sUnix), 0644)
	if err != nil {
		log.WithError(err).Error("unable to write state file")
	}
}

type RepoOnDisk struct {
	Repo        *model.RuleRepo
	Path        string
	WasModified bool
}

func UpdateRepos(isRunning *bool, baseRepoFolder string, rulesRepos []*model.RuleRepo, cfg *config.ServerConfig) (allRepos []*RepoOnDisk, anythingNew bool, err error) {
	allRepos = make([]*RepoOnDisk, 0, len(rulesRepos))

	// read existing repos
	entries, err := os.ReadDir(baseRepoFolder)
	if err != nil {
		log.WithError(err).WithField("reposFolder", baseRepoFolder).Error("Failed to read repos folder")
		return nil, false, err
	}

	existingRepos := map[string]struct{}{}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		existingRepos[entry.Name()] = struct{}{}
	}

	// pull or clone repos
	for _, repo := range rulesRepos {
		if !*isRunning {
			return nil, false, fmt.Errorf("module has stopped running")
		}

		parser, err := url.Parse(repo.Repo)
		if err != nil {
			log.WithError(err).WithField("repoUrl", repo.Repo).Error("Failed to parse repo URL, doing nothing with it")
			continue
		}

		_, lastFolder := path.Split(parser.Path)
		repoPath := filepath.Join(baseRepoFolder, lastFolder)

		dirty := &RepoOnDisk{
			Repo: repo,
			Path: repoPath,
		}

		allRepos = append(allRepos, dirty)
		reclone := false

		proxyOpts, err := proxyToTransportOptions(cfg.Proxy)
		if err != nil {
			log.WithError(err).WithField("proxy", cfg.Proxy).Error("failed to parse proxy URL, not using the proxy")
			// no return here, not a bug
		}

		_, ok := existingRepos[lastFolder]
		if ok {
			var work *git.Worktree
			var ctx context.Context
			var cancel context.CancelFunc

			// repo already exists, pull
			gitrepo, err := git.PlainOpen(repoPath)
			if err != nil {
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to open repo, doing nothing with it")
				reclone = true

				goto skippull
			}

			work, err = gitrepo.Worktree()
			if err != nil {
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to get worktree, doing nothing with it")
				reclone = true

				goto skippull
			}

			err = work.Reset(&git.ResetOptions{
				Mode: git.HardReset,
			})
			if err != nil {
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to reset worktree, doing nothing with it")
				reclone = true

				goto skippull
			}

			ctx, cancel = context.WithTimeout(context.Background(), time.Minute*5)
			defer cancel()

			err = work.PullContext(ctx, &git.PullOptions{
				Depth:           1,
				SingleBranch:    true,
				ProxyOptions:    proxyOpts,
				CABundle:        []byte(cfg.AdditionalCA),
				InsecureSkipTLS: cfg.InsecureSkipVerify,
			})
			if err != nil && err != git.NoErrAlreadyUpToDate {
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to pull repo, doing nothing with it")
				reclone = true

				goto skippull
			}

			if err == nil {
				anythingNew = true
				dirty.WasModified = true
			}

			delete(existingRepos, lastFolder)

		skippull:
		}

		if reclone {
			log.WithField("repoPath", repoPath).Info("removing problematic repo before re-clone")

			err = os.RemoveAll(repoPath)
			if err != nil {
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to remove repo, doing nothing with it")
				continue
			}
		}

		if !ok || reclone {
			// repo does not exist or was just deleted, clone
			_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
				Depth:           1,
				SingleBranch:    true,
				URL:             repo.Repo,
				ProxyOptions:    proxyOpts,
				CABundle:        []byte(cfg.AdditionalCA),
				InsecureSkipTLS: cfg.InsecureSkipVerify,
			})
			if err != nil {
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to clone repo, doing nothing with it")
				continue
			}

			anythingNew = true
			dirty.WasModified = true
		}
	}

	for repo := range existingRepos {
		// remove any repos that are no longer in the list
		repoPath := filepath.Join(baseRepoFolder, repo)

		err = os.RemoveAll(repoPath)
		if err != nil {
			log.WithError(err).WithField("repoPath", repoPath).Error("failed to remove repo, doing nothing with it")
			continue
		}
	}

	return allRepos, anythingNew, nil
}

func proxyToTransportOptions(proxy string) (transport.ProxyOptions, error) {
	if proxy == "" {
		return transport.ProxyOptions{}, nil
	}

	p, err := url.Parse(proxy)
	if err != nil {
		return transport.ProxyOptions{}, err
	}

	if p.Scheme == "" {
		p.Scheme = "http"
	}

	username := p.User.Username()
	password, _ := p.User.Password()

	p.User = nil

	return transport.ProxyOptions{
		URL:      p.String(),
		Username: username,
		Password: password,
	}, nil
}

func CheckWriteNoRead(ctx context.Context, DetStore GetterByPublicId, writeNoRead *string) (shouldFail bool) {
	if writeNoRead == nil {
		return false
	}

	log.WithField("publicId", *writeNoRead).Error("detection was written but not read back, attempting read before continuing")

	// det, err := e.srv.Detectionstore.GetDetectionByPublicId(e.srv.Context, *writeNoRead)
	det, err := DetStore.GetDetectionByPublicId(ctx, *writeNoRead)
	if err != nil {
		log.WithError(err).WithField("publicId", *writeNoRead).Error("failed to read back detection")

		return true
	}

	if det == nil {
		log.WithField("publicId", *writeNoRead).Error("detection still not found")

		return true
	}

	fields := log.Fields{
		"publicId":       *writeNoRead,
		"detectionDocId": det.Id,
	}

	if det.CreateTime != nil {
		fields["durationCouldNotRead"] = time.Since(*det.CreateTime).Seconds()
	}

	log.WithFields(fields).Info("detection read back successfully")

	return false
}

func MakeUser(user *model.User) string {
	author := strings.Join([]string{user.FirstName, user.LastName}, " ")
	if len(strings.TrimSpace(author)) == 0 {
		author = user.Email
	}
	return author
}

func AddUser(previous string, user *model.User, sep string) string {
	author := MakeUser(user)
	previous = strings.TrimSpace(previous)

	if previous == author || len(author) == 0 {
		return previous
	}

	if len(previous) > 0 {
		previous += sep
	}

	return previous + author
}

func EscapeDoubleQuotes(str string) string {
	return doubleQuoteEscaper.ReplaceAllString(str, "\\$1$2")
}

func DeduplicateByPublicId(detects []*model.Detection) []*model.Detection {
	set := map[string]*model.Detection{}
	deduped := make([]*model.Detection, 0, len(detects))

	for _, detect := range detects {
		existing, inSet := set[detect.PublicID]
		if inSet {
			log.WithFields(log.Fields{
				"publicId":         detect.PublicID,
				"engine":           detect.Engine,
				"existingRuleset":  existing.Ruleset,
				"duplicateRuleset": detect.Ruleset,
				"existingTitle":    existing.Title,
				"duplicateTitle":   detect.Title,
			}).Warn("duplicate publicId found, skipping")
		} else {
			set[detect.PublicID] = detect
			deduped = append(deduped, detect)
		}
	}

	return deduped
}

type TemplateChecker interface {
	DoesTemplateExist(ctx context.Context, tmpl string) (bool, error)
}

func CheckTemplate(ctx context.Context, detStore TemplateChecker) (haveTemplate bool) {
	templateMutex.Lock()
	defer templateMutex.Unlock()

	if templateFound {
		return true
	}

	exists, err := detStore.DoesTemplateExist(ctx, "so-detection")
	if err != nil {
		log.WithError(err).Error("failed to check for so-detection template")
		return false
	}

	templateFound = exists
	log.WithField("templateExists", exists).Info("checked for so-detection template")

	return exists
}
