package detections

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
	"github.com/go-git/go-git/v5"
)

type GetterByPublicId interface {
	GetDetectionByPublicId(ctx context.Context, publicId string) (*model.Detection, error)
}

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
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

type DirtyRepo struct {
	WasModified bool
	Repo        *model.RuleRepo
}

func UpdateRepos(isRunning *bool, baseRepoFolder string, rulesRepos []*model.RuleRepo) (allRepos map[string]*DirtyRepo, anythingNew bool, err error) {
	allRepos = map[string]*DirtyRepo{} // map[repoPath]repo

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

		dirty := &DirtyRepo{
			Repo: repo,
		}

		allRepos[repoPath] = dirty
		reclone := false

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

			err = work.PullContext(ctx, &git.PullOptions{
				Depth:        1,
				SingleBranch: true,
			})
			if err != nil && err != git.NoErrAlreadyUpToDate {
				cancel()
				log.WithError(err).WithField("repoPath", repoPath).Error("failed to pull repo, doing nothing with it")
				reclone = true

				goto skippull
			}
			cancel()

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
				Depth:        1,
				SingleBranch: true,
				URL:          repo.Repo,
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
