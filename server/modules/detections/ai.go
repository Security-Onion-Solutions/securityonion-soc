package detections

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"sync"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"gopkg.in/yaml.v3"
)

var aiRepoMutex = sync.Mutex{}

type AiLoader interface {
	LoadAuxilleryData(summaries []*model.AiSummary) error
}

//go:generate mockgen -destination mock/mock_ailoader.go -package mock . AiLoader

func RefreshAiSummaries(eng AiLoader, engName model.EngineName, isRunning *bool, aiRepoPath string, aiRepoUrl string, iom IOManager, logger *log.Entry) error {
	err := updateAiRepo(isRunning, aiRepoPath, aiRepoUrl, iom)
	if err != nil {
		if errors.Is(err, ErrModuleStopped) {
			return err
		}

		logger.WithError(err).WithFields(log.Fields{
			"aiRepoUrl":  aiRepoUrl,
			"aiRepoPath": aiRepoPath,
		}).Error("unable to update AI repo")
	}

	parser, err := url.Parse(aiRepoUrl)
	if err != nil {
		log.WithError(err).WithField("aiRepoUrl", aiRepoUrl).Error("Failed to parse repo URL, doing nothing with it")
	} else {
		_, lastFolder := path.Split(parser.Path)
		repoPath := filepath.Join(aiRepoPath, lastFolder)

		sums, err := readAiSummary(repoPath, engName, iom)
		if err != nil {
			logger.WithError(err).WithField("repoPath", repoPath).Error("unable to read AI summary")
		} else {
			err = eng.LoadAuxilleryData(sums)
			if err != nil {
				logger.WithError(err).Error("unable to load AI summaries")
			} else {
				logger.Info("successfully loaded AI summaries")
			}
		}
	}

	return nil
}

func updateAiRepo(isRunning *bool, baseRepoFolder string, repoUrl string, iom IOManager) error {
	aiRepoMutex.Lock()
	defer aiRepoMutex.Unlock()

	_, _, err := UpdateRepos(isRunning, baseRepoFolder, []*model.RuleRepo{
		{
			Repo: repoUrl,
		},
	}, iom)

	return err
}

func readAiSummary(repoRoot string, engine model.EngineName, iom IOManager) (sums []*model.AiSummary, err error) {
	aiRepoMutex.Lock()
	defer aiRepoMutex.Unlock()

	filename := fmt.Sprintf("detections-ai-%s.yml", engine)
	targetFile := filepath.Join(repoRoot, "detections-ai/", filename)

	raw, err := iom.ReadFile(targetFile)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(raw, &sums)
	if err != nil {
		return nil, err
	}

	return sums, nil
}
