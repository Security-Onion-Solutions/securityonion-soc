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

func RefreshAiSummaries(eng AiLoader, lang model.SigLanguage, isRunning *bool, aiRepoPath string, aiRepoUrl string, aiRepoBranch string, logger *log.Entry, iom IOManager) error {
	err := updateAiRepo(isRunning, aiRepoPath, aiRepoUrl, aiRepoBranch, iom)
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
		log.WithError(err).WithField("aiRepoUrl", aiRepoUrl).Error("failed to parse repo URL, doing nothing with it")
	} else {
		_, lastFolder := path.Split(parser.Path)
		repoPath := filepath.Join(aiRepoPath, lastFolder)

		sums, err := readAiSummary(repoPath, lang, logger, iom)
		if err != nil {
			logger.WithError(err).WithField("repoPath", repoPath).Error("unable to read AI summaries")
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

func updateAiRepo(isRunning *bool, baseRepoFolder string, repoUrl string, branch string, iom IOManager) error {
	aiRepoMutex.Lock()
	defer aiRepoMutex.Unlock()

	var branchPtr *string
	if branch != "" {
		branchPtr = &branch
	}

	_, _, err := UpdateRepos(isRunning, baseRepoFolder, []*model.RuleRepo{
		{
			Repo:   repoUrl,
			Branch: branchPtr,
		},
	}, iom)

	return err
}

func readAiSummary(repoRoot string, lang model.SigLanguage, logger *log.Entry, iom IOManager) (sums []*model.AiSummary, err error) {
	aiRepoMutex.Lock()
	defer aiRepoMutex.Unlock()

	filename := fmt.Sprintf("%s_summaries.yaml", lang)
	targetFile := filepath.Join(repoRoot, "detections-ai/", filename)

	logger.WithField("targetFile", targetFile).Info("reading AI summaries")

	raw, err := iom.ReadFile(targetFile)
	if err != nil {
		return nil, err
	}

	data := map[string]*model.AiSummary{}

	err = yaml.Unmarshal(raw, data)
	if err != nil {
		return nil, err
	}

	for pid, sum := range data {
		sum.PublicId = pid
		sums = append(sums, sum)
	}

	logger.WithField("aiSummaryCount", len(sums)).Info("successfully read AI summary")

	return sums, nil
}
