package detections

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
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

		sums, err := readAiSummary(isRunning, repoPath, lang, logger, iom)
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

func readAiSummary(isRunning *bool, repoRoot string, lang model.SigLanguage, logger *log.Entry, iom IOManager) (sums []*model.AiSummary, err error) {
	aiRepoMutex.Lock()
	defer aiRepoMutex.Unlock()

	filename := fmt.Sprintf("%s_summaries.yaml", lang)
	targetFile := filepath.Join(repoRoot, "detections-ai/", filename)

	logger.WithField("targetFile", targetFile).Info("reading AI summaries")

	raw, err := iom.ReadFile(targetFile)
	if err != nil {
		return nil, err
	}

	// large yaml files take 30+ seconds to unmarshal, so we need to check if the
	// module has stopped or risk becoming unresponsive when sent a signal to stop
	done := false
	data := map[string]*model.AiSummary{}

	go func() {
		err = yaml.Unmarshal(raw, data)
		done = true
	}()

	for !done {
		if !*isRunning {
			return nil, ErrModuleStopped
		}

		time.Sleep(time.Millisecond * 200)
	}

	if err != nil {
		return nil, err
	}

	logger.Info("successfully unmarshalled AI summaries, parsing...")

	for pid, sum := range data {
		if !*isRunning {
			return nil, ErrModuleStopped
		}

		sum.PublicId = pid
		sums = append(sums, sum)
	}

	logger.WithField("aiSummaryCount", len(sums)).Info("successfully parsed AI summaries")

	return sums, nil
}
