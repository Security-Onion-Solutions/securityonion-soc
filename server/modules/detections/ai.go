package detections

import (
	"errors"
	"net/url"
	"path"
	"path/filepath"
	"sync"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

var aiRepoMutex = sync.Mutex{}

type AiLoader interface {
	LoadAuxilleryData(summaries []*AiSummary) error
}

type AiSummary struct {
	PublicId string `json:"public_id"`
	Reviewed bool   `json:"reviewed"`
	Summary  string `json:"summary"`
}

func RefreshAiSummaries(eng AiLoader, isRunning *bool, aiRepoPath string, aiRepoUrl string, iom IOManager, logger *log.Entry) error {
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

		sums, err := readAiSummary(repoPath, model.EngineNameElastAlert, iom)
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

func readAiSummary(repoRoot string, engine model.EngineName, iom IOManager) (sums []*AiSummary, err error) {
	aiRepoMutex.Lock()
	defer aiRepoMutex.Unlock()

	_, _ = repoRoot, iom // will be used when this isn't mocked

	// TODO: Read the AI summary from the repoRoot
	switch engine {
	case model.EngineNameElastAlert:
		sums = []*AiSummary{
			{
				PublicId: "032f5fb3-d959-41a5-9263-4173c802dc2b",
				Reviewed: true,
				Summary:  `This rule detects Formbook process executions that inject code into files within the System32 folder and execute commands to delete the dropper from the AppData Temp folder. It specifically monitors for parent processes with command lines starting with System32 or SysWOW64 directories and ending with '.exe'. Furthermore, it looks for command lines containing specific parameters related to deletion activities within the user's AppData Temp and Desktop directories. This helps to distinguish malicious activity from legitimate actions by ensuring the parent command line parameters do not indicate normal operations.`,
			},
			{
				PublicId: "36e35854-a11d-408d-a918-9d0fe7567766",
				Reviewed: false,
				Summary:  "ElastAlert AI Rule Summary",
			},
		}
	case model.EngineNameSuricata:
		sums = []*AiSummary{
			{
				PublicId: "2015738",
				Reviewed: true,
				Summary:  "Suricata AI Rule Summary",
			},
			{
				PublicId: "2016190",
				Reviewed: false,
				Summary:  "Suricata AI Rule Summary",
			},
		}
	case model.EngineNameStrelka:
		sums = []*AiSummary{
			{
				PublicId: "Webshell_FOPO_Obfuscation_APT_ON_Nov17_1",
				Reviewed: true,
				Summary:  "Strelka AI Rule Summary",
			},
			{
				PublicId: "Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167",
				Reviewed: false,
				Summary:  "Strelka AI Rule Summary",
			},
		}
	}
	return sums, nil
}
