package elastalert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/go-git/go-git/v5"
	_ "github.com/go-git/go-git/v5"
)

type ElastAlertEngine struct {
	srv                                  *server.Server
	communityRulesImportFrequencySeconds int
	sigmaRepo                            string
	sigmaRepoRoot                        string
	gitTimeout                           int
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
	e.sigmaRepoRoot = module.GetStringDefault(config, "sigmaRepoRoot", "/opt/so/rules/sigma")
	e.gitTimeout = module.GetIntDefault(config, "gitTimeout", 600)

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

		err := e.ensureUpToDateRepo(ctx)
		if err != nil {
			log.WithField("error", err).Error("something went wrong while ensuring the sigma repo is up to date")
			continue
		}
	}
}

func (e *ElastAlertEngine) ensureUpToDateRepo(ctx context.Context) error {
	readme := filepath.Join(e.sigmaRepoRoot, "README.md")

	gitCtx, cancel := context.WithTimeout(ctx, time.Duration(e.gitTimeout)*time.Second)
	defer cancel()

	_, err := os.Stat(readme)
	if os.IsNotExist(err) {
		err = os.MkdirAll(e.sigmaRepoRoot, 0755)
		if err != nil {
			return fmt.Errorf("unable to create repo root directory: %w", err)
		}

		_, err = git.PlainCloneContext(gitCtx, e.sigmaRepoRoot, false, &git.CloneOptions{
			URL:   e.sigmaRepo,
			Depth: 1,
		})
		if err != nil {
			return fmt.Errorf("unable to clone repo: %w", err)
		}
	} else if err == nil {
		repo, err := git.PlainOpen(e.sigmaRepoRoot)
		if err != nil {
			return fmt.Errorf("unable to open existing repo: %w", err)
		}

		w, err := repo.Worktree()
		if err != nil {
			return fmt.Errorf("unable to get worktree of existing repo: %w", err)
		}

		err = w.PullContext(gitCtx, &git.PullOptions{
			Depth: 1,
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("unable to pull repo: %w", err)
		}
	} else {
		return fmt.Errorf("unable to determine if README.md exists: %w", err)
	}

	return nil
}
