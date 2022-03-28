// Copyright 2022 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package analyze

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/agent"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
)

const DEFAULT_ANALYZERS_PATH = "/opt/sensoroni/analyzers"
const DEFAULT_ANALYZER_EXECUTABLE = "python3"
const DEFAULT_TIMEOUT_MS = 900000
const DEFAULT_PARALLEL_LIMIT = 5
const DEFAULT_SUMMARY_LENGTH = 50

type Analyze struct {
	config             module.ModuleConfig
	analyzersPath      string
	analyzerExecutable string
	agent              *agent.Agent
	timeoutMs          int
	analyzers          []*model.Analyzer
	parallelLimit      int
	summaryLength      int
}

func NewAnalyze(agt *agent.Agent) *Analyze {
	return &Analyze{
		agent: agt,
	}
}

func (analyze *Analyze) PrerequisiteModules() []string {
	return nil
}

func (analyze *Analyze) Init(cfg module.ModuleConfig) error {
	var err error
	analyze.config = cfg
	analyze.analyzersPath = strings.TrimSuffix(module.GetStringDefault(cfg, "analyzersPath", DEFAULT_ANALYZERS_PATH), "/")
	analyze.timeoutMs = module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
	analyze.parallelLimit = module.GetIntDefault(cfg, "parallelLimit", DEFAULT_PARALLEL_LIMIT)
	analyze.summaryLength = module.GetIntDefault(cfg, "summaryLength", DEFAULT_SUMMARY_LENGTH)
	analyze.analyzerExecutable = strings.TrimSuffix(module.GetStringDefault(cfg, "analyzerExecutable", DEFAULT_ANALYZER_EXECUTABLE), "/")
	if analyze.agent == nil {
		err = errors.New("Unable to invoke JobMgr.AddJobProcessor due to nil agent")
	} else {
		err = analyze.refreshAnalyzers()
		if err == nil {
			analyze.agent.JobMgr.AddJobProcessor(analyze)
		}
	}
	return err
}

func (analyze *Analyze) Start() error {
	return nil
}

func (analyze *Analyze) Stop() error {
	return nil
}

func (analyze *Analyze) IsRunning() bool {
	return false
}

func (analyze *Analyze) createAnalyzer(entry fs.FileInfo) *model.Analyzer {
	if entry.IsDir() || strings.HasSuffix(entry.Name(), ".py") {
		name := strings.TrimSuffix(entry.Name(), ".py")
		log.WithFields(log.Fields{
			"Id":      name,
			"Package": entry.IsDir(),
		}).Info("Added analyzer")
		return model.NewAnalyzer(name, entry.IsDir())
	}
	return nil
}

func (analyze *Analyze) refreshAnalyzers() error {
	entries, err := ioutil.ReadDir(analyze.analyzersPath)
	if err != nil {
		log.WithError(err).WithField("analyzersPath", analyze.analyzersPath).Error("Failed to read analyzers directory")
	} else {
		analyze.analyzers = nil
		for _, entry := range entries {
			analyzer := analyze.createAnalyzer(entry)
			if analyzer != nil {
				analyze.analyzers = append(analyze.analyzers, analyzer)
			}
		}
	}
	return err
}

func (analyze *Analyze) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	var err error
	if job.GetKind() != "analyze" {
		log.WithFields(log.Fields{
			"jobId": job.Id,
			"kind":  job.GetKind(),
		}).Debug("Skipping analyze processor due to unsupported job")
		return reader, nil
	}
	if len(job.Filter.Parameters) == 0 {
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).Debug("Skipping analyze processor due to missing parameters")
		return reader, nil
	} else {
		input := "{}"
		if val, ok := job.Filter.Parameters["artifact"]; ok {
			bytes, err := json.WriteJson(val)
			if err != nil {
				log.WithError(err).Error("Unable to convert artifact parameter to JSON string")
			} else {
				input = string(bytes)
			}
		}

		if err == nil {
			job.FileExtension = ""

			resultsLock := sync.Mutex{}
			var waitGroup sync.WaitGroup

			analyzers := analyze.filterAnalyzers(job)
			log.WithFields(log.Fields{
				"jobId":         job.Id,
				"parallelLimit": analyze.parallelLimit,
				"timeoutMs":     analyze.timeoutMs,
				"analyzers":     len(analyzers),
			}).Info("About to run analyzers for job")

			for idx, analyzer := range analyzers {

				waitGroup.Add(1)
				go func(analyzer *model.Analyzer) {
					defer waitGroup.Done()
					var output []byte

					output, err = analyze.startAnalyzer(job, analyzer, input)

					if err == nil {
						// parse into JSON to verify syntax is correct
						result := make(map[string]interface{})
						err = json.LoadJson(output, &result)
						if err == nil {
							resultsLock.Lock()
							defer resultsLock.Unlock()
							var summary string
							if value, ok := result["summary"]; ok {
								summary = value.(string)
							} else {
								summary = string(output)
							}
							if len(summary) > analyze.summaryLength {
								summary = summary[:analyze.summaryLength] + "..."
							}
							jobResult := model.NewJobResult(analyzer.Id, result, string(summary))
							job.Results = append(job.Results, jobResult)
						}
					}

				}(analyzer)

				// Limit parallel threads if needed
				if (idx+1)%analyze.parallelLimit == 0 {
					waitGroup.Wait()
				}
			}

			waitGroup.Wait()

			// sort the results
			sort.SliceStable(job.Results, func(i, j int) bool {
				return job.Results[i].Id < job.Results[j].Id
			})
		}
	}
	return reader, err
}

func (analyze *Analyze) filterAnalyzers(job *model.Job) []*model.Analyzer {
	return analyze.analyzers
}

func (analyze *Analyze) startAnalyzer(job *model.Job, analyzer *model.Analyzer, input string) ([]byte, error) {
	log.WithFields(log.Fields{
		"jobId":               job.Id,
		"analyzersPath":       analyze.analyzersPath,
		"analyzerInterpretor": analyze.analyzerExecutable,
		"analyzer":            analyzer.Id,
	}).Info("Executing python analyzer for job")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(analyze.timeoutMs)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, analyze.analyzerExecutable, "-m", analyzer.GetModule(), "-i", input)
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+analyze.analyzersPath,
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		log.WithFields(log.Fields{
			"analyzer": analyzer.Id,
			"input":    input,
			"output":   string(output),
			"err":      err,
		}).Debug("Executed analyzer")
	} else {
		log.WithFields(log.Fields{
			"analyzer": analyzer.Id,
			"input":    input,
			"output":   string(output),
			"err":      err,
		}).WithError(err).Error("Failed to execute analyzer")
	}

	return output, err
}

func (analyze *Analyze) CleanupJob(job *model.Job) {
}

func (analyze *Analyze) GetDataEpoch() time.Time {
	// Epoch not used for analyzer processor, return current time
	return time.Now()
}
