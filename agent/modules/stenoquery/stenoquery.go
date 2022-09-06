// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package stenoquery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/kennygrant/sanitize"
	"github.com/security-onion-solutions/securityonion-soc/agent"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
)

const DEFAULT_EXECUTABLE_PATH = "stenoread"
const DEFAULT_PCAP_OUTPUT_PATH = "/nsm/pcapout"
const DEFAULT_PCAP_INPUT_PATH = "/nsm/pcap"
const DEFAULT_EPOCH_REFRESH_MS = 120000
const DEFAULT_TIMEOUT_MS = 1200000
const DEFAULT_DATA_LAG_MS = 120000

type StenoQuery struct {
	config           module.ModuleConfig
	executablePath   string
	pcapOutputPath   string
	pcapInputPath    string
	agent            *agent.Agent
	epochTimeTmp     time.Time
	epochTime        time.Time
	epochRefreshTime time.Time
	epochRefreshMs   int
	timeoutMs        int
	dataLagMs        int
}

func NewStenoQuery(agt *agent.Agent) *StenoQuery {
	return &StenoQuery{
		agent: agt,
	}
}

func (lag *StenoQuery) PrerequisiteModules() []string {
	return nil
}

func (steno *StenoQuery) Init(cfg module.ModuleConfig) error {
	var err error
	steno.config = cfg
	steno.executablePath = module.GetStringDefault(cfg, "executablePath", DEFAULT_EXECUTABLE_PATH)
	steno.pcapOutputPath = module.GetStringDefault(cfg, "pcapOutputPath", DEFAULT_PCAP_OUTPUT_PATH)
	steno.pcapInputPath = module.GetStringDefault(cfg, "pcapInputPath", DEFAULT_PCAP_INPUT_PATH)
	steno.epochRefreshMs = module.GetIntDefault(cfg, "epochRefreshMs", DEFAULT_EPOCH_REFRESH_MS)
	steno.timeoutMs = module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
	steno.dataLagMs = module.GetIntDefault(cfg, "dataLagMs", DEFAULT_DATA_LAG_MS)
	if steno.agent == nil {
		err = errors.New("Unable to invoke JobMgr.AddJobProcessor due to nil agent")
	} else {
		steno.agent.JobMgr.AddJobProcessor(steno)
	}
	return err
}

func (steno *StenoQuery) Start() error {
	return nil
}

func (steno *StenoQuery) Stop() error {
	return nil
}

func (steno *StenoQuery) IsRunning() bool {
	return false
}

func (steno *StenoQuery) getDataLagDate() time.Time {
	return time.Now().Add(time.Duration(-steno.dataLagMs) * time.Millisecond)
}

func (steno *StenoQuery) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	var err error
	if job.GetKind() != "pcap" {
		log.WithFields(log.Fields{
			"jobId": job.Id,
			"kind":  job.GetKind(),
		}).Debug("Skipping steno processor due to unsupported job")
		return reader, nil
	}
	if len(job.Filter.ImportId) > 0 {
		log.WithFields(log.Fields{
			"jobId":    job.Id,
			"importId": job.Filter.ImportId,
		}).Debug("Skipping steno processor due to presence of importId")
		return reader, nil
	} else if job.Filter == nil || job.Filter.EndTime.Before(steno.GetDataEpoch()) || job.Filter.BeginTime.After(steno.getDataLagDate()) {
		log.WithFields(log.Fields{
			"jobId":                  job.Id,
			"availableDataBeginDate": steno.GetDataEpoch(),
			"availableDataEndDate":   steno.getDataLagDate(),
			"jobBeginDate":           job.Filter.BeginTime,
			"jobEndDate":             job.Filter.EndTime,
		}).Info("Skipping steno processor due to date range conflict")
		err = errors.New("No data available for the requested dates")
	} else {
		job.FileExtension = "pcap"

		query := steno.CreateQuery(job)

		pcapFilepath := fmt.Sprintf("%s/%d.%s", steno.pcapOutputPath, job.Id, job.FileExtension)

		log.WithField("jobId", job.Id).Info("Processing pcap export for job")

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(steno.timeoutMs)*time.Millisecond)
		defer cancel()
		cmd := exec.CommandContext(ctx, steno.executablePath, query, "-w", pcapFilepath)
		var output []byte
		output, err = cmd.CombinedOutput()
		log.WithFields(log.Fields{
			"executablePath": steno.executablePath,
			"query":          query,
			"output":         string(output),
			"pcapFilepath":   pcapFilepath,
			"err":            err,
		}).Debug("Executed stenoread")
		if err == nil {
			var file *os.File
			file, err = os.Open(pcapFilepath)
			if err == nil {
				reader = file
			}
		}
	}
	return reader, err
}

func (steno *StenoQuery) CleanupJob(job *model.Job) {
	pcapOutputFilepath := fmt.Sprintf("%s/%d.%s", steno.pcapOutputPath, job.Id, sanitize.Name(job.FileExtension))
	os.Remove(pcapOutputFilepath)
}

func (steno *StenoQuery) CreateQuery(job *model.Job) string {
	beginTime := job.Filter.BeginTime.Format(time.RFC3339)
	endTime := job.Filter.EndTime.Format(time.RFC3339)

	query := fmt.Sprintf("before %s and after %s", endTime, beginTime)

	if len(job.Filter.SrcIp) > 0 {
		query = fmt.Sprintf("%s and host %s", query, job.Filter.SrcIp)
	}

	if len(job.Filter.DstIp) > 0 {
		query = fmt.Sprintf("%s and host %s", query, job.Filter.DstIp)
	}

	if job.Filter.SrcPort > 0 {
		query = fmt.Sprintf("%s and port %d", query, job.Filter.SrcPort)
	}

	if job.Filter.DstPort > 0 {
		query = fmt.Sprintf("%s and port %d", query, job.Filter.DstPort)
	}

	return query
}

func (steno *StenoQuery) GetDataEpoch() time.Time {
	now := time.Now()
	refreshDuration := time.Duration(steno.epochRefreshMs) * time.Millisecond
	if now.Sub(steno.epochRefreshTime) > refreshDuration {
		steno.epochTimeTmp = now
		err := filepath.Walk(steno.pcapInputPath, steno.updateEpochTimeTmp)
		if err != nil {
			log.WithError(err).WithField("pcapInputPath", steno.pcapInputPath)
		} else {
			steno.epochTime = steno.epochTimeTmp
		}
		steno.epochRefreshTime = now
	}
	return steno.epochTime
}

func (steno *StenoQuery) updateEpochTimeTmp(path string, info os.FileInfo, err error) error {
	if err != nil {
		log.WithError(err).WithField("path", path).Error("Unable to access path while updating epoch")
		return err
	}
	if !info.IsDir() && info.Size() > 0 && info.ModTime().Before(steno.epochTimeTmp) {
		steno.epochTimeTmp = info.ModTime()
	}
	return nil
}
