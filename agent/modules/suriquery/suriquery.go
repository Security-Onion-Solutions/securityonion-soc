// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suriquery

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

const DEFAULT_EXECUTABLE_PATH = "suriquery.sh"
const DEFAULT_PCAP_OUTPUT_PATH = "/nsm/pcapout"
const DEFAULT_PCAP_INPUT_PATH = "/nsm/pcap"
const DEFAULT_EPOCH_REFRESH_MS = 120000
const DEFAULT_TIMEOUT_MS = 1200000
const DEFAULT_DATA_LAG_MS = 120000

type SuriQuery struct {
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

func NewSuriQuery(agt *agent.Agent) *SuriQuery {
	return &SuriQuery{
		agent: agt,
	}
}

func (lag *SuriQuery) PrerequisiteModules() []string {
	return nil
}

func (suri *SuriQuery) Init(cfg module.ModuleConfig) error {
	var err error
	suri.config = cfg
	suri.executablePath = module.GetStringDefault(cfg, "executablePath", DEFAULT_EXECUTABLE_PATH)
	suri.pcapOutputPath = module.GetStringDefault(cfg, "pcapOutputPath", DEFAULT_PCAP_OUTPUT_PATH)
	suri.pcapInputPath = module.GetStringDefault(cfg, "pcapInputPath", DEFAULT_PCAP_INPUT_PATH)
	suri.epochRefreshMs = module.GetIntDefault(cfg, "epochRefreshMs", DEFAULT_EPOCH_REFRESH_MS)
	suri.timeoutMs = module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
	suri.dataLagMs = module.GetIntDefault(cfg, "dataLagMs", DEFAULT_DATA_LAG_MS)
	if suri.agent == nil {
		err = errors.New("Unable to invoke JobMgr.AddJobProcessor due to nil agent")
	} else {
		suri.agent.JobMgr.AddJobProcessor(suri)
	}
	return err
}

func (suri *SuriQuery) Start() error {
	return nil
}

func (suri *SuriQuery) Stop() error {
	return nil
}

func (suri *SuriQuery) IsRunning() bool {
	return false
}

func (suri *SuriQuery) getDataLagDate() time.Time {
	return time.Now().Add(time.Duration(-suri.dataLagMs) * time.Millisecond)
}

func (suri *SuriQuery) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	var err error
	if job.GetKind() != "pcap" {
		log.WithFields(log.Fields{
			"jobId": job.Id,
			"kind":  job.GetKind(),
		}).Debug("Skipping suri processor due to unsupported job")
		return reader, nil
	}
	if len(job.Filter.ImportId) > 0 {
		log.WithFields(log.Fields{
			"jobId":    job.Id,
			"importId": job.Filter.ImportId,
		}).Debug("Skipping suri processor due to presence of importId")
		return reader, nil
	} else if job.Filter == nil || job.Filter.EndTime.Before(suri.GetDataEpoch()) || job.Filter.BeginTime.After(suri.getDataLagDate()) {
		log.WithFields(log.Fields{
			"jobId":                  job.Id,
			"availableDataBeginDate": suri.GetDataEpoch(),
			"availableDataEndDate":   suri.getDataLagDate(),
			"jobBeginDate":           job.Filter.BeginTime,
			"jobEndDate":             job.Filter.EndTime,
		}).Info("Skipping suri processor due to date range conflict")
		err = errors.New("No data available for the requested dates")
	} else {
		job.FileExtension = "pcap"

		query := suri.CreateQuery(job)

		pcapFilepath := fmt.Sprintf("%s/%d.%s", suri.pcapOutputPath, job.Id, job.FileExtension)

		log.WithField("jobId", job.Id).Info("Processing pcap export for job")

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(suri.timeoutMs)*time.Millisecond)
		defer cancel()
		beginTime := job.Filter.BeginTime.Format(time.RFC3339)
		endTime := job.Filter.EndTime.Format(time.RFC3339)

		cmd := exec.CommandContext(ctx, suri.executablePath, pcapFilepath, beginTime, endTime, query)
		var output []byte
		output, err = cmd.CombinedOutput()
		log.WithFields(log.Fields{
			"executablePath": suri.executablePath,
			"query":          query,
			"output":         string(output),
			"pcapFilepath":   pcapFilepath,
			"err":            err,
		}).Debug("Executed suriread")
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

func (suri *SuriQuery) CleanupJob(job *model.Job) {
	pcapOutputFilepath := fmt.Sprintf("%s/%d.%s", suri.pcapOutputPath, job.Id, sanitize.Name(job.FileExtension))
	os.Remove(pcapOutputFilepath)
}

func (suri *SuriQuery) CreateQuery(job *model.Job) string {

	query := ""

	if len(job.Filter.SrcIp) > 0 {
		if len(query) > 0 {
			query = query + " and "
		}
		query = query + fmt.Sprintf("host %s", job.Filter.SrcIp)
	}

	if len(job.Filter.DstIp) > 0 {
		if len(query) > 0 {
			query = query + " and "
		}
		query = query + fmt.Sprintf("host %s", job.Filter.DstIp)
	}

	if job.Filter.SrcPort > 0 {
		if len(query) > 0 {
			query = query + " and "
		}
		query = query + fmt.Sprintf("port %d", job.Filter.SrcPort)
	}

	if job.Filter.DstPort > 0 {
		if len(query) > 0 {
			query = query + " and "
		}
		query = query + fmt.Sprintf("port %d", job.Filter.DstPort)
	}

	return query
}

func (suri *SuriQuery) GetDataEpoch() time.Time {
	now := time.Now()
	refreshDuration := time.Duration(suri.epochRefreshMs) * time.Millisecond
	if now.Sub(suri.epochRefreshTime) > refreshDuration {
		suri.epochTimeTmp = now
		err := filepath.Walk(suri.pcapInputPath, suri.updateEpochTimeTmp)
		if err != nil {
			log.WithError(err).WithField("pcapInputPath", suri.pcapInputPath)
		} else {
			suri.epochTime = suri.epochTimeTmp
		}
		suri.epochRefreshTime = now
	}
	return suri.epochTime
}

func (suri *SuriQuery) updateEpochTimeTmp(path string, info os.FileInfo, err error) error {
	if err != nil {
		log.WithError(err).WithField("path", path).Error("Unable to access path while updating epoch")
		return err
	}
	if !info.IsDir() && info.Size() > 0 && info.ModTime().Before(suri.epochTimeTmp) {
		suri.epochTimeTmp = info.ModTime()
	}
	return nil
}
