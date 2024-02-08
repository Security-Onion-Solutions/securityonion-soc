// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suriquery

import (
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/google/gopacket"
	"github.com/security-onion-solutions/securityonion-soc/agent"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/packet"
)

const DEFAULT_PCAP_INPUT_PATH = "/nsm/suripcap"
const DEFAULT_EPOCH_REFRESH_MS = 120000
const DEFAULT_DATA_LAG_MS = 120000
const DEFAULT_PCAP_MAX_COUNT = 999999

const SURI_PCAP_PREFIX = "so-pcap."

type SuriQuery struct {
	config           module.ModuleConfig
	pcapInputPath    string
	agent            *agent.Agent
	epochTimeTmp     time.Time
	epochTime        time.Time
	epochRefreshTime time.Time
	epochRefreshMs   int
	dataLagMs        int
	pcapMaxCount     int
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
	suri.pcapInputPath = module.GetStringDefault(cfg, "pcapInputPath", DEFAULT_PCAP_INPUT_PATH)
	suri.epochRefreshMs = module.GetIntDefault(cfg, "epochRefreshMs", DEFAULT_EPOCH_REFRESH_MS)
	suri.dataLagMs = module.GetIntDefault(cfg, "dataLagMs", DEFAULT_DATA_LAG_MS)
	suri.pcapMaxCount = module.GetIntDefault(cfg, "pcapMaxCount", DEFAULT_PCAP_MAX_COUNT)
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
			"jobId":   job.Id,
			"jobKind": job.GetKind(),
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
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).Debug("Starting to process new Suricata PCAP job")
		pcapFiles := suri.findFilesInTimeRange(job.Filter.BeginTime, job.Filter.EndTime)
		reader, err = suri.streamPacketsInPcaps(pcapFiles, job.Filter)
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("Finished processing PCAP")
	}
	return reader, err
}

func (suri *SuriQuery) CleanupJob(job *model.Job) {
	// Noop
}

func (suri *SuriQuery) streamPacketsInPcaps(paths []string, filter *model.Filter) (io.ReadCloser, error) {
	allPackets := make([]gopacket.Packet, 0, 0)

	for _, path := range paths {
		packets, perr := packet.ParseRawPcap(path, suri.pcapMaxCount, filter)
		if perr != nil {
			log.WithError(perr).WithField("pcapPath", path).Error("Failed to parse PCAP file")
		}
		if packets != nil && len(packets) > 0 {
			allPackets = append(allPackets, packets...)
		}
	}

	slices.SortFunc(allPackets, func(a, b gopacket.Packet) int {
		return a.Metadata().Timestamp.Compare(b.Metadata().Timestamp)
	})

	log.WithField("matchedCount", len(allPackets)).Debug("Finished filtering eligible packets")

	return packet.ToStream(allPackets)
}

func (suri *SuriQuery) getPcapCreateTime(filepath string) (time.Time, error) {
	var createTime time.Time
	var err error
	filename := path.Base(filepath)
	if !strings.HasPrefix(filename, SURI_PCAP_PREFIX) {
		err = errors.New("unsupported pcap file")
	} else {
		secondsStr := strings.TrimLeft(filename, SURI_PCAP_PREFIX)
		var seconds int64
		seconds, err = strconv.ParseInt(secondsStr, 10, 64)
		if err == nil {
			createTime = time.Unix(seconds, 0).UTC()
		}
	}
	return createTime, err
}

func (suri *SuriQuery) findFilesInTimeRange(start time.Time, stop time.Time) []string {
	eligibleFiles := make([]string, 0, 0)
	err := filepath.Walk(suri.pcapInputPath, func(filepath string, fileinfo os.FileInfo, err error) error {
		createTime, err := suri.getPcapCreateTime(filepath)
		if err != nil {
			log.WithField("pcapPath", filepath).WithError(err).Warn("PCAP file does not conform to expected format")
			return nil
		}
		modTime := fileinfo.ModTime()
		log.WithFields(log.Fields{
			"pcapPath":   filepath,
			"createTime": createTime,
			"modTime":    modTime,
		}).Debug("Reviewing eligibility for PCAP file")

		// file was created before the time range but has still open when time range started.
		if (createTime.Before(start) && modTime.After(start)) ||
			// file was created and finished in between time range start and stop times
			(createTime.After(start) && createTime.Before(modTime) && modTime.Before(stop)) ||
			// file was created before the end of the time range but was still being written to after the time range stop time
			(createTime.Before(stop) && modTime.After(stop)) {
			eligibleFiles = append(eligibleFiles, filepath)
		}
		return nil
	})
	if err != nil {
		log.WithError(err).WithField("pcapInputPath", suri.pcapInputPath).Error("Unable to access path while locating PCAP files in time range")
	}
	return eligibleFiles
}

func (suri *SuriQuery) GetDataEpoch() time.Time {
	now := time.Now()
	refreshDuration := time.Duration(suri.epochRefreshMs) * time.Millisecond
	if now.Sub(suri.epochRefreshTime) > refreshDuration {
		suri.epochTimeTmp = now
		err := filepath.Walk(suri.pcapInputPath, suri.updateEpochTimeTmp)
		if err != nil {
			log.WithError(err).WithField("pcapPath", suri.pcapInputPath)
		} else {
			suri.epochTime = suri.epochTimeTmp
		}
		suri.epochRefreshTime = now
	}
	return suri.epochTime
}

func (suri *SuriQuery) updateEpochTimeTmp(path string, info os.FileInfo, err error) error {
	if err != nil {
		log.WithError(err).WithField("pcapPath", path).Error("Unable to access path while updating epoch")
		return err
	}
	if !info.IsDir() && info.Size() > 0 {
		createTime, err := suri.getPcapCreateTime(path)
		if err != nil {
			return err
		}

		if createTime.Before(suri.epochTimeTmp) {
			suri.epochTimeTmp = createTime
		}
	}
	return nil
}
