// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package agent

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type JobManager struct {
	agent         *Agent
	node          *model.Node
	running       bool
	jobProcessors []JobProcessor
	lock          sync.RWMutex
	jobsLock      sync.Mutex
	inProcessJobs map[int]bool
}

func NewJobManager(agent *Agent) *JobManager {
	mgr := &JobManager{
		agent:         agent,
		node:          model.NewNode(agent.Config.NodeId),
		inProcessJobs: make(map[int]bool),
	}

	// Any field/value added to this list must be manually copied to the
	// existing node object in filedatastoreimpl.go::UpdateNode()
	mgr.node.Role = agent.Config.Role
	mgr.node.Description = agent.Config.Description
	mgr.node.Address = agent.Config.Address
	mgr.node.Version = agent.Version
	mgr.node.Model = agent.Config.Model
	mgr.node.MgmtMac = mgr.lookupMgmtMac(agent.Config.MgmtNic)

	return mgr
}

func (mgr *JobManager) lookupMgmtMac(nic string) string {
	filename := "/sys/class/net/" + nic + "/address"
	mac, err := os.ReadFile(filename)
	if err != nil {
		log.WithFields(log.Fields{
			"mgmtNic":     nic,
			"macFilename": filename,
		}).WithError(err).Error("Failed to open MAC address file for NIC")
		return "missing"
	}
	return strings.TrimSpace(string(mac))
}

func (mgr *JobManager) Start() {
	if mgr.inProcessJobs == nil {
		mgr.inProcessJobs = make(map[int]bool)
	}
	mgr.running = true
	mgr.updateOnlineTime("/nsm/pcapout")

	jobsChan := make(chan *model.Job)
	var wg sync.WaitGroup

	for i := 0; i < mgr.agent.Config.TaskPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				mgr.runJob(job)
			}
		}()
	}

	for mgr.running {
		mgr.updateDataEpoch()
		job, err := mgr.PollPendingJobs()
		if err != nil {
			log.WithError(err).Warn("Failed to poll for pending jobs")
			time.Sleep(time.Duration(mgr.agent.Config.PollIntervalMs) * time.Millisecond)
		} else if job == nil {
			log.Debug("No pending jobs available")
			time.Sleep(time.Duration(mgr.agent.Config.PollIntervalMs) * time.Millisecond)
		} else {
			mgr.jobsLock.Lock()
			inProcess := mgr.inProcessJobs[job.Id]
			if !inProcess {
				mgr.inProcessJobs[job.Id] = true
			}
			mgr.jobsLock.Unlock()

			if inProcess {
				log.WithField("jobId", job.Id).Debug("Job is already in progress, skipping")
				job = nil
				time.Sleep(time.Duration(mgr.agent.Config.PollIntervalMs) * time.Millisecond)
			} else {
				select {
				case jobsChan <- job:
				default:
					mgr.jobsLock.Lock()
					delete(mgr.inProcessJobs, job.Id)
					mgr.jobsLock.Unlock()
					log.WithField("jobId", job.Id).Debug("Workers are busy, discarding job")
					time.Sleep(time.Duration(mgr.agent.Config.PollIntervalMs) * time.Millisecond)
				}
			}
		}
	}
	close(jobsChan)
	wg.Wait()
}

func (mgr *JobManager) runJob(job *model.Job) {
	log.WithField("jobId", job.Id).Info("Discovered pending job")
	var reader io.ReadCloser

	reader, err := mgr.ProcessJob(job)
	if err == nil {
		if reader != nil {
			defer reader.Close()
			err = mgr.StreamJobResults(job, reader)
		} else {
			log.WithField("jobId", job.Id).Debug("Job completed without stream result")
		}
	}
	if err == nil {
		job.Complete()
	} else {
		log.WithError(err).WithField("jobId", job.Id).Error("Job failed")
		job.Fail(err)
	}
	mgr.CleanupJob(job)
	err = mgr.UpdateJob(job)
	if err != nil {
		log.WithError(err).WithField("jobId", job.Id).Error("Failed to update job")
	}

	mgr.jobsLock.Lock()
	delete(mgr.inProcessJobs, job.Id)
	mgr.jobsLock.Unlock()
}

func (mgr *JobManager) Stop() {
	mgr.running = false
}

func (mgr *JobManager) PollPendingJobs() (*model.Job, error) {
	job := model.NewJob()
	available, err := mgr.agent.Client.SendAuthorizedObject("POST", "/api/node", mgr.node, job)
	if !available {
		job = nil
	}
	return job, err
}

func (mgr *JobManager) ProcessJob(job *model.Job) (io.ReadCloser, error) {
	mgr.lock.RLock()
	defer mgr.lock.RUnlock()
	var reader io.ReadCloser

	job.Size = 0
	for _, processor := range mgr.jobProcessors {
		var err error
		reader, err = processor.ProcessJob(job, reader)
		if err != nil {
			if reader != nil {
				reader.Close()
			}
			return nil, err
		}
	}
	if reader == nil && len(job.Results) == 0 {
		return nil, errors.New("no job processor provided a result")
	}
	return reader, nil
}

func (mgr *JobManager) CleanupJob(job *model.Job) {
	for _, processor := range mgr.jobProcessors {
		processor.CleanupJob(job)
	}
}

func (mgr *JobManager) updateOnlineTime(src string) {
	cmd := exec.Command("stat", src, "-c", "%W")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithFields(log.Fields{"statSrcFile": src, "statOutput": out}).WithError(err).Error("unable to run stat against original dir")
		return
	}
	log.WithFields(log.Fields{
		"statSrcFile":  src,
		"statOutput":   out,
		"statExitCode": cmd.ProcessState.ExitCode(),
	}).Debug("ran stat against original dir")
	secondsSinceEpochStr := strings.TrimSpace(string(out))
	secondsSinceEpoch, parseerr := strconv.ParseInt(secondsSinceEpochStr, 10, 64)
	if parseerr != nil {
		log.WithField("statOutput", secondsSinceEpochStr).WithError(parseerr).Error("unable to convert stat output to number")
		return
	}
	mgr.node.OnlineTime = time.Unix(int64(secondsSinceEpoch), 0)
	log.WithField("onlineTime", mgr.node.OnlineTime).Info("Updated online time (node installation time)")
}

func (mgr *JobManager) updateDataEpoch() {
	epochHasBeenSet := false
	for _, processor := range mgr.jobProcessors {
		processorEpoch := processor.GetDataEpoch()
		if !epochHasBeenSet || mgr.node.EpochTime.After(processorEpoch) {
			mgr.node.EpochTime = processorEpoch
			epochHasBeenSet = true
		}
	}
}

func (mgr *JobManager) StreamJobResults(job *model.Job, reader io.ReadCloser) error {
	resp, err := mgr.agent.Client.SendAuthorizedRequest("POST", "/api/stream?jobId="+strconv.Itoa(job.Id), "application/octet-stream", reader)
	if resp.StatusCode != 200 {
		err = errors.New("Unable to submit job results (" + strconv.Itoa(resp.StatusCode) + "): " + resp.Status)
	}
	return err
}

func (mgr *JobManager) UpdateJob(job *model.Job) error {
	_, err := mgr.agent.Client.SendAuthorizedObject("PUT", "/api/job/", job, nil)
	return err
}

func (mgr *JobManager) AddJobProcessor(jobProcessor JobProcessor) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()
	mgr.jobProcessors = append(mgr.jobProcessors, jobProcessor)
}
