// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package agent

import (
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "io"
  "strconv"
  "sync"
  "time"
)

type JobManager struct {
  agent         *Agent
  node          *model.Node
  running       bool
  jobProcessors []JobProcessor
  lock          sync.RWMutex
}

func NewJobManager(agent *Agent) *JobManager {
  mgr := &JobManager{
    agent: agent,
    node:  model.NewNode(agent.Config.NodeId),
  }

  // Any field/value added to this list must be manually copied to the
  // existing node object in filedatastoreimpl.go::UpdateNode()
  mgr.node.Role = agent.Config.Role
  mgr.node.Description = agent.Config.Description
  mgr.node.Address = agent.Config.Address
  mgr.node.Version = agent.Version
  mgr.node.Model = agent.Config.Model

  return mgr
}

func (mgr *JobManager) Start() {
  mgr.running = true
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
      log.WithField("jobId", job.Id).Info("Discovered pending job")
      var reader io.ReadCloser
      reader, err = mgr.ProcessJob(job)
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
        job.Fail(err)
      }
      mgr.CleanupJob(job)
      err = mgr.UpdateJob(job)
      if err != nil {
        log.WithError(err).WithField("jobId", job.Id).Error("Failed to update job")
        time.Sleep(time.Duration(mgr.agent.Config.PollIntervalMs) * time.Millisecond)
      }
    }
  }
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
  var err error
  for _, processor := range mgr.jobProcessors {
    reader, err = processor.ProcessJob(job, reader)
    if err != nil {
      log.WithError(err).WithFields(log.Fields{
        "jobId": job.Id,
      }).Error("Failed to process job; job processing aborted")
      break
    }
  }
  return reader, err
}

func (mgr *JobManager) CleanupJob(job *model.Job) {
  for _, processor := range mgr.jobProcessors {
    processor.CleanupJob(job)
  }
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
