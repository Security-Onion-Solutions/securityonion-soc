// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package filedatastore

import (
  "context"
  "errors"
  "fmt"
  "github.com/apex/log"
  "github.com/kennygrant/sanitize"
  "github.com/security-onion-solutions/securityonion-soc/json"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/packet"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "io"
  "os"
  "path/filepath"
  "strings"
  "sync"
  "time"
)

const DEFAULT_RETRY_FAILURE_INTERVAL_MS = 600000

type FileDatastoreImpl struct {
  server                 *server.Server
  jobDir                 string
  retryFailureIntervalMs int
  jobsByNodeId           map[string][]*model.Job
  jobsById               map[int]*model.Job
  nodesById              map[string]*model.Node
  ready                  bool
  nextJobId              int
  lock                   sync.RWMutex
}

func NewFileDatastoreImpl(srv *server.Server) *FileDatastoreImpl {
  return &FileDatastoreImpl{
    server:       srv,
    jobsByNodeId: make(map[string][]*model.Job),
    jobsById:     make(map[int]*model.Job),
    nodesById:    make(map[string]*model.Node),
    lock:         sync.RWMutex{},
  }
}

func (datastore *FileDatastoreImpl) Init(cfg module.ModuleConfig) error {
  var err error
  if err == nil {
    datastore.jobDir, err = module.GetString(cfg, "jobDir")
  }
  if err == nil {
    datastore.retryFailureIntervalMs = module.GetIntDefault(cfg, "retryFailureIntervalMs", DEFAULT_RETRY_FAILURE_INTERVAL_MS)
  }
  return datastore.loadJobs()
}

func (datastore *FileDatastoreImpl) CreateNode(ctx context.Context, id string) *model.Node {
  var node *model.Node
  node = model.NewNode(id)
  return node
}

func (datastore *FileDatastoreImpl) GetNodes(ctx context.Context) []*model.Node {
  allNodes := make([]*model.Node, 0)
  if err := datastore.server.CheckAuthorized(ctx, "read", "nodes"); err == nil {
    datastore.lock.RLock()
    defer datastore.lock.RUnlock()
    for _, node := range datastore.nodesById {
      allNodes = append(allNodes, node)
    }
  }
  return allNodes
}

func (datastore *FileDatastoreImpl) AddNode(ctx context.Context, node *model.Node) error {
  _, err := datastore.UpdateNode(ctx, node)
  return err
}

func (datastore *FileDatastoreImpl) addNode(node *model.Node) *model.Node {
  datastore.nodesById[node.Id] = node
  log.WithFields(log.Fields{
    "id":          node.Id,
    "description": node.Description,
  }).Debug("Added node")
  return node
}

func (datastore *FileDatastoreImpl) UpdateNode(ctx context.Context, newNode *model.Node) (*model.Node, error) {
  var node *model.Node
  var err error
  if len(newNode.Id) > 0 {
    if err = datastore.server.CheckAuthorized(ctx, "write", "nodes"); err == nil {
      datastore.lock.Lock()
      defer datastore.lock.Unlock()
      node = datastore.nodesById[newNode.Id]
      if node == nil {
        node = datastore.addNode(newNode)
      }

      // Only copy the following values from the incoming node. Preserve everything else.
      node.EpochTime = newNode.EpochTime
      node.Role = newNode.Role
      node.Description = newNode.Description
      node.Address = newNode.Address
      node.Version = newNode.Version

      // Ensure model parameters are updated
      node.SetModel(newNode.Model)

      // Mark ConnectionStatus as Ok since this node just checked in
      node.ConnectionStatus = model.NodeStatusOk

      // Update time is now
      node.UpdateTime = time.Now()

      // Calculate uptime
      node.UptimeSeconds = int(node.UpdateTime.Sub(node.OnlineTime).Seconds())
    }
  } else {
    log.WithFields(log.Fields{
      "description": newNode.Description,
      "requestId":   ctx.Value(web.ContextKeyRequestId),
    }).Info("Not adding node with missing id")
  }
  return node, err
}

func (datastore *FileDatastoreImpl) GetNextJob(ctx context.Context, nodeId string) *model.Job {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  var nextJob *model.Job

  if err := datastore.server.CheckAuthorized(ctx, "process", "jobs"); err == nil {
    now := time.Now()
    jobs := datastore.jobsByNodeId[strings.ToLower(nodeId)]
    for _, job := range jobs {
      retryTime := job.FailTime.Add(time.Millisecond * time.Duration(datastore.retryFailureIntervalMs))
      if job.Status != model.JobStatusCompleted &&
        (nextJob == nil || job.CreateTime.Before(nextJob.CreateTime)) &&
        (job.Status != model.JobStatusIncomplete || retryTime.Before(now)) {
        nextJob = job
      }
    }
  }
  return nextJob
}

func (datastore *FileDatastoreImpl) CreateJob(ctx context.Context) *model.Job {
  datastore.lock.Lock()
  defer datastore.lock.Unlock()
  job := model.NewJob()
  job.Id = datastore.nextJobId
  datastore.incrementJobId(job.Id)
  log.WithFields(log.Fields{
    "id":        job.Id,
    "nextJobId": datastore.nextJobId,
  }).Debug("Created job")

  return job
}

func (datastore *FileDatastoreImpl) jobIsAllowed(ctx context.Context, job *model.Job, op string) bool {
  allowed := false

  if job != nil {
    if err := datastore.server.CheckAuthorized(ctx, op, "jobs"); err == nil {
      // User can operate on all jobs
      allowed = true
    } else {
      // User is only authorized against their own jobs.
      if user, ok := ctx.Value(web.ContextKeyRequestor).(*model.User); ok {
        if job.UserId == user.Id {
          allowed = true
        }
      }
    }
  }
  return allowed
}

func (datastore *FileDatastoreImpl) GetJob(ctx context.Context, jobId int) *model.Job {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  job := datastore.getJobById(jobId)
  if job != nil {
    if !datastore.jobIsAllowed(ctx, job, "read") {
      // Do not return jobs that are not allowed to be viewed by this user.
      job = nil
    }
  }

  return job
}

func (datastore *FileDatastoreImpl) filterParameterMatches(parameters map[string]interface{}, jobParams map[string]interface{}) bool {
  if len(parameters) > 0 {
    for key, value := range parameters {
      if jobValue, ok := jobParams[key]; ok {
        if nested, ok := value.(map[string]interface{}); ok {
          if jobNested, ok := jobValue.(map[string]interface{}); ok {
            // this nested input filter param also exists in the job filter params
            subresult := datastore.filterParameterMatches(nested, jobNested)
            if !subresult {
              return false // nested map failed to match
            }
          } else {
            return false // equivalent input job param is not also a map, therefore it can't possibly match
          }
        } else if value != jobValue {
          return false // input filter param is not a map so check for simple equivalency
        }
        // Making it this far indicates the values matched, including if they were nested maps
      } else {
        return false // filter param doesn't exist in job
      }
    }
    return true // all params matched
  }
  return true // no parameters specified, so all jobs will match
}

func (datastore *FileDatastoreImpl) GetJobs(ctx context.Context, kind string, parameters map[string]interface{}) []*model.Job {
  if kind == "" {
    kind = model.DEFAULT_JOB_KIND
  }

  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  allJobs := make([]*model.Job, 0)
  for _, job := range datastore.jobsById {
    if datastore.jobIsAllowed(ctx, job, "read") {
      if job.GetKind() == kind && datastore.filterParameterMatches(parameters, job.Filter.Parameters) {
        allJobs = append(allJobs, job)
      }
    }
  }
  return allJobs
}

func (datastore *FileDatastoreImpl) AddJob(ctx context.Context, job *model.Job) error {
  var err error
  if err = datastore.server.CheckAuthorized(ctx, "write", "jobs"); err == nil {
    if err == nil {
      err = datastore.addAndSaveJob(ctx, job)
    }
  }
  return err
}

func (datastore *FileDatastoreImpl) AddPivotJob(ctx context.Context, job *model.Job) error {
  var err error
  if err = datastore.server.CheckAuthorized(ctx, "pivot", "jobs"); err == nil {
    err = datastore.addAndSaveJob(ctx, job)
  }
  return err
}

func (datastore *FileDatastoreImpl) addAndSaveJob(ctx context.Context, job *model.Job) error {
  var err error
  if user, ok := ctx.Value(web.ContextKeyRequestor).(*model.User); ok {
    job.UserId = user.Id
  } else {
    err = errors.New("User not found in context")
  }
  datastore.lock.Lock()
  defer datastore.lock.Unlock()
  err = datastore.addJob(job)
  if err == nil {
    err = datastore.saveJob(job)
  }
  return err
}

func (datastore *FileDatastoreImpl) UpdateJob(ctx context.Context, job *model.Job) error {
  var err error
  if err = datastore.server.CheckAuthorized(ctx, "process", "jobs"); err == nil {
    existingJob := datastore.getJobById(job.Id)
    if existingJob != nil {
      job.UserId = existingJob.UserId // Prevent users from altering the creating user
      job.NodeId = existingJob.NodeId // Do not allow moving a job between nodes due to data file path
      if existingJob.CanProcess() {
        datastore.lock.Lock()
        defer datastore.lock.Unlock()
        datastore.deleteJob(existingJob)
        err = datastore.addJob(job)
        if err == nil {
          err = datastore.saveJob(job)
        }
      } else {
        err = errors.New("Job is ineligible for processing")
      }
    } else {
      err = errors.New("Job not found")
    }
  }

  return err
}

func (datastore *FileDatastoreImpl) getJobById(jobId int) *model.Job {
  return datastore.jobsById[jobId]
}

func (datastore *FileDatastoreImpl) DeleteJob(ctx context.Context, jobId int) (*model.Job, error) {
  var err error
  job := datastore.getJobById(jobId)
  if job != nil {
    if datastore.jobIsAllowed(ctx, job, "delete") {
      datastore.lock.Lock()
      defer datastore.lock.Unlock()
      datastore.deleteJob(job)
      job.Status = model.JobStatusDeleted
      filename := fmt.Sprintf("%d.json", job.Id)
      folder := filepath.Join(datastore.jobDir, sanitize.Name(job.GetNodeId()))
      err = os.Remove(filepath.Join(folder, filename))
      if err == nil {
        filename = fmt.Sprintf("%d.bin", job.Id)
        os.Remove(filepath.Join(folder, filename))
        filename = fmt.Sprintf("%d.bin.unwrapped", job.Id)
        os.Remove(filepath.Join(folder, filename))

        log.WithFields(log.Fields{
          "id":       job.Id,
          "folder":   folder,
          "filename": filename,
        }).Info("Permanently deleted job and job files")
      }
    } else {
      err = errors.New("Permission denied attempting to delete job")
    }
  } else {
    err = errors.New("Job not found")
  }
  return job, err
}

func (datastore *FileDatastoreImpl) deleteJob(job *model.Job) {
  jobs := datastore.jobsByNodeId[job.GetNodeId()]
  newJobs := make([]*model.Job, 0)
  for _, currentJob := range jobs {
    if currentJob.Id != job.Id {
      newJobs = append(newJobs, currentJob)
    }
  }
  datastore.jobsByNodeId[job.GetNodeId()] = newJobs
  delete(datastore.jobsById, job.Id)
  log.WithFields(log.Fields{
    "id":   job.Id,
    "node": job.GetNodeId(),
  }).Debug("Deleted job from list")
}

func (datastore *FileDatastoreImpl) addJob(job *model.Job) error {
  var err error
  existingJob := datastore.getJobById(job.Id)
  if existingJob != nil {
    err = errors.New("Job already exists")
  } else {
    jobs := datastore.jobsByNodeId[job.GetNodeId()]
    if jobs == nil {
      jobs = make([]*model.Job, 0)
    }
    datastore.jobsByNodeId[job.GetNodeId()] = append(jobs, job)
    datastore.jobsById[job.Id] = job
    datastore.incrementJobId(job.Id)
    log.WithFields(log.Fields{
      "id":   job.Id,
      "node": job.GetNodeId(),
    }).Debug("Added job")
  }
  return err
}

func (datastore *FileDatastoreImpl) incrementJobId(id int) {
  if id >= datastore.nextJobId {
    datastore.nextJobId = id + 1
  }
}

func (datastore *FileDatastoreImpl) saveJob(job *model.Job) error {
  filename := fmt.Sprintf("%d.json", job.Id)
  folder := filepath.Join(datastore.jobDir, sanitize.Name(job.GetNodeId()))
  log.WithFields(log.Fields{
    "id":       job.Id,
    "folder":   folder,
    "filename": filename,
  }).Debug("Saving job file")
  os.MkdirAll(folder, os.ModePerm)
  return json.WriteJsonFile(filepath.Join(folder, filename), job)
}

func (datastore *FileDatastoreImpl) loadJobs() error {
  datastore.lock.Lock()
  defer datastore.lock.Unlock()
  datastore.nextJobId = 1001
  files := make([]string, 0)
  err := filepath.Walk(datastore.jobDir, func(path string, info os.FileInfo, err error) error {
    if err == nil && strings.HasSuffix(info.Name(), ".json") {
      files = append(files, path)
    }
    return err
  })
  if err == nil {
    for _, file := range files {
      job := model.NewJob()
      err = json.LoadJsonFile(file, job)
      if err == nil {
        datastore.addJob(job)
      } else {
        log.WithError(err).WithField("file", file).Error("Unable to load job file")
      }
    }
  }
  return err
}

func (datastore *FileDatastoreImpl) GetPackets(ctx context.Context, jobId int, offset int, count int, unwrap bool) ([]*model.Packet, error) {
  var packets []*model.Packet
  var err error
  job := datastore.GetJob(ctx, jobId)
  if job != nil {
    if datastore.jobIsAllowed(ctx, job, "read") {
      if job.Status == model.JobStatusCompleted {
        packets, err = packet.ParsePcap(datastore.getStreamFilename(job), offset, count, unwrap)
        if err != nil {
          log.WithError(err).WithField("jobId", job.Id).Warn("Failed to parse captured packets")
          err = nil
        }
      }
    } else {
      err = errors.New("Job is inaccessible")
    }
  } else {
    err = errors.New("Job not found")
  }

  return packets, err
}

func (datastore *FileDatastoreImpl) SavePacketStream(ctx context.Context, jobId int, reader io.ReadCloser) error {
  var err error
  if err = datastore.server.CheckAuthorized(ctx, "process", "jobs"); err == nil {
    job := datastore.getJobById(jobId)
    if job != nil {
      if job.CanProcess() {
        var count int64
        file, err := os.Create(datastore.getStreamFilename(job))
        if err == nil {
          defer file.Close()
          count, err = io.Copy(file, reader)
        }
        if err != nil {
          log.WithError(err).WithField("jobId", jobId).Error("Failed to write packet stream to file")
        } else {
          log.WithFields(log.Fields{
            "bytes": count,
            "jobId": jobId,
          }).Info("Saved packet stream to file")
        }
      } else {
        err = errors.New("Job is ineligible for processing")
      }
    } else {
      err = errors.New("Job not found")
    }
  }
  return err
}

func (datastore *FileDatastoreImpl) GetPacketStream(ctx context.Context, jobId int, unwrap bool) (io.ReadCloser, string, int64, error) {
  var reader io.ReadCloser
  var filename string
  var length int64
  var err error
  job := datastore.GetJob(ctx, jobId)
  if job != nil {
    if datastore.jobIsAllowed(ctx, job, "read") {
      if job.Status == model.JobStatusCompleted {
        filename = fmt.Sprintf("sensoroni_%s_%d.%s", sanitize.Name(job.GetNodeId()), job.Id, sanitize.Name(job.FileExtension))
        var file *os.File
        file, err = os.Open(datastore.getModifiedStreamFilename(job, unwrap))
        if err != nil {
          log.WithError(err).WithField("jobId", job.Id).Error("Failed to open packet stream")
        } else {
          reader = file
          info, err := file.Stat()
          length = info.Size()
          log.WithFields(log.Fields{
            "size": length,
            "name": info.Name(),
          }).Info("Streaming file")
          if err != nil {
            log.WithError(err).WithField("jobId", job.Id).Error("Failed to open file stats")
          }
        }
      }
    } else {
      err = errors.New("Job is inaccessible")
    }
  } else {
    err = errors.New("Job not found")
  }

  return reader, filename, length, err
}

func (datastore *FileDatastoreImpl) getStreamFilename(job *model.Job) string {
  filename := fmt.Sprintf("%d.bin", job.Id)
  folder := filepath.Join(datastore.jobDir, sanitize.Name(job.GetNodeId()))
  return filepath.Join(folder, filename)
}

func (datastore *FileDatastoreImpl) getModifiedStreamFilename(job *model.Job, unwrap bool) string {
  filename := datastore.getStreamFilename(job)
  if unwrap {
    unwrappedFilename := filename + ".unwrapped"
    unwrapped := packet.UnwrapPcap(filename, unwrappedFilename)
    if unwrapped {
      filename = unwrappedFilename
    }
  }
  return filename
}
