// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package filedatastore

import (
  "errors"
  "fmt"
  "io"
  "os"
  "path/filepath"
  "strings"
  "sync"
  "time"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/json"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/packet"
  "github.com/kennygrant/sanitize"
)

const DEFAULT_RETRY_FAILURE_INTERVAL_MS = 600000

type FileDatastoreImpl struct {
  jobDir                  string
  retryFailureIntervalMs  int
  jobsByNodeId            map[string][]*model.Job
  jobsById                map[int]*model.Job
  nodesById               map[string]*model.Node
  ready                   bool
  nextJobId               int
  lock                    sync.RWMutex
}

func NewFileDatastoreImpl() *FileDatastoreImpl {
  return &FileDatastoreImpl {
    jobsByNodeId: make(map[string][]*model.Job),
    jobsById: make(map[int]*model.Job),
    nodesById: make(map[string]*model.Node),
    lock: sync.RWMutex{},
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

func (datastore *FileDatastoreImpl) CreateNode(id string) *model.Node {
  node := model.NewNode(id)
  return node
}

func (datastore *FileDatastoreImpl) GetNodes() []*model.Node {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  allNodes := make([]*model.Node, 0)
  for _, node := range datastore.nodesById {
    allNodes = append(allNodes, node)
  }
  return allNodes
}

func (datastore *FileDatastoreImpl) AddNode(node *model.Node) error {
  _, err := datastore.UpdateNode(node)
  return err
}

func (datastore *FileDatastoreImpl) addNode(node *model.Node) *model.Node {
  datastore.nodesById[node.Id] = node
  log.WithFields(log.Fields {
    "id": node.Id,
    "description": node.Description,
  }).Debug("Added node")
  return node
}

func (datastore *FileDatastoreImpl) UpdateNode(newNode *model.Node) (*model.Node, error) {
  var node *model.Node

  if len(newNode.Id) > 0 {
    datastore.lock.Lock()
    defer datastore.lock.Unlock()
    node = datastore.nodesById[newNode.Id]
    if node == nil {
      node = datastore.addNode(newNode)
    }

    // Only copy the following values from the incoming node. Preserve everything else.
    node.EpochTime     = newNode.EpochTime
    node.Role          = newNode.Role
    node.Description   = newNode.Description
    node.Address       = newNode.Address
    node.Version       = newNode.Version

    // Ensure model parameters are updated
    node.SetModel(newNode.Model)
    
    // Mark ConnectionStatus as Ok since this node just checked in
    node.ConnectionStatus = model.NodeStatusOk

    // Update time is now
    node.UpdateTime = time.Now()

    // Calculate uptime
    node.UptimeSeconds = int(node.UpdateTime.Sub(node.OnlineTime).Seconds())
  } else {
    log.WithField("description", newNode.Description).Info("Not adding node with missing id")
  }
  return node, nil
} 

func (datastore *FileDatastoreImpl) GetNextJob(nodeId string) *model.Job {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  var nextJob *model.Job
  now := time.Now()
  jobs := datastore.jobsByNodeId[nodeId]
  for _, job := range jobs {
    retryTime := job.FailTime.Add(time.Millisecond * time.Duration(datastore.retryFailureIntervalMs))
    if job.Status != model.JobStatusCompleted && 
       (nextJob == nil || job.CreateTime.Before(nextJob.CreateTime)) && 
       (job.Status != model.JobStatusIncomplete || retryTime.Before(now)) {
      nextJob = job
    }
  }
  return nextJob
}

func (datastore *FileDatastoreImpl) CreateJob() *model.Job {
  datastore.lock.Lock()
  defer datastore.lock.Unlock()
  job := model.NewJob()
  job.Id = datastore.nextJobId
  datastore.incrementJobId(job.Id)
  log.WithFields(log.Fields {
    "id": job.Id,
    "nextJobId": datastore.nextJobId,
  }).Debug("Created job")

  return job
}

func (datastore *FileDatastoreImpl) GetJob(jobId int) *model.Job {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  return datastore.getJobById(jobId)
}

func (datastore *FileDatastoreImpl) GetJobs() []*model.Job {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  allJobs := make([]*model.Job, 0)
  for _, job := range datastore.jobsById {
    allJobs = append(allJobs, job)
  }
  return allJobs
}

func (datastore *FileDatastoreImpl) AddJob(job *model.Job) error {
  datastore.lock.Lock()
  defer datastore.lock.Unlock()
  err := datastore.addJob(job)
  if err == nil {
    err = datastore.saveJob(job)
  }
  return err
}

func (datastore *FileDatastoreImpl) UpdateJob(job *model.Job) error {
  datastore.lock.Lock()
  defer datastore.lock.Unlock()
  err := datastore.deleteJob(job)
  if err == nil {
    err = datastore.addJob(job)
    if err == nil {
      err = datastore.saveJob(job)
    }
  }
  return err
}

func (datastore *FileDatastoreImpl) getJobById(jobId int) *model.Job {
  return datastore.jobsById[jobId]
}

func (datastore *FileDatastoreImpl) DeleteJob(job *model.Job) error {
  err := datastore.deleteJob(job)
  if err == nil {
    job.Status = model.JobStatusDeleted
    filename := fmt.Sprintf("%d.json", job.Id)
    folder := filepath.Join(datastore.jobDir, sanitize.Name(job.NodeId))
    err = os.Remove(filepath.Join(folder, filename))
    if err == nil {
      filename = fmt.Sprintf("%d.bin", job.Id)
      os.Remove(filepath.Join(folder, filename))
      filename = fmt.Sprintf("%d.bin.unwrapped", job.Id)
      os.Remove(filepath.Join(folder, filename))

      log.WithFields(log.Fields {
        "id": job.Id,
        "folder": folder,
        "filename": filename,
      }).Info("Permanently deleted job and job files")
    }
  }
  return err
}

func (datastore *FileDatastoreImpl) deleteJob(job *model.Job) error {
  var err error
  existingJob := datastore.getJobById(job.Id)
  if existingJob == nil {
    err = errors.New("Job does not exist")
  } else {
    jobs := datastore.jobsByNodeId[job.NodeId]
    newJobs := make([]*model.Job, 0)
    for _, currentJob := range jobs {
      if currentJob.Id != job.Id {
        newJobs = append(newJobs, currentJob)
      }
    }
    datastore.jobsByNodeId[job.NodeId] = newJobs
    delete(datastore.jobsById, job.Id)
    log.WithFields(log.Fields {
      "id": job.Id,
      "node": job.NodeId,
    }).Debug("Deleted job from list")
  }
  return err
}

func (datastore *FileDatastoreImpl) addJob(job *model.Job) error {
  var err error
  existingJob := datastore.getJobById(job.Id)
  if existingJob != nil {
    err = errors.New("Job already exists")
  } else {
    jobs := datastore.jobsByNodeId[job.NodeId]
    if jobs == nil {
      jobs = make([]*model.Job, 0)
    }
    datastore.jobsByNodeId[job.NodeId] = append(jobs, job)
    datastore.jobsById[job.Id] = job
    datastore.incrementJobId(job.Id)
    log.WithFields(log.Fields {
      "id": job.Id,
      "node": job.NodeId,
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
  folder := filepath.Join(datastore.jobDir, sanitize.Name(job.NodeId))
  log.WithFields(log.Fields {
    "id": job.Id,
    "folder": folder,
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

func (datastore *FileDatastoreImpl) GetPackets(jobId int, offset int, count int, unwrap bool) ([]*model.Packet, error) {
  var packets []*model.Packet
  var err error
  job := datastore.GetJob(jobId)
  if job != nil {
    if job.Status == model.JobStatusCompleted {
      packets, err = packet.ParsePcap(datastore.getStreamFilename(job), offset, count, unwrap)
      if err != nil {
        log.WithError(err).WithField("jobId", job.Id).Warn("Failed to parse captured packets")
        err = nil
      }
    }
  } else {
    err = errors.New("Job not found")
  }

  return packets, err
}

func (datastore *FileDatastoreImpl) SavePacketStream(jobId int, reader io.ReadCloser) error {
  var err error
  job := datastore.GetJob(jobId)
  if job != nil {
    var count int64
    file, err := os.Create(datastore.getStreamFilename(job))
    if err == nil {
      defer file.Close()
      count, err = io.Copy(file, reader)
    }
    if err != nil {
      log.WithError(err).WithField("jobId", jobId).Error("Failed to write packet stream to file")
    } else {
      log.WithFields(log.Fields {
        "bytes": count,
        "jobId": jobId,
      }).Info("Saved packet stream to file")
    }
  } else {
    err = errors.New("Job not found")
  }
  return err
}

func (datastore *FileDatastoreImpl) GetPacketStream(jobId int, unwrap bool) (io.ReadCloser, string, int64, error) {
  var reader io.ReadCloser
  var filename string
  var length int64
  var err error
  job := datastore.GetJob(jobId)
  if job != nil {
    if job.Status == model.JobStatusCompleted {
      filename = fmt.Sprintf("nodeoni_%s_%d.%s", sanitize.Name(job.NodeId), job.Id, job.FileExtension);
      file, err := os.Open(datastore.getModifiedStreamFilename(job, unwrap))
      if err != nil {
        log.WithError(err).WithField("jobId", job.Id).Error("Failed to open packet stream")
      }
      reader = file
      info, err := file.Stat()
      length = info.Size()
      log.WithFields(log.Fields {
        "size": length,
        "name": info.Name(),
      }).Info("Streaming file")
      if err != nil {
        log.WithError(err).WithField("jobId", job.Id).Error("Failed to open file stats")
      }
    }
  } else {
    err = errors.New("Job not found")
  }

  return reader, filename, length, err
}

func (datastore *FileDatastoreImpl) getStreamFilename(job *model.Job) string {
  filename := fmt.Sprintf("%d.bin", job.Id)
  folder := filepath.Join(datastore.jobDir, sanitize.Name(job.NodeId))
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
