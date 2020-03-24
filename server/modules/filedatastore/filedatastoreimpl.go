// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  "github.com/sensoroni/sensoroni/json"
  "github.com/sensoroni/sensoroni/model"
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/packet"
  "github.com/kennygrant/sanitize"
)

const DEFAULT_RETRY_FAILURE_INTERVAL_MS = 600000

type FileDatastoreImpl struct {
  jobDir									string
  retryFailureIntervalMs	int
  jobsBySensorId 					map[string][]*model.Job
  jobsById 								map[int]*model.Job
  sensorsById							map[string]*model.Sensor
  ready    								bool
  nextJobId								int
  lock										sync.RWMutex
}

func NewFileDatastoreImpl() *FileDatastoreImpl {
  return &FileDatastoreImpl {
    jobsBySensorId: make(map[string][]*model.Job),
    jobsById: make(map[int]*model.Job),
    sensorsById: make(map[string]*model.Sensor),
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

func (datastore *FileDatastoreImpl) CreateSensor(id string) *model.Sensor {
  sensor := model.NewSensor(id)
  return sensor
}

func (datastore *FileDatastoreImpl) GetSensors() []*model.Sensor {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  allSensors := make([]*model.Sensor, 0)
  for _, sensor := range datastore.sensorsById {
    allSensors = append(allSensors, sensor)
  }
  return allSensors
}

func (datastore *FileDatastoreImpl) AddSensor(sensor *model.Sensor) error {
  return datastore.UpdateSensor(sensor)
}

func (datastore *FileDatastoreImpl) addSensor(sensor *model.Sensor) *model.Sensor {
  datastore.sensorsById[sensor.Id] = sensor
  log.WithFields(log.Fields {
    "id": sensor.Id,
    "description": sensor.Description,
  }).Debug("Added sensor")
  return sensor
}

func (datastore *FileDatastoreImpl) UpdateSensor(newSensor *model.Sensor) error {
  if len(newSensor.Id) > 0 {
    datastore.lock.Lock()
    defer datastore.lock.Unlock()
    sensor := datastore.sensorsById[newSensor.Id]
    if sensor == nil {
      sensor = datastore.addSensor(newSensor)
    }
    // Preserve the original online time
    newSensor.OnlineTime = sensor.OnlineTime
    // Update time is now
    newSensor.UpdateTime = time.Now()
    // Calculate uptime
    newSensor.UptimeSeconds = int(newSensor.UpdateTime.Sub(newSensor.OnlineTime).Seconds())
    datastore.sensorsById[newSensor.Id] = newSensor
  } else {
    log.WithField("description", newSensor.Description).Info("Not adding sensor with missing id")
  }
  return nil
} 

func (datastore *FileDatastoreImpl) GetNextJob(sensorId string) *model.Job {
  datastore.lock.RLock()
  defer datastore.lock.RUnlock()
  var nextJob *model.Job
  now := time.Now()
  jobs := datastore.jobsBySensorId[sensorId]
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

func (datastore *FileDatastoreImpl) deleteJob(job *model.Job) error {
  var err error
  existingJob := datastore.getJobById(job.Id)
  if existingJob == nil {
    err = errors.New("Job does not exist")
  } else {
    jobs := datastore.jobsBySensorId[job.SensorId]
    newJobs := make([]*model.Job, 0)
    for _, currentJob := range jobs {
      if currentJob.Id != job.Id {
        newJobs = append(newJobs, currentJob)
      }
    }
    datastore.jobsBySensorId[job.SensorId] = newJobs
    delete(datastore.jobsById, job.Id)
    log.WithFields(log.Fields {
      "id": job.Id,
      "sensor": job.SensorId,
    }).Debug("Deleted job")
  }
  return err
}

func (datastore *FileDatastoreImpl) addJob(job *model.Job) error {
  var err error
  existingJob := datastore.getJobById(job.Id)
  if existingJob != nil {
    err = errors.New("Job already exists")
  } else {
    jobs := datastore.jobsBySensorId[job.SensorId]
    if jobs == nil {
      jobs = make([]*model.Job, 0)
    }
    datastore.jobsBySensorId[job.SensorId] = append(jobs, job)
    datastore.jobsById[job.Id] = job
    datastore.incrementJobId(job.Id)
    log.WithFields(log.Fields {
      "id": job.Id,
      "sensor": job.SensorId,
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
  folder := filepath.Join(datastore.jobDir, sanitize.Name(job.SensorId))
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

func (datastore *FileDatastoreImpl) GetPackets(jobId int, offset int, count int) ([]*model.Packet, error) {
  var packets []*model.Packet
  var err error
  job := datastore.GetJob(jobId)
  if job != nil {
    if job.Status == model.JobStatusCompleted {
      packets, err = packet.ParsePcap(datastore.getStreamFilename(job), offset, count)
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

func (datastore *FileDatastoreImpl) GetPacketStream(jobId int) (io.ReadCloser, string, error) {
  var reader io.ReadCloser
  var filename string
  var err error
  job := datastore.GetJob(jobId)
  if job != nil {
    if job.Status == model.JobStatusCompleted {
      filename = fmt.Sprintf("sensoroni_%s_%d.%s", sanitize.Name(job.SensorId), job.Id, job.FileExtension);
      reader, err = os.Open(datastore.getStreamFilename(job))
      if err != nil {
        log.WithError(err).WithField("jobId", job.Id).Error("Failed to open packet stream")
        err = nil
      }
    }
  } else {
    err = errors.New("Job not found")
  }

  return reader, filename, err
}

func (datastore *FileDatastoreImpl) getStreamFilename(job *model.Job) string {
  filename := fmt.Sprintf("%d.bin", job.Id)
  folder := filepath.Join(datastore.jobDir, sanitize.Name(job.SensorId))
  return filepath.Join(folder, filename)
}
