// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package importer

import (
  "context"
  "errors"
  "fmt"
  "io"
  "os"
  "os/exec"
  "time"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/agent"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/module"
)

const DEFAULT_EXECUTABLE_PATH = "tcpdump"
const DEFAULT_PCAP_OUTPUT_PATH = "/nsm/pcapout"
const DEFAULT_PCAP_INPUT_PATH = "/nsm/import"
const DEFAULT_TIMEOUT_MS = 1200000

type Importer struct {
  config						module.ModuleConfig
  executablePath		string
  pcapOutputPath		string
  pcapInputPath			string
  agent							*agent.Agent
  timeoutMs					int
}

func NewImporter(agt *agent.Agent) *Importer {
  return &Importer {
    agent: agt,
  }
}

func (lag *Importer) PrerequisiteModules() []string {
  return nil
}

func (importer *Importer) Init(cfg module.ModuleConfig) error {
  var err error
  importer.config = cfg
  importer.executablePath = module.GetStringDefault(cfg, "executablePath", DEFAULT_EXECUTABLE_PATH)
  importer.pcapOutputPath = module.GetStringDefault(cfg, "pcapOutputPath", DEFAULT_PCAP_OUTPUT_PATH)
  importer.pcapInputPath = module.GetStringDefault(cfg, "pcapInputPath", DEFAULT_PCAP_INPUT_PATH)
  importer.timeoutMs = module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
  if importer.agent == nil {
    err = errors.New("Unable to invoke JobMgr.AddJobProcessor due to nil agent")
  } else {
    importer.agent.JobMgr.AddJobProcessor(importer)
  }
  return err
}

func (importer *Importer) Start() error {
  return nil
}

func (importer *Importer) Stop() error {
  return nil
}

func (importer *Importer) IsRunning() bool {
  return false
}

func (importer *Importer) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
  var err error
  if len(job.Filter.ImportId) == 0 {
    log.WithFields(log.Fields {
      "jobId": job.Id,
      "importId": job.Filter.ImportId,
    }).Debug("Skipping import processor due to missing importId")
    return reader, nil
  } else {
    job.FileExtension = "pcap"

    query := fmt.Sprintf("host %s and host %s and port %d and port %d",
                        job.Filter.SrcIp, job.Filter.DstIp, job.Filter.SrcPort, job.Filter.DstPort)

    pcapInputFilepath := fmt.Sprintf("%s/%s/pcap/data.pcap", importer.pcapInputPath, job.Filter.ImportId)
    pcapOutputFilepath := fmt.Sprintf("%s/%d.%s", importer.pcapOutputPath, job.Id, job.FileExtension)

    log.WithField("jobId", job.Id).Info("Processing pcap export for imported PCAP job")

    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(importer.timeoutMs) * time.Millisecond)
    defer cancel()
    cmd := exec.CommandContext(ctx, importer.executablePath, "-r", pcapInputFilepath, "-w", pcapOutputFilepath, query)
    var output []byte
    output, err = cmd.CombinedOutput()
    log.WithFields(log.Fields {
      "executablePath": importer.executablePath,
      "query": query,
      "output": string(output),
      "pcapInputFilepath": pcapInputFilepath,
      "pcapOutputFilepath": pcapOutputFilepath,
      "err": err,
      }).Debug("Executed tcpdump")
    if err == nil {
      var file *os.File
      file, err = os.Open(pcapOutputFilepath)
      if err == nil {
        reader = file
      }
    }
  }
  return reader, err
}

func (importer *Importer) CleanupJob(job *model.Job) {
    pcapOutputFilepath := fmt.Sprintf("%s/%d.%s", importer.pcapOutputPath, job.Id, job.FileExtension)
    os.Remove(pcapOutputFilepath)
}

func (importer *Importer) GetDataEpoch() time.Time {
  // Epoch not used for imported data, return current time
  return time.Now()
}
