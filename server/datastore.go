// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
  "io"
  "github.com/security-onion-solutions/securityonion-soc/model"
)

type Datastore interface {
  CreateSensor(id string) *model.Sensor
  GetSensors() []*model.Sensor
  AddSensor(sensor *model.Sensor) error
  UpdateSensor(newSensor *model.Sensor) error
  GetNextJob(sensorId string) *model.Job
  CreateJob() *model.Job
  GetJob(jobId int) *model.Job
  GetJobs() []*model.Job
  AddJob(job *model.Job) error
  UpdateJob(job *model.Job) error
  GetPackets(jobId int, offset int, count int) ([]*model.Packet, error)
  SavePacketStream(jobId int, reader io.ReadCloser) error
  GetPacketStream(jobId int) (io.ReadCloser, string, error)
}