// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	"io"
)

type Datastore interface {
	CreateNode(id string) *model.Node
	GetNodes() []*model.Node
	AddNode(node *model.Node) error
	UpdateNode(newNode *model.Node) (*model.Node, error)
	GetNextJob(nodeId string) *model.Job
	CreateJob() *model.Job
	GetJob(jobId int) *model.Job
	GetJobs() []*model.Job
	AddJob(job *model.Job) error
	UpdateJob(job *model.Job) error
	DeleteJob(job *model.Job) error
	GetPackets(jobId int, offset int, count int, unwrap bool) ([]*model.Packet, error)
	SavePacketStream(jobId int, reader io.ReadCloser) error
	GetPacketStream(jobId int, unwrap bool) (io.ReadCloser, string, int64, error)
}
