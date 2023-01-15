// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"io"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
)

type FakeUserstore struct {
	users []*model.User
}

func (impl *FakeUserstore) GetUsers(ctx context.Context) ([]*model.User, error) {
	return impl.users, nil
}

func (impl *FakeUserstore) GetUserById(ctx context.Context, id string) (*model.User, error) {
	for _, user := range impl.users {
		if user.Id == id {
			return user, nil
		}
	}
	return nil, errors.New("not found")
}

type FakeRolestore struct {
	roleMap map[string][]string
}

func (impl *FakeRolestore) Reload() {
}

func (impl *FakeRolestore) GetAssignments(ctx context.Context) (map[string][]string, error) {
	return impl.roleMap, nil
}

func (impl *FakeRolestore) PopulateUserRoles(ctx context.Context, user *model.User) error {
	user.Roles = impl.roleMap[user.Email]
	return nil
}

func (impl *FakeRolestore) GetRoles(ctx context.Context) []string {
	roles := make([]string, 0, 0)
	for role := range impl.roleMap {
		roles = append(roles, role)
	}
	return roles
}

type FakeDatastore struct {
	nodes   []*model.Node
	jobs    []*model.Job
	packets []*model.Packet
}

func NewFakeDatastore() *FakeDatastore {
	nodes := make([]*model.Node, 0)
	nodes = append(nodes, &model.Node{})
	nodes = append(nodes, &model.Node{})

	jobs := make([]*model.Job, 0)
	jobs = append(jobs, &model.Job{})
	jobs = append(jobs, &model.Job{})
	jobs = append(jobs, &model.Job{})

	packets := make([]*model.Packet, 0)
	packets = append(packets, &model.Packet{})
	packets = append(packets, &model.Packet{})
	packets = append(packets, &model.Packet{})

	return &FakeDatastore{
		nodes:   nodes,
		jobs:    jobs,
		packets: packets,
	}
}

func (impl *FakeDatastore) CreateNode(ctx context.Context, id string) *model.Node {
	return nil
}

func (impl *FakeDatastore) GetNodes(ctx context.Context) []*model.Node {
	return impl.nodes
}

func (impl *FakeDatastore) AddNode(ctx context.Context, node *model.Node) error {
	return nil
}

func (impl *FakeDatastore) UpdateNode(ctx context.Context, newNode *model.Node) (*model.Node, error) {
	return nil, nil
}

func (impl *FakeDatastore) GetNextJob(ctx context.Context, nodeId string) *model.Job {
	return nil
}

func (impl *FakeDatastore) CreateJob(ctx context.Context) *model.Job {
	return nil
}

func (impl *FakeDatastore) GetJob(ctx context.Context, jobId int) *model.Job {
	return nil
}

func (impl *FakeDatastore) GetJobs(ctx context.Context, kind string, parameters map[string]interface{}) []*model.Job {
	return impl.jobs
}

func (impl *FakeDatastore) AddJob(ctx context.Context, job *model.Job) error {
	return nil
}

func (impl *FakeDatastore) AddPivotJob(ctx context.Context, job *model.Job) error {
	return nil
}

func (impl *FakeDatastore) UpdateJob(ctx context.Context, job *model.Job) error {
	return nil
}

func (impl *FakeDatastore) DeleteJob(ctx context.Context, jobId int) (*model.Job, error) {
	return nil, nil
}

func (impl *FakeDatastore) GetPackets(ctx context.Context, jobId int, offset int, count int, unwrap bool) ([]*model.Packet, error) {
	return impl.packets, nil
}

func (impl *FakeDatastore) SavePacketStream(ctx context.Context, jobId int, reader io.ReadCloser) error {
	return nil
}

func (impl *FakeDatastore) GetPacketStream(ctx context.Context, jobId int, unwrap bool) (io.ReadCloser, string, int64, error) {
	return nil, "", 0, nil
}

type FakeMetrics struct {
}

func NewFakeMetrics() *FakeMetrics {
	return &FakeMetrics{}
}

func (impl *FakeMetrics) GetGridEps(ctx context.Context) int {
	return 12
}

func (impl *FakeMetrics) UpdateNodeMetrics(ctx context.Context, node *model.Node) bool {
	return false
}

func NewFakeServer(authorized bool, roleMap map[string][]string) *Server {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	srv.Authorizer = &rbac.FakeAuthorizer{
		Authorized: authorized,
	}
	srv.Rolestore = &FakeRolestore{
		roleMap: roleMap,
	}

	users := make([]*model.User, 0, 0)
	users = append(users, &model.User{
		Id:    "user-id-1",
		Email: "user1@somewhere.invalid",
	})
	users = append(users, &model.User{
		Id:    "user-id-2",
		Email: "user2@somewhere.invalid",
	})
	srv.Userstore = &FakeUserstore{
		users: users,
	}

	srv.Datastore = NewFakeDatastore()
	srv.Metrics = NewFakeMetrics()

	return srv
}

func NewFakeAuthorizedServer(roleMap map[string][]string) *Server {
	return NewFakeServer(true, roleMap)
}

func NewFakeUnauthorizedServer() *Server {
	return NewFakeServer(false, make(map[string][]string))
}
