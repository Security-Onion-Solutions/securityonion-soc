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
  "context"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/config"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "os/exec"
  "strings"
)

type Authorizer interface {
  CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error
}

type Server struct {
  Config      *config.ServerConfig
  Host        *web.Host
  Datastore   Datastore
  Userstore   Userstore
  Rolestore   Rolestore
  Eventstore  Eventstore
  Casestore   Casestore
  Metrics     Metrics
  stoppedChan chan bool
  Authorizer  Authorizer
  Agent       *model.User
  Context     context.Context
}

func NewServer(cfg *config.ServerConfig, version string) *Server {
  server := &Server{
    Config:      cfg,
    Host:        web.NewHost(cfg.BindAddress, cfg.HtmlDir, cfg.IdleConnectionTimeoutMs, version),
    stoppedChan: make(chan bool, 1),
  }
  server.initContext()
  return server
}

func (server *Server) initContext() {
  // Server will retain the role of an agent until there's a need for higher privileges
  server.Agent = model.NewUser()
  server.Agent.Id = "agent"
  server.Agent.Email = server.Agent.Id
  server.Context = context.WithValue(context.Background(), web.ContextKeyRequestor, server.Agent)
}

func (server *Server) Start() {
  if server.Datastore == nil {
    log.Error("Datastore module has not been initialized; ensure a valid datastore module has been defined in the configuration")
  } else {
    log.Info("Starting server")

    server.Host.Register("/api/case", NewCaseHandler(server))
    server.Host.Register("/api/events/", NewEventHandler(server))
    server.Host.Register("/api/info", NewInfoHandler(server))
    server.Host.Register("/api/job/", NewJobHandler(server))
    server.Host.Register("/api/jobs/", NewJobsHandler(server))
    server.Host.Register("/api/packets", NewPacketHandler(server))
    server.Host.Register("/api/query/", NewQueryHandler(server))
    server.Host.Register("/api/node", NewNodeHandler(server))
    server.Host.Register("/api/grid", NewGridHandler(server))
    server.Host.Register("/api/stream", NewStreamHandler(server))
    server.Host.Register("/api/user/", NewUserHandler(server))
    server.Host.Register("/api/users/", NewUsersHandler(server))

    server.Host.Start()
  }

  server.stoppedChan <- true
}

func (server *Server) Stop() {
  if server.Host != nil {
    log.Info("Stopping server")
    server.Host.Stop()
  }
}

func (server *Server) Wait() {
  <-server.stoppedChan
}

func (server *Server) CheckAuthorized(ctx context.Context, operation string, target string) error {
  var err error
  if server.Authorizer == nil {
    log.Warn("No authorizer module has been configured; assuming no authorization")
    err = errors.New("Missing Authorizer module")
  } else {
    err = server.Authorizer.CheckContextOperationAuthorized(ctx, "write", "cases")
  }
  return err
}

func (server *Server) GetTimezones() []string {
  var zones []string = make([]string, 0, 0)
  bytes, err := exec.Command(server.Config.TimezoneScript).Output()
  if err == nil {
    output := string(bytes)
    if strings.Contains(output, "America/New_York") {
      zones = strings.Split(output, "\n")
    } else {
      log.WithError(err).Error("Timezone output is invalid")
    }
  } else {
    log.WithError(err).Error("Unable to lookup timezones from operating system")
  }
  return zones
}
