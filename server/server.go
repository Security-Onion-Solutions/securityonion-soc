// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/config"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/rbac"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "os/exec"
  "strings"
)

const AGENT_ID = "agent"

type Server struct {
  Config           *config.ServerConfig
  Host             *web.Host
  Datastore        Datastore
  AdminUserstore   AdminUserstore
  Userstore        Userstore
  Rolestore        Rolestore
  Eventstore       Eventstore
  Casestore        Casestore
  Configstore      Configstore
  GridMembersstore GridMembersstore
  Metrics          Metrics
  stoppedChan      chan bool
  Authorizer       rbac.Authorizer
  Agent            *model.User
  Context          context.Context
}

func NewServer(cfg *config.ServerConfig, version string) *Server {
  server := &Server{
    Config:      cfg,
    Host:        web.NewHost(cfg.BindAddress, cfg.HtmlDir, cfg.IdleConnectionTimeoutMs, version, cfg.SrvKeyBytes, AGENT_ID),
    stoppedChan: make(chan bool, 1),
  }
  server.initContext()
  return server
}

func (server *Server) initContext() {
  // Server will retain the role of an agent until there's a need for higher privileges
  server.Agent = model.NewUser()
  server.Agent.Id = AGENT_ID
  server.Agent.Email = server.Agent.Id
  server.Context = context.WithValue(context.Background(), web.ContextKeyRequestor, server.Agent)
}

func (server *Server) Start() {
  if server.Datastore == nil {
    log.Error("Datastore module has not been initialized; ensure a valid datastore module has been defined in the configuration")
  } else {
    log.Info("Starting server")

    server.Host.Register("/api/case/", NewCaseHandler(server))
    server.Host.Register("/api/events/", NewEventHandler(server))
    server.Host.Register("/api/info", NewInfoHandler(server))
    server.Host.Register("/api/job/", NewJobHandler(server))
    server.Host.Register("/api/jobs/", NewJobsHandler(server))
    server.Host.Register("/api/packets", NewPacketHandler(server))
    server.Host.Register("/api/query/", NewQueryHandler(server))
    server.Host.Register("/api/node", NewNodeHandler(server))
    server.Host.Register("/api/grid", NewGridHandler(server))
    server.Host.Register("/api/stream", NewStreamHandler(server))
    server.Host.Register("/api/users/", NewUsersHandler(server))
    server.Host.Register("/api/config/", NewConfigHandler(server))
    server.Host.Register("/api/gridmembers/", NewGridMembersHandler(server))
    server.Host.Register("/api/roles/", NewRolesHandler(server))

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
    if server.Config.DeveloperEnabled {
      log.Info("Using developer mode; all authorization requests will succeed")
    } else {
      log.Warn("No authorizer module has been configured; assuming no authorization")
      err = errors.New("Missing Authorizer module")
    }
  } else {
    err = server.Authorizer.CheckContextOperationAuthorized(ctx, operation, target)
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
