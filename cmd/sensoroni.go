// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package main

import (
  "flag"
  "fmt"
  "os"
  "os/signal"
  "syscall"
  "time"
  "github.com/apex/log"
  "github.com/apex/log/handlers/logfmt"
  "github.com/apex/log/handlers/text"
  "github.com/sensoroni/sensoroni/agent"
  agentModules "github.com/sensoroni/sensoroni/agent/modules"
  "github.com/sensoroni/sensoroni/config"
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/server"
  serverModules "github.com/sensoroni/sensoroni/server/modules"
)

var (
  BuildVersion = "unknown"
  BuildTime    = "unknown"
)

func InitLogging(logFilename string, logLevel string) (*os.File, error) {
  logFile, err := os.OpenFile(logFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
  if err == nil {
    log.SetHandler(logfmt.New(logFile))
  } else {
    log.WithError(err).WithField("logfile", logFilename).Error("Failed to create log file, using console instead")
    log.SetHandler(text.New(os.Stdout))
  }
  log.SetLevelFromString(logLevel)
  return logFile, err
}

func main() {
  configFilename := flag.String("config", "sensoroni.json", "Configuration file, in JSON format")
  flag.Parse()

  buildTime, err := time.Parse("2006-01-02T15:04:05", BuildTime)
  if err != nil {
    fmt.Printf("Unable to parse build time; reason=%s\n", err.Error())
  }
  cfg, err := config.LoadConfig(*configFilename, BuildVersion, buildTime)
  if err == nil {
    logFile, _ := InitLogging(cfg.LogFilename, cfg.LogLevel)
    defer logFile.Close()

    log.WithFields(log.Fields {
      "version": cfg.Version,
      "buildTime": cfg.BuildTime,
    }).Info("Version Information")	

    moduleMgr := module.NewModuleManager()
    var srv *server.Server
    if cfg.Server != nil {
      srv = server.NewServer(cfg.Server, cfg.Version)
      err = moduleMgr.LaunchModules(serverModules.BuildModuleMap(srv), cfg.Server.Modules, cfg.Server.ModuleFailuresIgnored)
      if err == nil {
        go srv.Start()
      } else {
        srv = nil
      }
    }
    var agt *agent.Agent
    if err == nil && cfg.Agent != nil {
      agt = agent.NewAgent(cfg.Agent, cfg.Version)
      err = moduleMgr.LaunchModules(agentModules.BuildModuleMap(agt), cfg.Agent.Modules, cfg.Agent.ModuleFailuresIgnored)
      if err == nil {
        go agt.Start()
      } else {
        agt = nil
      }
    }

    terminateChan := make(chan os.Signal, 2)
    signal.Notify(terminateChan, os.Interrupt, syscall.SIGTERM)
    go func() {
      <-terminateChan
      log.Warn("Detected shutdown request, waiting for app to shutdown gracefully")
      if agt != nil {
        agt.Stop()
      }
      if srv != nil {
        srv.Stop()
      }

      time.Sleep(time.Duration(cfg.ShutdownGracePeriodMs) * time.Millisecond)
      log.WithField("ShutdownGracePeriodMs", cfg.ShutdownGracePeriodMs).Warn("Shutdown did not exit within grace period; aborting")
      logFile.Close()
      os.Exit(1)
    }()

    if agt != nil {
      agt.Wait()
      log.Info("Agent has stopped")
    }
    if srv != nil {
      srv.Wait()
      log.Info("Server has stopped")
    }

    moduleMgr.TerminateModules()
  } else {
    fmt.Printf("Error: Unable to read configuration file '%s' [%s]\n", *configFilename, err)
  }
}
