// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package module

import (
  "errors"
  "github.com/apex/log"
)

type ModuleManager struct {
  enabled     []Module
  stoppedChan chan string
}

func NewModuleManager() *ModuleManager {
  return &ModuleManager{
    stoppedChan: make(chan string),
  }
}

func (mgr *ModuleManager) LaunchModules(available map[string]Module, modules ModuleConfigMap, skipFailures bool) error {
  var err error
  if len(modules) > 0 {
    log.Info("Launching modules")
    var initialized map[string]Module
    initialized, err = mgr.initModules(available, modules, skipFailures)
    if err == nil {
      mgr.startModules(initialized, skipFailures)
    } else {
      log.WithError(err).Error("Aborting module launch due to initialization error")
    }
  }
  return err
}

func (mgr *ModuleManager) initModules(available map[string]Module, modules ModuleConfigMap, skipFailures bool) (map[string]Module, error) {
  var err error
  initialized := make(map[string]Module)
  for moduleName, moduleConfig := range modules {
    log.WithField("module", moduleName).Info("Initializing module")

    instance := available[moduleName]
    if instance == nil {
      log.WithField("module", moduleName).Error("Module does not exist")
      err = errors.New("Module does not exist: " + moduleName)
      break
    } else {
      prereqs := instance.PrerequisiteModules()
      if !mgr.meetsPrerequisites(prereqs, modules) {
        err = errors.New("Pre-requisites not met for module: " + moduleName)
      } else {
        err = instance.Init(moduleConfig)
        if err == nil {
          initialized[moduleName] = instance
        } else {
          log.WithError(err).WithField("module", moduleName).Error("Failed to initialize module")
          if !skipFailures {
            break
          }
        }
      }
    }
  }
  return initialized, err
}

func (mgr *ModuleManager) meetsPrerequisites(prereqs []string, modules ModuleConfigMap) bool {
  for _, name := range prereqs {
    if _, found := modules[name]; !found {
      return false
    }
  }
  return true
}

func (mgr *ModuleManager) startModules(modules map[string]Module, skipFailures bool) {
  for name, instance := range modules {
    go mgr.runModule(name, instance)
    mgr.enabled = append(mgr.enabled, instance)
  }
}

func (mgr *ModuleManager) runModule(name string, module Module) {
  log.WithField("module", name).Info("Starting module")
  err := module.Start()
  if err != nil {
    log.WithError(err).WithField("module", name).Info("Module failed")
  }
  mgr.stoppedChan <- name
}

func (mgr *ModuleManager) TerminateModules() {
  log.Info("Terminating Modules")
  for _, module := range mgr.enabled {
    if module.IsRunning() {
      module.Stop()
    }
  }

  completedCount := 0
  for completedCount < len(mgr.enabled) {
    name := <-mgr.stoppedChan
    log.WithField("module", name).Info("Module stopped")
    completedCount++
  }
}
