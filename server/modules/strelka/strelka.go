// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type IOManager interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, contents []byte, perm fs.FileMode) error
	DeleteFile(path string) error
	ReadDir(path string) ([]os.DirEntry, error)
	MakeRequest(*http.Request) (*http.Response, error)
}

type StrelkaEngine struct {
	srv             *server.Server
	isRunning       bool
	thread          *sync.WaitGroup
	yaraRulesFolder string
	IOManager
}

func NewStrelkaEngine(srv *server.Server) *StrelkaEngine {
	return &StrelkaEngine{
		srv:       srv,
		IOManager: &ResourceManager{},
	}
}

func (e *StrelkaEngine) PrerequisiteModules() []string {
	return nil
}

func (e *StrelkaEngine) Init(config module.ModuleConfig) error {
	e.thread = &sync.WaitGroup{}

	e.yaraRulesFolder = module.GetStringDefault(config, "elastAlertRulesFolder", "/opt/so/conf/strelka/rules")

	return nil
}

func (e *StrelkaEngine) Start() error {
	e.srv.DetectionEngines[model.EngineNameStrelka] = e
	e.isRunning = true

	go e.startCommunityRuleImport()

	return nil
}

func (e *StrelkaEngine) Stop() error {
	e.isRunning = false

	return nil
}

func (e *StrelkaEngine) IsRunning() bool {
	return e.isRunning
}

func (e *StrelkaEngine) ValidateRule(data string) (string, error) {
	_, err := ParseYaraRules([]byte(data))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (e *StrelkaEngine) SyncLocalDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]string, err error) {
	return nil, nil
}

func (e *StrelkaEngine) startCommunityRuleImport() {
	for e.isRunning {
		time.Sleep(time.Second * 600)
		if !e.isRunning {
			break
		}

		start := time.Now()

		files, err := e.ReadDir(e.yaraRulesFolder)
		if err != nil {
			log.WithError(err).Error("Failed to read yara rules folder")
			continue
		}

		rules := []*YaraRule{}
		errors := 0

		for _, file := range files {
			ext := filepath.Ext(file.Name())
			if file.IsDir() || strings.ToLower(ext) != ".yar" {
				continue
			}

			filename := e.yaraRulesFolder + "/" + file.Name()

			raw, err := e.ReadFile(filename)
			if err != nil {
				log.WithError(err).WithField("file", filename).Error("failed to read yara rule file")
				errors++

				continue
			}

			parsed, err := ParseYaraRules(raw)
			if err != nil {
				log.WithError(err).WithField("file", filename).Error("failed to parse yara rule file")
				errors++
			}

			rules = append(rules, parsed...)
		}

		log.WithFields(log.Fields{
			"files":  len(files),
			"rules":  len(rules),
			"errors": errors,
			"exTime": time.Since(start).Seconds(),
		}).Info("parsed yara community rules")

		_, _ = e.syncCommunityDetections(context.Background(), nil)
	}
}

func (e *StrelkaEngine) syncCommunityDetections(ctx context.Context, detections []*model.Detection) (errMap map[string]error, err error) {
	return nil, nil
}

// go install go.uber.org/mock/mockgen@latest
//go:generate mockgen -destination mock/mock_iomanager.go -package mock . IOManager

type ResourceManager struct{}

func (_ *ResourceManager) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (_ *ResourceManager) WriteFile(path string, contents []byte, perm fs.FileMode) error {
	return os.WriteFile(path, contents, perm)
}

func (_ *ResourceManager) DeleteFile(path string) error {
	return os.Remove(path)
}

func (_ *ResourceManager) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func (_ *ResourceManager) MakeRequest(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}
