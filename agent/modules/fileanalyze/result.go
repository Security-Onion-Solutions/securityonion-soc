// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type FileResult struct {
	Timestamp time.Time                `json:"@timestamp"`
	File      FileInfo                 `json:"file"`
	Scanners  map[string]interface{}   `json:"scanners"`
	Event     map[string]interface{}   `json:"event"`
}

type FileInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Hash   string `json:"hash"`
	Depth  int    `json:"depth"`
}

type ResultWriter struct {
	mu      sync.Mutex
	logFile string
}

func NewResultWriter(logFile string) *ResultWriter {
	return &ResultWriter{
		logFile: logFile,
	}
}

func (w *ResultWriter) Write(result *FileResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}
