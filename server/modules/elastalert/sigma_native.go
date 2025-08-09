// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"context"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
	_ "github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/backends" // Register backends
)

// sigmaToElastAlertNative converts Sigma rules using native Go implementation
func (e *ElastAlertEngine) sigmaToElastAlertNative(ctx context.Context, det *model.Detection) (string, error) {
	// Check if native converter is enabled (can be controlled by config)
	useNative := e.srv.Config.GetBool("elastalert.useNativeSigmaConverter")
	if !useNative {
		// Fall back to Python implementation
		return e.sigmaToElastAlert(ctx, det)
	}

	startTime := time.Now()
	
	// Use the native converter
	query, err := sigma.ConvertDetectionToEQL(ctx, det, []string{
		e.sigmaPipelineFinal,
		e.sigmaPipelineSO,
	})
	
	runtime := time.Since(startTime)
	
	log.WithFields(log.Fields{
		"sigmaConvertNative":   true,
		"sigmaConvertOutput":   query,
		"sigmaConvertExecTime": runtime.Seconds(),
		"sigmaConvertError":    err,
	}).Info("executing native sigma converter")
	
	if err != nil {
		// If native converter fails, optionally fall back to Python
		if e.srv.Config.GetBool("elastalert.fallbackToPython") {
			log.WithError(err).Warn("Native sigma converter failed, falling back to Python")
			return e.sigmaToElastAlert(ctx, det)
		}
		return "", fmt.Errorf("native sigma converter failed: %w", err)
	}
	
	return query, nil
}

// EnableNativeSigmaConverter enables the native Go Sigma converter
func (e *ElastAlertEngine) EnableNativeSigmaConverter() {
	// This can be called during initialization to enable native converter
	e.srv.Config.Set("elastalert.useNativeSigmaConverter", true)
}

// SetNativeSigmaConverterFallback sets whether to fall back to Python on failure
func (e *ElastAlertEngine) SetNativeSigmaConverterFallback(enabled bool) {
	e.srv.Config.Set("elastalert.fallbackToPython", enabled)
}