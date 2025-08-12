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
	startTime := time.Now()
	
	// Log input for debugging
	log.WithFields(log.Fields{
		"detectionId":     det.PublicID,
		"detectionEngine": det.Engine,
		"contentLength":   len(det.Content),
		"overridesCount":  len(det.Overrides),
	}).Debug("converting sigma rule with native converter")
	
	// Use the native converter
	query, err := sigma.ConvertDetectionToEQL(ctx, det, []string{
		e.sigmaPipelineFinal,
		e.sigmaPipelineSO,
	})
	
	runtime := time.Since(startTime)
	
	// Always log the result
	logFields := log.Fields{
		"sigmaConvertNative":   true,
		"sigmaConvertExecTime": runtime.Seconds(),
	}
	
	if err != nil {
		logFields["sigmaConvertError"] = err.Error()
		log.WithFields(logFields).Error("native sigma converter failed")
		return "", fmt.Errorf("native sigma converter failed: %w", err)
	}
	
	logFields["sigmaConvertOutput"] = query
	logFields["sigmaConvertOutputLen"] = len(query)
	log.WithFields(logFields).Info("native sigma converter succeeded")
	
	return query, nil
}

