// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testModel(tester *testing.T, newModel string, model string, front string, back string) {
	node := NewNode("")
	node.SetModel(newModel)
	assert.Equal(tester, model, node.Model)
	assert.Equal(tester, front, node.ImageFront)
	assert.Equal(tester, back, node.ImageBack)
}

func TestSetModel(tester *testing.T) {
	testModel(tester, "", "N/A", "", "")
	testModel(tester, "foo", "N/A", "", "")
	testModel(tester, "SOSMN", "SOSMN", "sos-1u-front-thumb.jpg", "sos-1u-ethernet-back-thumb.jpg")
	testModel(tester, "SOS1000", "SOS1000", "sos-1u-front-thumb.jpg", "sos-1u-ethernet-back-thumb.jpg")
	testModel(tester, "SOS500", "SOS500", "sos-1u-front-thumb.jpg", "sos-1u-ethernet-back-thumb.jpg")
	testModel(tester, "SOSSNNV", "SOSSNNV", "sos-1u-front-thumb.jpg", "sos-1u-sfp-back-thumb.jpg")
	testModel(tester, "SOS1000F", "SOS1000F", "sos-1u-front-thumb.jpg", "sos-1u-sfp-back-thumb.jpg")
	testModel(tester, "SOS10K", "SOS10K", "sos-1u-front-thumb.jpg", "sos-1u-sfp-back-thumb.jpg")
	testModel(tester, "SOS4000", "SOS4000", "sos-2u-front-thumb.jpg", "sos-2u-back-thumb.jpg")
	testModel(tester, "SOSSN7200", "SOSSN7200", "sos-2u-front-thumb.jpg", "sos-2u-back-thumb.jpg")
	testModel(tester, "SO2AMI01", "SO2AMI01", "so-cloud-aws.jpg", "")
	testModel(tester, "SO2AZI01", "SO2AZI01", "so-cloud-azure.jpg", "")
	testModel(tester, "SO2GCI01", "SO2GCI01", "so-cloud-gcp.jpg", "")
}

func testStatus(tester *testing.T,
	enhancedStatusEnabled bool,
	nodeStatus string,
	connectionStatus string,
	raidStatus string,
	processStatus string,
	expectedStatus string) {
	node := NewNode("")
	node.Status = nodeStatus
	node.ConnectionStatus = connectionStatus
	node.RaidStatus = raidStatus
	node.ProcessStatus = processStatus
	result := node.UpdateOverallStatus(enhancedStatusEnabled)
	shouldChange := nodeStatus != expectedStatus
	assert.Equal(tester, shouldChange, result)
	assert.Equal(tester, expectedStatus, node.Status)
}

func TestUpdateNodeStatusAllUnknown(tester *testing.T) {
	// If all component statuses are unknown then the node's overall status is fault, regardless of current status.
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
}

func TestUpdateNodeStatusOneNotUnknown(tester *testing.T) {
	// If only one status is not unknown then must be in fault state.
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)

	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)

	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
}

func TestUpdateImportNodeStatusOneNotUnknown(tester *testing.T) {
	// If only one status is not unknown then must be in fault state.
	testStatus(tester, false, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk)
	testStatus(tester, false, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, false, NodeStatusUnknown, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)

	testStatus(tester, false, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk)
	testStatus(tester, false, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, false, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)

	testStatus(tester, false, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk)
	testStatus(tester, false, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, false, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, false, NodeStatusFault, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
}

func TestUpdateNodeStatusMultipleNotUnknownOkFirst(tester *testing.T) {
	// If an earlier component status is Ok then the subsequent status becomes the overall status, regardless of current status.
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusOk, NodeStatusOk, NodeStatusOk)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusOk, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusOk)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusOk, NodeStatusFault, NodeStatusFault)

	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusOk, NodeStatusOk, NodeStatusOk)
	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusOk, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusOk)
	testStatus(tester, true, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusFault, NodeStatusFault)

	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusOk, NodeStatusOk, NodeStatusOk)
	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusOk, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusOk, NodeStatusOk)
	testStatus(tester, true, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusFault, NodeStatusFault)
}

func TestUpdateNodeStatusMultipleNotUnknownFaultFirst(tester *testing.T) {
	// If an earlier component status is Fault then the subsequent status remains Fault, regardless of current status.
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusOk, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusOk, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusUnknown, NodeStatusUnknown, NodeStatusFault, NodeStatusFault, NodeStatusFault)

	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusOk, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusOk, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusOk, NodeStatusUnknown, NodeStatusFault, NodeStatusFault, NodeStatusFault)

	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusOk, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusOk, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusOk, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusOk, NodeStatusFault)
	testStatus(tester, true, NodeStatusFault, NodeStatusUnknown, NodeStatusFault, NodeStatusFault, NodeStatusFault)
}
