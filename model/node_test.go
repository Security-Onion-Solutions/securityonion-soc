// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "testing"
)

func testModel(tester *testing.T, newModel string, model string, front string, back string) {
  node := NewNode("")
  node.SetModel(newModel)

  if node.Model != model {
    tester.Errorf("Expected model %s but got %s", model, node.Model)
  }
  if node.ImageFront != front {
    tester.Errorf("Expected front %s but got %s", front, node.ImageFront)
  }
  if node.ImageBack != back {
    tester.Errorf("Expected back %s but got %s", back, node.ImageBack)
  }
}

func TestSetModel(tester *testing.T) {
  testModel(tester, "", "N/A", "", "");
  testModel(tester, "foo", "N/A", "", "");
  testModel(tester, "SOSMN", "SOSMN", "sos-1u-front-thumb.jpg", "sos-1u-ethernet-back-thumb.jpg");
  testModel(tester, "SOS1000", "SOS1000", "sos-1u-front-thumb.jpg", "sos-1u-ethernet-back-thumb.jpg");
  testModel(tester, "SOS500", "SOS500", "sos-1u-front-thumb.jpg", "sos-1u-ethernet-back-thumb.jpg");
  testModel(tester, "SOSSNNV", "SOSSNNV", "sos-1u-front-thumb.jpg", "sos-1u-sfp-back-thumb.jpg");
  testModel(tester, "SOS1000F", "SOS1000F", "sos-1u-front-thumb.jpg", "sos-1u-sfp-back-thumb.jpg");
  testModel(tester, "SOS10K", "SOS10K", "sos-1u-front-thumb.jpg", "sos-1u-sfp-back-thumb.jpg");
  testModel(tester, "SOS4000", "SOS4000", "sos-2u-front-thumb.jpg", "sos-2u-back-thumb.jpg");
  testModel(tester, "SOSSN7200", "SOSSN7200", "sos-2u-front-thumb.jpg", "sos-2u-back-thumb.jpg");
}

func testStatus(tester *testing.T, 
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
  result := node.UpdateOverallStatus()
  shouldChange := nodeStatus != expectedStatus
  if result != shouldChange {
    tester.Errorf("Unexpected node status change")
  }
  if expectedStatus != node.Status {
    tester.Errorf("Expected status %s but got %s [%s, %s, %s, %s]", expectedStatus, node.Status, nodeStatus, connectionStatus, raidStatus, processStatus)
  }
}

func TestUpdateNodeStatusAllUnknown(tester *testing.T) {
  // If all component statuses are unknown then the node's overall status is fault, regardless of current status.
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
}

func TestUpdateNodeStatusOneNotUnknown(tester *testing.T) {
  // If only one status is not unknown then must be in fault state.
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusOk,       NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusFault,    NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault,    NodeStatusFault)

  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusOk,       NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault,    NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault,    NodeStatusFault)

  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusOk,       NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault,    NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusUnknown,  NodeStatusFault,    NodeStatusFault)
}

func TestUpdateNodeStatusMultipleNotUnknownOkFirst(tester *testing.T) {
  // If an earlier component status is Ok then the subsequent status becomes the overall status, regardless of current status.
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusOk,      NodeStatusOk,       NodeStatusOk)
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusUnknown, NodeStatusOk,       NodeStatusOk)
  testStatus(tester, NodeStatusUnknown, NodeStatusOk,       NodeStatusUnknown, NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusOk,      NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusOk,      NodeStatusFault,    NodeStatusFault)

  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusOk,      NodeStatusOk,       NodeStatusOk)
  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusUnknown, NodeStatusOk,       NodeStatusOk)
  testStatus(tester, NodeStatusOk,      NodeStatusOk,       NodeStatusUnknown, NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusOk,      NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusOk,      NodeStatusFault,    NodeStatusFault)

  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusOk,      NodeStatusOk,       NodeStatusOk)
  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusUnknown, NodeStatusOk,       NodeStatusOk)
  testStatus(tester, NodeStatusFault,   NodeStatusOk,       NodeStatusUnknown, NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusOk,      NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
}

func TestUpdateNodeStatusMultipleNotUnknownFaultFirst(tester *testing.T) {
  // If an earlier component status is Fault then the subsequent status remains Fault, regardless of current status.
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusOk,      NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusUnknown, NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusFault,    NodeStatusUnknown, NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusFault,   NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusUnknown, NodeStatusUnknown,  NodeStatusFault,   NodeStatusFault,    NodeStatusFault)
  
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusOk,      NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusUnknown, NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusFault,    NodeStatusUnknown, NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault,   NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault,   NodeStatusFault,    NodeStatusFault)
  
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusOk,      NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusOk,      NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusOk,      NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusUnknown, NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusFault,    NodeStatusUnknown, NodeStatusFault,    NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault,   NodeStatusOk,       NodeStatusFault)
  testStatus(tester, NodeStatusFault,   NodeStatusUnknown,  NodeStatusFault,   NodeStatusFault,    NodeStatusFault)
}