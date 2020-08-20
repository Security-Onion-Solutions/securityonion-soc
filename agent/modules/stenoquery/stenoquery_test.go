// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package stenoquery

import (
	"strconv"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

func TestInitStenoQuery(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewStenoQuery(nil)
	err := sq.Init(cfg)
	if err == nil {
		tester.Errorf("expected non-nil error during init")
	}
	if sq.executablePath != DEFAULT_EXECUTABLE_PATH {
		tester.Errorf("expected executablePath of %s but got %s", DEFAULT_EXECUTABLE_PATH, sq.executablePath)
	}
	if sq.pcapOutputPath != DEFAULT_PCAP_OUTPUT_PATH {
		tester.Errorf("expected pcapOutputPath of %s but got %s", DEFAULT_PCAP_OUTPUT_PATH, sq.pcapOutputPath)
	}
	if sq.pcapInputPath != DEFAULT_PCAP_INPUT_PATH {
		tester.Errorf("expected pcapInputPath of %s but got %s", DEFAULT_PCAP_INPUT_PATH, sq.pcapInputPath)
	}
	if sq.epochRefreshMs != DEFAULT_EPOCH_REFRESH_MS {
		tester.Errorf("expected epochRefreshMs of %d but got %d", DEFAULT_EPOCH_REFRESH_MS, sq.epochRefreshMs)
	}
	if sq.timeoutMs != DEFAULT_TIMEOUT_MS {
		tester.Errorf("expected timeoutMs of %d but got %d", DEFAULT_TIMEOUT_MS, sq.timeoutMs)
	}
	if sq.dataLagMs != DEFAULT_DATA_LAG_MS {
		tester.Errorf("expected dataLagMs of %d but got %d", DEFAULT_DATA_LAG_MS, sq.dataLagMs)
	}
}

func TestDataLag(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewStenoQuery(nil)
	sq.Init(cfg)
	lagDate := sq.getDataLagDate()
	if lagDate.After(time.Now()) {
		tester.Errorf("expected data lag date to be before current date")
	}
}

func TestCreateQuery(tester *testing.T) {
	sq := NewStenoQuery(nil)

	job := model.NewJob()
	job.Filter.BeginTime, _ = time.Parse(time.RFC3339, "2006-01-02T15:05:05Z")
	job.Filter.EndTime, _ = time.Parse(time.RFC3339, "2006-01-02T15:06:05Z")
	expectedQuery := "before 2006-01-02T15:06:05Z and after 2006-01-02T15:05:05Z"
	query := sq.CreateQuery(job)
	if query != expectedQuery {
		tester.Errorf("expected query %s to equal %s", query, expectedQuery)
	}

	job.Filter.SrcIp = "1.2.3.4"
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and host " + job.Filter.SrcIp
	if query != expectedQuery {
		tester.Errorf("expected query %s to equal %s", query, expectedQuery)
	}

	job.Filter.DstIp = "1.2.1.2"
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and host " + job.Filter.DstIp
	if query != expectedQuery {
		tester.Errorf("expected query %s to equal %s", query, expectedQuery)
	}

	job.Filter.SrcPort = 123
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and port " + strconv.Itoa(job.Filter.SrcPort)
	if query != expectedQuery {
		tester.Errorf("expected query %s to equal %s", query, expectedQuery)
	}

	job.Filter.DstPort = 123
	query = sq.CreateQuery(job)
	expectedQuery = expectedQuery + " and port " + strconv.Itoa(job.Filter.DstPort)
	if query != expectedQuery {
		tester.Errorf("expected query %s to equal %s", query, expectedQuery)
	}
}
