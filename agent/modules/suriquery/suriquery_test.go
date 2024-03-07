// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suriquery

import (
	"os"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func initTest() *SuriQuery {
	cfg := make(map[string]interface{})
	cfg["pcapInputPath"] = "test_resources"
	sq := NewSuriQuery(nil)
	sq.Init(cfg)
	return sq
}
func TestInitSuriQuery(tester *testing.T) {
	cfg := make(map[string]interface{})
	sq := NewSuriQuery(nil)
	err := sq.Init(cfg)
	assert.Error(tester, err)
	assert.Equal(tester, DEFAULT_PCAP_INPUT_PATH, sq.pcapInputPath)
	assert.Equal(tester, DEFAULT_EPOCH_REFRESH_MS, sq.epochRefreshMs)
	assert.Equal(tester, DEFAULT_DATA_LAG_MS, sq.dataLagMs)
}

func TestDataLag(tester *testing.T) {
	sq := initTest()
	lagDate := sq.getDataLagDate()
	assert.False(tester, lagDate.After(time.Now()), "expected data lag datetime to be before current datetime")
}

func TestFindFilesExcludesMalformedNamesAndImpossibleStartTimes(tester *testing.T) {
	sq := initTest()

	start, _ := time.Parse(time.RFC3339, "2024-02-05T00:00:00Z")
	stop, _ := time.Parse(time.RFC3339, "2099-02-06T00:00:00Z")
	files := sq.findFilesInTimeRange(start, stop)
	assert.Len(tester, files, 2)
	assert.Equal(tester, files[0], "test_resources/1/so-pcap.1575817346.lz4")
	assert.Equal(tester, files[1], "test_resources/3/so-pcap.1575817346")
}

func TestDecompress(tester *testing.T) {
	decompressedFilename := "test_resources/1/so-pcap.1575817346"
	compressedFilename := decompressedFilename + SURI_LZ4_SUFFIX

	sq := initTest()
	defer os.Remove(decompressedFilename)

	// Ensure decompressed file does not exist
	_, statErrBefore := os.Stat(decompressedFilename)
	assert.Error(tester, statErrBefore, os.ErrNotExist)
	newPath, err := sq.decompress(compressedFilename)
	assert.Nil(tester, err)
	assert.Equal(tester, decompressedFilename, newPath)

	// Ensure decompressed file does exist
	stats, statErrAfter := os.Stat(decompressedFilename)
	assert.Nil(tester, err, statErrAfter)
	assert.Equal(tester, int64(14918), stats.Size())
}

func TestGetPcapCreateTime(tester *testing.T) {
	sq := initTest()

	_, err := sq.getPcapCreateTime("/some/path/nonconforming.file")
	assert.ErrorContains(tester, err, "unsupported pcap file")

	_, err = sq.getPcapCreateTime("/some/path/so-pcap.file")
	assert.ErrorContains(tester, err, "invalid syntax")

	expectedTime, _ := time.Parse(time.RFC3339, "2019-12-08T15:02:26Z")
	var created time.Time
	created, err = sq.getPcapCreateTime("/some/path/so-pcap.1575817346")
	assert.Nil(tester, err)
	assert.Equal(tester, expectedTime, created)
}

func TestGetDataEpoch(tester *testing.T) {
	sq := initTest()

	epoch := sq.GetDataEpoch()
	expectedTime, _ := time.Parse(time.RFC3339, "2019-12-08T15:02:26Z")
	assert.Equal(tester, expectedTime, epoch)
}

func TestStreamPacketsInPcaps(tester *testing.T) {
	sq := initTest()

	paths := []string{"test_resources/3/so-pcap.1575817346"}
	filter := model.NewFilter()
	startTime, _ := time.Parse(time.RFC3339, "2019-12-08T00:00:00Z")
	filter.BeginTime = startTime
	endTime, _ := time.Parse(time.RFC3339, "2019-12-08T23:59:59Z")
	filter.EndTime = endTime
	filter.SrcIp = "185.47.63.113"
	filter.SrcPort = 19
	filter.DstIp = "176.126.243.198"
	filter.DstPort = 34515

	reader, err := sq.streamPacketsInPcaps(paths, filter)
	assert.Nil(tester, err)
	pcap_length := 14122 // correlates to so-pcap test file
	bytes := make([]byte, 32768)
	count, err := reader.Read(bytes)
	assert.Nil(tester, err)
	assert.Equal(tester, pcap_length, count)
}
