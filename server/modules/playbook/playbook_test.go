// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	SuricataPlaybook = `name: Baseline Playbook - NIDS
id: 1dfe7517-f105-454f-ae96-f2280c09e4b2
description: |
    This is the baseline playbook for NIDS detections.
type: detection
detection_id: ''
detection_category: ''
detection_type: nids
contributors:
  - SecurityOnionSolutions
date: 2025-3-12
modified: 2025-3-13
questions:
  - question: 'What specifically does the alert describe?'
    context: 'Review the Detection description and signature to understand what the detection is trying to expose.'
    answer_sources:
        - alert
    query: |
        aggregation: false
        logsource:
          category: alert
        detection:
            selection:
                document_id|expand: '%document_id%'
            condition: selection
        fields:
            - rule.name
            - rule.category
            - network.data.decoded

  - question: 'What internal system is involved?'
    context: 'Gaining a clear understanding of the services provided by the internal system helps assess potential risks more effectively. Refer to your asset inventory for additional information about the internal host.'
    answer_sources:
        - alert
    query: |
        aggregation: false
        logsource:
          category: alert
          product: suricata
        detection:
            selection:
                document_id|expand: '%document_id%'
            condition: selection
        fields:
            - src_ip
            - src_port
            - dst_ip
            - dst_port

  - question: 'Are there any other alerts associated with the internal system?'
    context: 'Identifying related alerts can help determine if the internal system is experiencing a broader issue.'
    answer_sources:
        - alert
    range: -3d
    query: |
        aggregation: true
        logsource:
          category: alert
        detection:
            selection:
                - src_ip|expand: '%private_ip%'
                - dst_ip|expand: '%private_ip%'
            condition: selection
        fields:
            - rule.type
            - rule.name
            - rule.category

  - question: 'What process is associated with this specific network connection?'
    context: 'Correlating process execution to the network connection can give further indication of intent.'
    answer_sources:
        - network
    range: +/-15m
    query: |
        aggregation: false
        logsource:
          category: network
        detection:
            selection:
                community_id|expand: '%community_id%'
            filter:
                Image|exists: true
            condition: selection and filter
        fields:
            - hostname
            - Image
            - CommandLine

  - question: 'What processes are associated with the public IP?'
    context: 'Correlating process execution with the public IP will give additional context outside of this specific alert.'
    answer_sources:
        - network
    range: -7d
    query: |
        aggregation: false
        logsource:
          category: network
        detection:
            selection:
                related_ip|expand: '%public_ip%'
            filter:
                Image|exists: true
            condition: selection and filter
        fields:
            - hostname
            - Image
            - CommandLine

  - question: 'What is the historical network traffic pattern for the public IP?'
    context: 'Understanding historical traffic patterns can help identify anomalous behavior.'
    answer_sources:
        - network.connection
    range: -30d
    query: |
        aggregation: false
        logsource:
          category: network
          service: connection
        detection:
            selection:
                - src_ip|expand: '%public_ip%'
                - dst_ip|expand: '%public_ip%'
            condition: selection
        fields:
            - src_ip
            - dst_ip
            - dst_port
            - network.protocol
            - event.duration
            - client.ip_bytes
            - server.ip_bytes
            - connection.state_description

  - question: 'Are there any file transfers associated with this alert?'
    context: 'Identifying file transfers can help detect malicious file sharing or data exfiltration.'
    answer_sources:
        - network.file
    range: +/-5m
    query: |
        aggregation: false
        logsource:
          category: network
          service: file
        detection:
            selection:
                - src_ip|expand: '%public_ip%'
                - dst_ip|expand: '%public_ip%'
            condition: selection
        fields:
            - filename
            - filesize
            - file_state
            - magic

  - question: 'Are there any DNS queries associated with the external domains/IPs?'
    context: 'DNS queries can reveal additional infrastructure or C2 channels.'
    answer_sources:
        - dns
    range: +/-1h
    query: |
        aggregation: false
        logsource:
          category: network
          service: dns
        detection:
            selection:
               - dns.query.name|expand: '%domain%'
               - dns.answers.name|expand: '%public_ip%'
            condition: selection
        fields:
            - dns.query.name
            - dns.query.type_name
            - dns.answers.name
            - dns.response.code_name

  - question: 'Are there any TLS certificates associated with this connection?'
    context: 'TLS certificate information can help identify malicious infrastructure or validate legitimate services.'
    answer_sources:
        - network.tls
    range: +/-5m
    query: |
        aggregation: false
        logsource:
          category: network
          service: tls
        detection:
            selection:
                - src_ip|expand: '%src_ip%'
                - dst_ip|expand: '%dst_ip%'
            condition: selection
        fields:
            - ssl.server_name
            - ssl.version
            - ssl.cipher`
	HistoryFileDeletionPlaybook = `name: History File Deletion
id: 6F64990A-ACDA-40B6-AB71-134C073013B5
description: |
    Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity
type: detection
detection_id: '1182f3b3-e716-4efa-99ab-d2685d04360f'
detection_category: ''
detection_type: 'sigma'
contributors:
  - 'SecurityOnionSolutions'
date: 2025-04-21
modified: 2025-04-21
questions:
  - question: 'What was the full command line that triggered the alert?'
    context: 'The full command line provides critical context about which history file was deleted and how it was deleted.'
    range: ''
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: linux
        detection:
            selection:
               ProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - CommandLine
  - question: 'Who was the user that executed the history file deletion command?'
    context: 'Understanding which user deleted the history file helps determine if this was a privileged user (like root) or if a user account may have been compromised.'
    range: ''
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: linux
        detection:
            selection:
               ProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - User
            - CommandLine
  - question: 'What was the parent process that initiated the history file deletion?'
    context: 'The parent process helps identify how the deletion command was initiated, which could indicate if this was part of a script or interactive shell session.'
    range: ''
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: linux
        detection:
            selection:
               ProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - User
            - ParentImage
            - ParentCommandLine
  - question: 'What other commands were executed by the same user within 30 minutes before and after the history file deletion?'
    context: 'Examining the commands executed before and after the deletion can reveal the attackers activities that they were trying to hide.'
    range: +/-30m
    answer_sources:
        - process_creation
    query: |
        aggregation: true
        logsource:
          category: process_creation
          product: linux
        detection:
            selection:
                User|expand: '%User%'
            filter:
                hostname|expand: '%hostname%'
            condition: selection and filter
        fields:
            - Image
            - CommandLine
  - question: 'Was the history file accessed or modified before being deleted?'
    context: 'Attackers might view or modify history files before deleting them to understand previous commands or implant false information.'
    range: -30m
    answer_sources:
        - file_event
    query: |
        aggregation: false
        logsource:
          category: file_event
          product: linux
        detection:
            selection:
                TargetFilename|contains:
                    - '.bash_history'
                    - '.zsh_history'
                    - '_history'
                    - '.history'
                    - 'zhistory'
            filter:
                hostname|expand: '%hostname%'
            condition: selection and filter
        fields:
            - User
            - Image
            - CommandLine
            - TargetFilename
  - question: 'Were any suspicious files created or modified by the user who deleted the history file?'
    context: 'File creation/modification by the user could indicate persistence mechanisms or other malicious tools being deployed.'
    range: +/-30m
    answer_sources:
        - file_event
    query: |
        aggregation: false
        logsource:
          category: file_event
          product: linux
        detection:
            selection:
                User|expand: '%User%'
            filter:
                hostname|expand: '%hostname%'
            condition: selection and filter
        fields:
            - Image
            - CommandLine
            - TargetFilename`
	ProcessCreationPlaybook = `name: Sigma - Category - Process Creation
id: 4f1db62f-cb41-41fb-8af3-11a67585b5db
description: |
    Base Playbook for investigating process_creation-based alerts.
type: detection
detection_id: ''
detection_category: 'process_creation'
detection_type: 'sigma'
contributors:
  - 'SecurityOnionSolutions'
date: 2025-04-04
questions:
  - question: 'What was the exact process execution that triggered the alert?'
    context: 'Understanding the complete command line and process details provides crucial context about the activity.'
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: windows
        detection:
            selection:
               ProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - User
            - Image
            - CommandLine

  - question: 'What is the process lineage (parent process chain)?'
    context: 'The process creation chain helps understand how the process was spawned and identify potential abuse of legitimate processes.'
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: windows
        detection:
            selection:
               ProcessGuid|expand: '%ParentProcessGuid%'
            condition: selection
        fields:
            - User
            - ParentImage
            - Image
            - CommandLine

  - question: 'What child processes were spawned?'
    context: 'Child processes can indicate the full scope of the activity and subsequent actions taken.'
    range: +5m
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: windows
        detection:
            selection:
                ParentProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - Image
            - CommandLine

  - question: 'What files were accessed by the process?'
    context: 'File interactions can reveal what data or systems were targeted.'
    range: +/-5m
    answer_sources:
        - file_event
    query: |
        aggregation: false
        logsource:
          category: file_event
          product: windows
        detection:
            selection:
                ProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - Image
            - TargetFilename

  - question: 'What network connections were established by the process?'
    context: 'Network connections can indicate command and control activity or other malicious activity.'
    range: +/-15m
    answer_sources:
        - network_connection
    query: |
        aggregation: false
        logsource:
          category: network_connection
          product: windows
        detection:
            selection:
                ProcessGuid|expand: '%ProcessGuid%'
            condition: selection
        fields:
            - Image
            - DestinationIp
            - DestinationPort

  - question: 'Has this process executed on this host before?'
    context: 'Historical execution patterns help establish if this is normal behavior for this system.'
    range: -30d
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: windows
        detection:
            selection:
                Image|endswith|expand: '%Image%'
                hostname|expand: '%hostname%'
            condition: selection
        fields:
            - User
            - ParentImage
            - Image
            - CommandLine

  - question: 'What other processes were running around the same time?'
    context: 'Understanding the broader process execution context can reveal related suspicious activity.'
    range: +/-10m
    answer_sources:
        - process_creation
    query: |
        aggregation: false
        logsource:
          category: process_creation
          product: windows
        detection:
            selection:
                hostname|expand: '%hostname%'
            condition: selection
        fields:
            - User
            - ParentImage
            - Image
            - CommandLine`
)

func TestScheduler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	pdm := PlaybookDiskManager{
		srv:                server.NewFakeAuthorizedServer(nil),
		playbookRepoPath:   "/tmp/playbooks",
		playbookRepoUrl:    "https://github.com/playbooks/repo",
		playbookRepoBranch: "dev",
		interruptChan:      make(chan bool, 1),
		isRunning:          true,
		IOManager:          iom,
	}

	iom.EXPECT().ReadDir(pdm.playbookRepoPath).Return(nil, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "/tmp/playbooks/repo", pdm.playbookRepoUrl, util.Ptr(pdm.playbookRepoBranch)).Return(nil)

	iom.EXPECT().WalkDir("/tmp/playbooks/repo", gomock.Any()).DoAndReturn(func(path string, fn func(p string, dir fs.DirEntry, err error) error) error {
		err := fn("/tmp/playbooks/repo/playbook1.yaml", &handmock.MockDirEntry{
			Filename: "playbook1.yaml",
		}, nil)
		assert.NoError(t, err)

		err = fn("/tmp/playbooks/repo/playbook2.yaml", &handmock.MockDirEntry{
			Filename: "playbook2.yaml",
		}, nil)
		assert.NoError(t, err)

		err = fn("/tmp/playbooks/repo/playbook3.yaml", &handmock.MockDirEntry{
			Filename: "playbook3.yaml",
		}, nil)
		assert.NoError(t, err)

		return nil
	})

	iom.EXPECT().ReadFile("/tmp/playbooks/repo/playbook1.yaml").Return([]byte(SuricataPlaybook), nil)
	iom.EXPECT().ReadFile("/tmp/playbooks/repo/playbook2.yaml").Return([]byte(HistoryFileDeletionPlaybook), nil)
	iom.EXPECT().ReadFile("/tmp/playbooks/repo/playbook3.yaml").Return([]byte(ProcessCreationPlaybook), nil)

	iom.EXPECT().ReadDir(pdm.playbookRepoPath).DoAndReturn(func(path string) ([]fs.DirEntry, error) {
		pdm.isRunning = false
		return []fs.DirEntry{
			&handmock.MockDirEntry{
				Filename: "repo",
				Dir:      true,
			},
		}, nil
	})

	pdm.scheduler()

	assert.Equal(t, 1, len(pdm.PlaybooksByDetectionId))
	assert.NotNil(t, pdm.PlaybooksByDetectionId["1182f3b3-e716-4efa-99ab-d2685d04360f"])

	assert.Equal(t, 1, len(pdm.PlaybooksByCategory))
	assert.Equal(t, 1, len(pdm.PlaybooksByCategory["process_creation"]))
	assert.Equal(t, "4f1db62f-cb41-41fb-8af3-11a67585b5db", pdm.PlaybooksByCategory["process_creation"][0])

	assert.Equal(t, 1, len(pdm.PlaybooksByEngine))
	assert.Equal(t, 1, len(pdm.PlaybooksByEngine["suricata"]))
	assert.Equal(t, "1dfe7517-f105-454f-ae96-f2280c09e4b2", pdm.PlaybooksByEngine["suricata"][0])

	assert.Equal(t, 3, len(pdm.playbooksOnDisk))
	assert.Equal(t, "/tmp/playbooks/repo/playbook1.yaml", pdm.playbooksOnDisk["1dfe7517-f105-454f-ae96-f2280c09e4b2"])
	assert.Equal(t, "/tmp/playbooks/repo/playbook2.yaml", pdm.playbooksOnDisk["6f64990a-acda-40b6-ab71-134c073013b5"])
	assert.Equal(t, "/tmp/playbooks/repo/playbook3.yaml", pdm.playbooksOnDisk["4f1db62f-cb41-41fb-8af3-11a67585b5db"])
}

func TestGetPlaybooksForDetection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	pdm := PlaybookDiskManager{
		srv: server.NewFakeAuthorizedServer(nil),
		PlaybooksByDetectionId: map[string][]string{
			"1182f3b3-e716-4efa-99ab-d2685d04360f": {"6f64990a-acda-40b6-ab71-134c073013b5"},
		},
		PlaybooksByCategory: map[string][]string{
			"process_creation": {"4f1db62f-cb41-41fb-8af3-11a67585b5db"},
		},
		PlaybooksByEngine: map[string][]string{
			"suricata": {"1dfe7517-f105-454f-ae96-f2280c09e4b2"},
		},
		playbooksOnDisk: map[string]string{
			"6f64990a-acda-40b6-ab71-134c073013b5": "/path/6f6",
			"4f1db62f-cb41-41fb-8af3-11a67585b5db": "/path/4f1",
			"1dfe7517-f105-454f-ae96-f2280c09e4b2": "/path/1df",
		},
		IOManager: iom,
	}

	ctx := context.Background()

	iom.EXPECT().ReadFile("/path/6f6").Return([]byte("id: 6f64990a-acda-40b6-ab71-134c073013b5"), nil)
	playbooks, err := pdm.GetPlaybooksForDetection(ctx, "1182f3b3-e716-4efa-99ab-d2685d04360f", "web_request", model.EngineNameElastAlert)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "6f64990a-acda-40b6-ab71-134c073013b5", playbooks[0].Id)

	iom.EXPECT().ReadFile("/path/4f1").Return([]byte("id: 4f1db62f-cb41-41fb-8af3-11a67585b5db"), nil)
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "abc", "process_creation", model.EngineNameElastAlert)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "4f1db62f-cb41-41fb-8af3-11a67585b5db", playbooks[0].Id)

	iom.EXPECT().ReadFile("/path/1df").Return([]byte("id: 1dfe7517-f105-454f-ae96-f2280c09e4b2"), nil)
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "abc", "network_access", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "1dfe7517-f105-454f-ae96-f2280c09e4b2", playbooks[0].Id)

	iom.EXPECT().ReadFile("/path/6f6").Return([]byte("id: 6f64990a-acda-40b6-ab71-134c073013b5"), nil)
	iom.EXPECT().ReadFile("/path/4f1").Return([]byte("id: 4f1db62f-cb41-41fb-8af3-11a67585b5db"), nil)
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "1182F3B3-E716-4EFA-99AB-D2685D04360F", "PROCESS_CREATION", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(playbooks))
	assert.Equal(t, "6f64990a-acda-40b6-ab71-134c073013b5", playbooks[0].Id)
	assert.Equal(t, "4f1db62f-cb41-41fb-8af3-11a67585b5db", playbooks[1].Id)
}

func TestGetPlaybookById(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	pdm := PlaybookDiskManager{
		srv: server.NewFakeAuthorizedServer(nil),
		playbooksOnDisk: map[string]string{
			"1182f3b3-e716-4efa-99ab-d2685d04360f": "/path/118",
			"4f1db62f-cb41-41fb-8af3-11a67585b5db": "/path/4f1",
			"1dfe7517-f105-454f-ae96-f2280c09e4b2": "/path/1df",
		},
		IOManager: iom,
	}

	ctx := context.Background()

	iom.EXPECT().ReadFile("/path/118").Return([]byte("id: 1182f3b3-e716-4efa-99ab-d2685d04360f"), nil)
	playbook, err := pdm.GetPlaybookById(ctx, "1182f3b3-e716-4efa-99ab-d2685d04360f")
	assert.NoError(t, err)
	assert.Equal(t, "1182f3b3-e716-4efa-99ab-d2685d04360f", playbook.Id)

	iom.EXPECT().ReadFile("/path/4f1").Return([]byte("id: 4f1db62f-cb41-41fb-8af3-11a67585b5db"), nil)
	playbook, err = pdm.GetPlaybookById(ctx, "4f1db62f-cb41-41fb-8af3-11a67585b5db")
	assert.NoError(t, err)
	assert.Equal(t, "4f1db62f-cb41-41fb-8af3-11a67585b5db", playbook.Id)

	iom.EXPECT().ReadFile("/path/1df").Return([]byte("id: 1dfe7517-f105-454f-ae96-f2280c09e4b2"), nil)
	playbook, err = pdm.GetPlaybookById(ctx, "1dfe7517-f105-454f-ae96-f2280c09e4b2")
	assert.NoError(t, err)
	assert.Equal(t, "1dfe7517-f105-454f-ae96-f2280c09e4b2", playbook.Id)

	playbook, err = pdm.GetPlaybookById(ctx, "nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, playbook)
}

func TestConvertQuestions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	pdm := PlaybookDiskManager{
		srv:       server.NewFakeAuthorizedServer(nil),
		IOManager: iom,
	}

	iom.EXPECT().ExecCommand(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) ([]byte, int, time.Duration, error) {
		assert.True(t, strings.HasSuffix(cmd.Path, "sigma"))
		assert.Equal(t, []string{"sigma", "convert", "-t", "security_onion", "-p", "/opt/sensoroni/sigma_final_pipeline.yaml", "-p", "/opt/sensoroni/sigma_so_pipeline.yaml", "-p", "windows-logsources", "-p", "ecs_windows", "--disable-pipeline-check", "/dev/stdin"}, cmd.Args)

		in, err := io.ReadAll(cmd.Stdin)
		assert.NoError(t, err)
		assert.Equal(t, "query1\n---\nquery2", string(in))

		return []byte("Converted Queries:\n" + `{"query": "query1", "fields": ["a", "b"]}` + "\n\n" + `{"query": "query2", "fields": ["b", "c"]}` + "\n\n"), 0, time.Second, nil
	})

	converted, err := pdm.ConvertQuestions(context.Background(), []string{"query1", "query2"})
	assert.NoError(t, err)
	assert.Equal(t, 2, len(converted))
	assert.Equal(t, "query1", converted[0].Query)
	assert.Equal(t, "query2", converted[1].Query)
	assert.Equal(t, 2, len(converted[0].Fields))
	assert.Equal(t, 2, len(converted[1].Fields))
	assert.Equal(t, "a", converted[0].Fields[0])
	assert.Equal(t, "b", converted[0].Fields[1])
	assert.Equal(t, "b", converted[1].Fields[0])
	assert.Equal(t, "c", converted[1].Fields[1])
}

func TestReadPlaybooks(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	pdm := PlaybookDiskManager{
		isRunning:          true,
		playbookRepoUrl:    "http://github.com/user/repo",
		playbookPathInRepo: "playbooks/dev",
		playbookRepoPath:   "/tmp/playbooks",
		IOManager:          iom,
	}

	iom.EXPECT().WalkDir("/tmp/playbooks/repo/playbooks/dev", gomock.Any()).DoAndReturn(func(path string, fn func(p string, dir fs.DirEntry, err error) error) error {
		err := fn("does not exist", &handmock.MockDirEntry{}, errors.New("something went wrong"))
		assert.NoError(t, err)

		err = fn("bad info", &handmock.BadMockDirEntry{ErrorStr: "something went wrong"}, nil)
		assert.NoError(t, err)

		iom.EXPECT().ReadFile("cannot be read").Return(nil, errors.New("something went wrong"))
		err = fn("cannot be read", &handmock.MockDirEntry{Filename: "a.yml"}, nil)
		assert.NoError(t, err)

		iom.EXPECT().ReadFile("unmarshal error").Return([]byte("&"), nil)
		err = fn("unmarshal error", &handmock.MockDirEntry{Filename: "a.yml"}, nil)
		assert.NoError(t, err)

		iom.EXPECT().ReadFile("success").Return([]byte("id: x"), nil)
		err = fn("success", &handmock.MockDirEntry{Filename: "a.yml"}, nil)
		assert.NoError(t, err)

		return nil
	})

	h := memory.New()
	lg := &log.Logger{Handler: h, Level: log.DebugLevel}
	logger := lg.WithField("test", true)

	pbs, err := pdm.readPlaybooks(logger)
	assert.NoError(t, err)
	assert.Len(t, pbs, 1)
	assert.Equal(t, "x", pbs[0].Id)

	assert.Equal(t, 1, len(pdm.playbooksOnDisk))
	assert.Equal(t, "success", pdm.playbooksOnDisk["x"])
}
