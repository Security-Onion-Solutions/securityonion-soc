// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
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
created: 2025-3-12
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
created: 2025-04-21
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
created: 2025-04-04
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
		srv:               server.NewFakeAuthorizedServer(nil),
		autoUpdateEnabled: true,
		playbookRepoPath:  "/tmp/playbooks",
		playbookRepos: []*model.Repo{
			{
				RepoUrl: "https://github.com/playbooks/repo",
				Branch:  util.Ptr("dev"),
			},
		},
		interruptChan: make(chan bool, 1),
		isRunning:     true,
		IOManager:     iom,
	}

	iom.EXPECT().ReadDir(pdm.playbookRepoPath).Return(nil, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "/tmp/playbooks/repo", pdm.playbookRepos[0].RepoUrl, pdm.playbookRepos[0].Branch).Return(nil)

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

	// Maps now store file paths instead of playbook IDs
	assert.Equal(t, 1, len(pdm.PlaybooksByCategory))
	assert.Equal(t, 1, len(pdm.PlaybooksByCategory["process_creation"]))
	assert.Equal(t, "/tmp/playbooks/repo/playbook3.yaml", pdm.PlaybooksByCategory["process_creation"][0])

	assert.Equal(t, 1, len(pdm.PlaybooksByEngine))
	assert.Equal(t, 1, len(pdm.PlaybooksByEngine["suricata"]))
	assert.Equal(t, "/tmp/playbooks/repo/playbook1.yaml", pdm.PlaybooksByEngine["suricata"][0])

	assert.Equal(t, 3, len(pdm.playbooksOnDisk))
	assert.Equal(t, "/tmp/playbooks/repo/playbook1.yaml", pdm.playbooksOnDisk["1dfe7517-f105-454f-ae96-f2280c09e4b2"])
	assert.Equal(t, "/tmp/playbooks/repo/playbook2.yaml", pdm.playbooksOnDisk["6f64990a-acda-40b6-ab71-134c073013b5"])
	assert.Equal(t, "/tmp/playbooks/repo/playbook3.yaml", pdm.playbooksOnDisk["4f1db62f-cb41-41fb-8af3-11a67585b5db"])
}

func TestGetPlaybooksForDetection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	// Maps now store file paths directly instead of playbook IDs
	pdm := PlaybookDiskManager{
		srv: server.NewFakeAuthorizedServer(nil),
		PlaybooksByDetectionId: map[string][]string{
			"1182f3b3-e716-4efa-99ab-d2685d04360f": {"/path/6f6"},
		},
		PlaybooksByCategory: map[string][]string{
			"process_creation": {"/path/4f1", "/path/4f1_nids"},
		},
		PlaybooksByEngine: map[string][]string{
			"suricata": {"/path/1df"},
		},
		playbooksOnDisk: map[string]string{
			"6f64990a-acda-40b6-ab71-134c073013b5": "/path/6f6",
			"4f1db62f-cb41-41fb-8af3-11a67585b5db": "/path/4f1",
			"1dfe7517-f105-454f-ae96-f2280c09e4b2": "/path/1df",
			"4f1db62f-nids":                        "/path/4f1_nids",
		},
		playbookTypes: map[string]string{
			"/path/4f1":      "sigma",
			"/path/4f1_nids": "nids",
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
	iom.EXPECT().ReadFile("/path/4f1_nids").Return([]byte("id: 4f1db62f-nids"), nil)
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "1182F3B3-E716-4EFA-99AB-D2685D04360F", "PROCESS_CREATION", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(playbooks))
	assert.Equal(t, "6f64990a-acda-40b6-ab71-134c073013b5", playbooks[0].Id)
	assert.Equal(t, "4f1db62f-nids", playbooks[1].Id)
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
		isRunning:        true,
		playbookRepoPath: "/tmp/playbooks",
		IOManager:        iom,
	}

	repos := []*detections.RepoOnDisk{
		{
			Repo: &model.Repo{
				RepoUrl: "http://github.com/user/repo",
				Folder:  util.Ptr("playbooks/dev"),
			},
			Path: "/tmp/playbooks/repo",
		},
		{
			Repo: &model.Repo{
				RepoUrl: "file:///playbooks/myRepo",
			},
			Path: "/tmp/playbooks/myRepo",
		},
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

		iom.EXPECT().ReadFile("success").Return([]byte("id: repo1-pb1"), nil)
		err = fn("success", &handmock.MockDirEntry{Filename: "a.yml"}, nil)
		assert.NoError(t, err)

		return nil
	})

	iom.EXPECT().WalkDir("/tmp/playbooks/myRepo", gomock.Any()).DoAndReturn(func(path string, fn func(p string, dir fs.DirEntry, err error) error) error {
		iom.EXPECT().ReadFile("repo2-playbook1.yaml").Return([]byte("id: repo2-pb1"), nil)
		err := fn("repo2-playbook1.yaml", &handmock.MockDirEntry{Filename: "repo2-playbook1.yaml"}, nil)
		assert.NoError(t, err)

		iom.EXPECT().ReadFile("repo2-playbook2.yaml").Return([]byte("id: repo2-pb2"), nil)
		err = fn("repo2-playbook2.yaml", &handmock.MockDirEntry{Filename: "repo2-playbook2.yaml"}, nil)
		assert.NoError(t, err)

		return nil
	})

	h := memory.New()
	lg := &log.Logger{Handler: h, Level: log.DebugLevel}
	logger := lg.WithField("test", true)

	pbs, err := pdm.readPlaybooks(logger, repos)
	assert.NoError(t, err)
	assert.Len(t, pbs, 3)

	// Verify playbooks from both repos are loaded
	playbookIds := make([]string, len(pbs))
	for i, pb := range pbs {
		playbookIds[i] = pb.Id
	}
	assert.Contains(t, playbookIds, "repo1-pb1")
	assert.Contains(t, playbookIds, "repo2-pb1")
	assert.Contains(t, playbookIds, "repo2-pb2")

	assert.Equal(t, 3, len(pdm.playbooksOnDisk))
	assert.Equal(t, "success", pdm.playbooksOnDisk["repo1-pb1"])
	assert.Equal(t, "repo2-playbook1.yaml", pdm.playbooksOnDisk["repo2-pb1"])
	assert.Equal(t, "repo2-playbook2.yaml", pdm.playbooksOnDisk["repo2-pb2"])
}

func TestGetPlaybooksForDetection_BaseCategoryMatching(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	// Maps now store file paths directly instead of playbook IDs
	pdm := PlaybookDiskManager{
		srv:                    server.NewFakeAuthorizedServer(nil),
		PlaybooksByDetectionId: map[string][]string{},
		PlaybooksByCategory: map[string][]string{
			"scan":    {"/path/scan", "/path/sigma-scan"},
			"et scan": {"/path/et-scan"},
			"sql":     {"/path/sql"},
			"generic": {"/path/generic"},
		},
		PlaybooksByEngine: map[string][]string{},
		playbooksOnDisk: map[string]string{
			"scan-playbook":       "/path/scan",
			"sigma-scan-playbook": "/path/sigma-scan",
			"et-scan-playbook":    "/path/et-scan",
			"sql-playbook":        "/path/sql",
			"generic-playbook":    "/path/generic",
		},
		playbookTypes: map[string]string{
			"/path/scan":       "nids",
			"/path/sigma-scan": "sigma",
			"/path/et-scan":    "nids",
			"/path/sql":        "nids",
			// /path/generic has no type - should match any engine
		},
		IOManager: iom,
	}

	ctx := context.Background()

	// Set up expectations for all possible file reads
	iom.EXPECT().ReadFile("/path/et-scan").Return([]byte("id: et-scan-playbook"), nil).AnyTimes()
	iom.EXPECT().ReadFile("/path/scan").Return([]byte("id: scan-playbook"), nil).AnyTimes()
	iom.EXPECT().ReadFile("/path/sigma-scan").Return([]byte("id: sigma-scan-playbook"), nil).AnyTimes()
	iom.EXPECT().ReadFile("/path/sql").Return([]byte("id: sql-playbook"), nil).AnyTimes()
	iom.EXPECT().ReadFile("/path/generic").Return([]byte("id: generic-playbook"), nil).AnyTimes()

	// Test case 1: NIDS engine with "ET SCAN" category should match both "et scan" and NIDS "scan" (but not Sigma "scan")
	playbooks, err := pdm.GetPlaybooksForDetection(ctx, "", "ET SCAN", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(playbooks))
	assert.Equal(t, "et-scan-playbook", playbooks[0].Id)
	assert.Equal(t, "scan-playbook", playbooks[1].Id)

	// Test case 2: NIDS engine with "GPL SQL" category should match "sql"
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "", "GPL SQL", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "sql-playbook", playbooks[0].Id)

	// Test case 3: Non-NIDS engine should not do base category matching and should filter exact matches by type
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "", "ET SCAN", model.EngineNameElastAlert)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(playbooks)) // No matches since et-scan-playbook is NIDS type

	// Test case 4: Single word category with exact match should only return NIDS playbook for NIDS engine
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "", "scan", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "scan-playbook", playbooks[0].Id)

	// Test case 5: Verify Sigma detection gets only the Sigma playbook for "scan" category
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "", "scan", model.EngineNameElastAlert)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "sigma-scan-playbook", playbooks[0].Id)

	// Test case 6: Verify playbooks without detection_type are included for any engine (backward compatibility)
	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "", "generic", model.EngineNameSuricata)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "generic-playbook", playbooks[0].Id)

	playbooks, err = pdm.GetPlaybooksForDetection(ctx, "", "generic", model.EngineNameElastAlert)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(playbooks))
	assert.Equal(t, "generic-playbook", playbooks[0].Id)
}

func TestExecutePlaybookSearches(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		event           *model.EventRecord
		playbooks       []*model.Playbook
		convertResults  []*model.ConvertedQuery
		convertError    error
		searchResults   *model.EventSearchResults
		searchError     error
		expectedError   string
		verifyQuestions func(t *testing.T, playbooks []*model.Playbook)
	}{
		{
			name: "successful execution with range question",
			event: &model.EventRecord{
				Id: "test-event-1",
				Payload: map[string]interface{}{
					"hostname":  "test-host",
					"user.name": "test-user",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "test-playbook"},
					Questions: []*model.Question{
						{
							Question:      "What processes were executed?",
							Context:       "Test context",
							Range:         util.Ptr("-1h"),
							AnswerSources: []string{"process_creation"},
							Query:         "hostname: {hostname}",
						},
					},
				},
			},
			convertResults: []*model.ConvertedQuery{
				{
					Query:  "hostname: test-host",
					Fields: []string{"Image", "CommandLine"},
				},
			},
			searchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "search-result-1",
						Payload: map[string]interface{}{
							"Image":       "notepad.exe",
							"CommandLine": "notepad.exe file.txt",
						},
					},
				},
			},
			verifyQuestions: func(t *testing.T, playbooks []*model.Playbook) {
				assert.Len(t, playbooks[0].Questions, 1)
				question := playbooks[0].Questions[0]
				assert.Equal(t, "hostname: test-host", question.FilledQuery)
				assert.Len(t, question.QueryResults, 1)
				assert.Equal(t, "search-result-1", question.QueryResults[0].Id)
			},
		},
		{
			name: "successful execution without range",
			event: &model.EventRecord{
				Id: "test-event-2",
				Payload: map[string]interface{}{
					"src_ip": "10.0.0.1",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "alert-playbook"},
					Questions: []*model.Question{
						{
							Question:      "What is the alert content?",
							Context:       "Show alert details",
							Range:         nil, // No range - should use original event
							AnswerSources: []string{"alert"},
							Query:         "src_ip: {src_ip}",
						},
					},
				},
			},
			convertResults: []*model.ConvertedQuery{
				{
					Query:  "src_ip: 10.0.0.1",
					Fields: []string{"rule.name", "rule.category"},
				},
			},
			// searchResults not used since Range is nil
			verifyQuestions: func(t *testing.T, playbooks []*model.Playbook) {
				assert.Len(t, playbooks[0].Questions, 1)
				question := playbooks[0].Questions[0]
				assert.Equal(t, "src_ip: 10.0.0.1", question.FilledQuery)
				assert.Len(t, question.QueryResults, 1)
				assert.Equal(t, "test-event-2", question.QueryResults[0].Id)
			},
		},
		{
			name: "authorization error",
			event: &model.EventRecord{
				Id:      "test-event-3",
				Payload: map[string]interface{}{},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "test-playbook"},
					Questions: []*model.Question{
						{
							Question: "Test question",
							Query:    "test query",
						},
					},
				},
			},
			expectedError: "not authorized", // Will be set by unauthorized server
		},
		{
			name: "convert questions error",
			event: &model.EventRecord{
				Id:      "test-event-4",
				Payload: map[string]interface{}{},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "test-playbook"},
					Questions: []*model.Question{
						{
							Question: "Test question",
							Query:    "invalid query",
						},
					},
				},
			},
			convertError:  errors.New("sigma conversion failed"),
			expectedError: "sigma conversion failed",
		},
		{
			name: "eventstore search error",
			event: &model.EventRecord{
				Id:      "test-event-6",
				Payload: map[string]interface{}{},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "test-playbook"},
					Questions: []*model.Question{
						{
							Question: "Test question",
							Range:    util.Ptr("-1h"),
							Query:    "test query",
						},
					},
				},
			},
			convertResults: []*model.ConvertedQuery{
				{
					Query:  "valid_field: value",
					Fields: []string{"field1"},
				},
			},
			searchError:   errors.New("elasticsearch connection failed"),
			expectedError: "elasticsearch connection failed",
		},
		{
			name: "multiple questions with mixed ranges",
			event: &model.EventRecord{
				Id: "test-event-7",
				Payload: map[string]interface{}{
					"hostname": "multi-host",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "multi-question-playbook"},
					Questions: []*model.Question{
						{
							Question: "Alert details",
							Range:    nil, // No range
							Query:    "hostname: {hostname}",
						},
						{
							Question: "Historical data",
							Range:    util.Ptr("-24h"),
							Query:    "hostname: {hostname}",
						},
					},
				},
			},
			convertResults: []*model.ConvertedQuery{
				{Query: "hostname: multi-host", Fields: []string{"field1"}},
				{Query: "hostname: multi-host", Fields: []string{"field2"}},
			},
			searchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{Id: "historical-1"},
					{Id: "historical-2"},
				},
			},
			verifyQuestions: func(t *testing.T, playbooks []*model.Playbook) {
				assert.Len(t, playbooks[0].Questions, 2)

				// First question (no range) should use original event
				question1 := playbooks[0].Questions[0]
				assert.Len(t, question1.QueryResults, 1)
				assert.Equal(t, "test-event-7", question1.QueryResults[0].Id)

				// Second question (with range) should use search results
				question2 := playbooks[0].Questions[1]
				assert.Len(t, question2.QueryResults, 2)
				assert.Equal(t, "historical-1", question2.QueryResults[0].Id)
				assert.Equal(t, "historical-2", question2.QueryResults[1].Id)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			iom := mock.NewMockIOManager(ctrl)

			var srv *server.Server
			if tc.expectedError == "not authorized" {
				srv = server.NewFakeUnauthorizedServer()
			} else {
				srv = server.NewFakeAuthorizedServer(nil)

				// Set up fake eventstore if we need search functionality
				if tc.searchResults != nil || tc.searchError != nil {
					fakeEventstore := server.NewFakeEventstore()
					if tc.searchResults != nil {
						fakeEventstore.SearchResults = []*model.EventSearchResults{tc.searchResults}
					}
					if tc.searchError != nil {
						fakeEventstore.Err = tc.searchError
					}
					srv.Eventstore = fakeEventstore
				}
			}

			pdm := PlaybookDiskManager{
				srv:       srv,
				IOManager: iom,
			}

			// Set up ConvertQuestions expectations
			if tc.convertResults != nil || tc.convertError != nil {
				// Mock ExecCommand for ConvertQuestions
				iom.EXPECT().ExecCommand(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) ([]byte, int, time.Duration, error) {
					if tc.convertError != nil {
						return nil, 1, time.Second, tc.convertError
					}

					// Build response with converted queries
					var responses []string
					for _, result := range tc.convertResults {
						jsonBytes, _ := json.Marshal(result)
						responses = append(responses, string(jsonBytes))
					}

					output := "Converted Queries:\n" + strings.Join(responses, "\n") + "\n"
					return []byte(output), 0, time.Second, nil
				}).AnyTimes()
			}

			// Execute the function
			err := pdm.ExecutePlaybookSearches(ctx, tc.event, tc.playbooks)

			// Verify results
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				if tc.verifyQuestions != nil {
					tc.verifyQuestions(t, tc.playbooks)
				}

				for _, pb := range tc.playbooks {
					for _, q := range pb.Questions {
						assert.NotEmpty(t, q.FilledQuery, "FilledQuery should not be empty")
						assert.NotEmpty(t, q.QueryFields, "QueryFields should not be empty")
					}
				}
			}
		})
	}
}

func TestQueryVariableSubstitution(t *testing.T) {
	tests := []struct {
		name      string
		event     *model.EventRecord
		playbooks []*model.Playbook
		expected  map[string]string // playbook ID -> expected filled query
	}{
		{
			name: "basic variable substitution",
			event: &model.EventRecord{
				Payload: map[string]interface{}{
					"hostname":  "test-host",
					"user.name": "admin",
					"src_ip":    "192.168.1.10",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "basic-test"},
					Questions: []*model.Question{
						{
							Query: "hostname: {hostname} AND user: {user.name} AND src_ip: {src_ip}",
						},
					},
				},
			},
			expected: map[string]string{
				"basic-test": "hostname: test-host AND user: admin AND src_ip: 192.168.1.10",
			},
		},
		{
			name: "missing variable replacement with NODATA",
			event: &model.EventRecord{
				Payload: map[string]interface{}{
					"hostname": "test-host",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "missing-var-test"},
					Questions: []*model.Question{
						{
							Query: "hostname: {hostname} AND missing: {missing_field}",
						},
					},
				},
			},
			expected: map[string]string{
				"missing-var-test": "hostname: test-host AND missing: NODATA",
			},
		},
		{
			name: "array field handling for special fields",
			event: &model.EventRecord{
				Payload: map[string]interface{}{
					"related.ip": []interface{}{"10.0.0.1", "192.168.1.1"},
					"hostname":   "test-host",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "array-test"},
					Questions: []*model.Question{
						{
							Query: `hostname: {hostname}
related.ip: {related.ip}`,
						},
					},
				},
			},
			expected: map[string]string{
				"array-test": `hostname: test-host
related.ip:
    - 10.0.0.1
    - 192.168.1.1`,
			},
		},
		{
			name: "array field fallback to comma-separated for non-special fields",
			event: &model.EventRecord{
				Payload: map[string]interface{}{
					"tags":     []interface{}{"malware", "suspicious"},
					"hostname": "test-host",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "array-fallback-test"},
					Questions: []*model.Question{
						{
							Query: "hostname: {hostname} AND tags: {tags}",
						},
					},
				},
			},
			expected: map[string]string{
				"array-fallback-test": "hostname: test-host AND tags: malware,suspicious",
			},
		},
		{
			name: "complex array field handling with indentation",
			event: &model.EventRecord{
				Payload: map[string]interface{}{
					"network.private_ip": []interface{}{"10.0.0.1", "10.0.0.2", "172.16.0.1"},
					"hostname":           "test-host",
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "complex-array-test"},
					Questions: []*model.Question{
						{
							Query: `logsource:
  category: network
detection:
  selection:
    hostname: {hostname}
    network.private_ip: {network.private_ip}
  condition: selection`,
						},
					},
				},
			},
			expected: map[string]string{
				"complex-array-test": `logsource:
  category: network
detection:
  selection:
    hostname: test-host
    network.private_ip:
        - 10.0.0.1
        - 10.0.0.2
        - 172.16.0.1
  condition: selection`,
			},
		},
		{
			name: "multiple playbooks variable substitution",
			event: &model.EventRecord{
				Payload: map[string]interface{}{
					"src_ip":   "1.2.3.4",
					"dst_port": 443,
				},
			},
			playbooks: []*model.Playbook{
				{
					Auditable: model.Auditable{Id: "playbook-1"},
					Questions: []*model.Question{
						{
							Query: "src_ip: {src_ip}",
						},
					},
				},
				{
					Auditable: model.Auditable{Id: "playbook-2"},
					Questions: []*model.Question{
						{
							Query: "dst_port: {dst_port} AND src_ip: {src_ip}",
						},
					},
				},
			},
			expected: map[string]string{
				"playbook-1": "src_ip: 1.2.3.4",
				"playbook-2": "dst_port: 443 AND src_ip: 1.2.3.4",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Execute variable substitution
			queryVariableSubstitution(tc.event, tc.playbooks)

			// Verify results
			for _, pb := range tc.playbooks {
				expectedQuery, exists := tc.expected[pb.Id]
				assert.True(t, exists, "Expected result not found for playbook %s", pb.Id)

				assert.Len(t, pb.Questions, 1, "Expected exactly one question for playbook %s", pb.Id)
				actualQuery := pb.Questions[0].FilledQuery

				assert.Equal(t, expectedQuery, actualQuery, "Filled query mismatch for playbook %s", pb.Id)
			}
		})
	}
}

func TestGetEventTimestamp(t *testing.T) {
	testCases := []struct {
		name          string
		event         *model.EventRecord
		expectedTime  time.Time
		shouldBeEmpty bool
	}{
		{
			name: "event with @timestamp field",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "2024-01-15T14:30:45.123Z",
					"source.ip":  "10.0.0.1",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 123000000, time.UTC),
		},
		{
			name: "event with event_data.@timestamp field (higher priority)",
			event: &model.EventRecord{
				Payload: map[string]any{
					"event_data.@timestamp": "2024-01-15T14:30:45.123Z",
					"@timestamp":            "2024-01-15T12:00:00.000Z",
					"soc_timestamp":         "2024-01-15T10:00:00.000Z",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 123000000, time.UTC),
		},
		{
			name: "event with soc_timestamp field",
			event: &model.EventRecord{
				Payload: map[string]any{
					"soc_timestamp": "2024-01-15T14:30:45Z",
					"source.ip":     "10.0.0.1",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
		},
		{
			name: "event with RFC3339Nano format",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "2024-01-15T14:30:45.123456789Z",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 123456789, time.UTC),
		},
		{
			name: "event with custom format '2006-01-02T15:04:05.000Z'",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "2024-01-15T14:30:45.123Z",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 123000000, time.UTC),
		},
		{
			name: "event with simple format '2006-01-02T15:04:05Z'",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "2024-01-15T14:30:45Z",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
		},
		{
			name: "event with format '2006-01-02 15:04:05'",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "2024-01-15 14:30:45",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
		},
		{
			name: "fallback to event.Time field",
			event: &model.EventRecord{
				Time: time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
				Payload: map[string]any{
					"source.ip": "10.0.0.1",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
		},
		{
			name: "prefer payload timestamp over event.Time",
			event: &model.EventRecord{
				Time: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
				Payload: map[string]any{
					"@timestamp": "2024-01-15T14:30:45Z",
				},
			},
			expectedTime: time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
		},
		{
			name: "empty timestamp field",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "",
					"source.ip":  "10.0.0.1",
				},
			},
			shouldBeEmpty: true,
		},
		{
			name: "non-string timestamp field",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": 1234567890,
					"source.ip":  "10.0.0.1",
				},
			},
			shouldBeEmpty: true,
		},
		{
			name: "invalid timestamp format",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": "invalid-time-format",
				},
			},
			shouldBeEmpty: true,
		},
		{
			name: "no timestamp fields and empty event.Time",
			event: &model.EventRecord{
				Payload: map[string]any{
					"source.ip": "10.0.0.1",
				},
			},
			shouldBeEmpty: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getEventTimestamp(tc.event)

			if tc.shouldBeEmpty {
				assert.True(t, result.IsZero(), "Expected zero time")
			} else {
				assert.Equal(t, tc.expectedTime.UTC(), result.UTC(), "Timestamp mismatch")
			}
		})
	}
}

func TestBuildQuestionRange(t *testing.T) {
	// Fixed timestamp for testing
	fixedTime := time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC)

	testCases := []struct {
		name           string
		event          *model.EventRecord
		rangeStr       string
		timezone       string
		expectedResult string
		shouldBeEmpty  bool
	}{
		{
			name: "empty range string",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr:      "",
			timezone:      "UTC",
			shouldBeEmpty: true,
		},
		{
			name: "event with zero timestamp",
			event: &model.EventRecord{
				Payload: map[string]any{
					"source.ip": "10.0.0.1",
				},
			},
			rangeStr:      "1h",
			timezone:      "UTC",
			shouldBeEmpty: true,
		},
		{
			name: "plus/minus range - 1 hour",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "+/-1h",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Add(-1*time.Hour).Format(time.RFC3339),
				fixedTime.Add(1*time.Hour).Format(time.RFC3339)),
		},
		{
			name: "plus/minus range - 30 minutes",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "+/-30m",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Add(-30*time.Minute).Format(time.RFC3339),
				fixedTime.Add(30*time.Minute).Format(time.RFC3339)),
		},
		{
			name: "plus/minus range - 2 days",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "+/-2d",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Add(-48*time.Hour).Format(time.RFC3339),
				fixedTime.Add(48*time.Hour).Format(time.RFC3339)),
		},
		{
			name: "looking back range - 2 hours",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "-2h",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Add(-2*time.Hour).Format(time.RFC3339),
				fixedTime.Format(time.RFC3339)),
		},
		{
			name: "looking back range - 15 minutes",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "-15m",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Add(-15*time.Minute).Format(time.RFC3339),
				fixedTime.Format(time.RFC3339)),
		},
		{
			name: "forward range - 3 hours",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "3h",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Format(time.RFC3339),
				fixedTime.Add(3*time.Hour).Format(time.RFC3339)),
		},
		{
			name: "forward range - 45 seconds",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "45s",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Format(time.RFC3339),
				fixedTime.Add(45*time.Second).Format(time.RFC3339)),
		},
		{
			name: "timezone conversion - EST",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "+/-1h",
			timezone: "America/New_York",
			expectedResult: func() string {
				loc, _ := time.LoadLocation("America/New_York")
				localTime := fixedTime.In(loc)
				return fmt.Sprintf("%s - %s",
					localTime.Add(-1*time.Hour).Format(time.RFC3339),
					localTime.Add(1*time.Hour).Format(time.RFC3339))
			}(),
		},
		{
			name: "invalid timezone falls back to UTC",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "+/-1h",
			timezone: "Invalid/Timezone",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Add(-1*time.Hour).Format(time.RFC3339),
				fixedTime.Add(1*time.Hour).Format(time.RFC3339)),
		},
		{
			name: "range too short",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr:      "h",
			timezone:      "UTC",
			shouldBeEmpty: true,
		},
		{
			name: "invalid unit",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr:      "1x",
			timezone:      "UTC",
			shouldBeEmpty: true,
		},
		{
			name: "invalid number",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr:      "abch",
			timezone:      "UTC",
			shouldBeEmpty: true,
		},
		{
			name: "zero value",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "0h",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Format(time.RFC3339),
				fixedTime.Format(time.RFC3339)),
		},
		{
			name: "large value",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "999d",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Format(time.RFC3339),
				fixedTime.Add(999*24*time.Hour).Format(time.RFC3339)),
		},
		{
			name: "case insensitive units",
			event: &model.EventRecord{
				Payload: map[string]any{
					"@timestamp": fixedTime.Format(time.RFC3339),
				},
			},
			rangeStr: "1H",
			timezone: "UTC",
			expectedResult: fmt.Sprintf("%s - %s",
				fixedTime.Format(time.RFC3339),
				fixedTime.Add(1*time.Hour).Format(time.RFC3339)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildQuestionRange(tc.event, tc.rangeStr, tc.timezone)

			if tc.shouldBeEmpty {
				assert.Empty(t, result, "Expected empty result")
			} else {
				assert.Equal(t, tc.expectedResult, result, "Range mismatch")
			}
		})
	}
}
