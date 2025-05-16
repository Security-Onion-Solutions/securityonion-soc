// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestDetermineWaitTimeNoState(t *testing.T) {
	ctrl := gomock.NewController(t)
	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ReadFile("state").Return(nil, fs.ErrNotExist)

	lastImport, dur := DetermineWaitTime(iom, "state", time.Minute)

	assert.Nil(t, lastImport, "Expected lastImport to be nil")
	assert.Equal(t, time.Minute*20, dur, "Expected duration to be 20 minutes")
}

func TestDetermineWaitTime(t *testing.T) {
	ctrl := gomock.NewController(t)
	iom := mock.NewMockIOManager(ctrl)

	tenSecAgo := time.Now().Unix() - 10
	tenSecAgoStr := strconv.FormatInt(tenSecAgo, 10)

	iom.EXPECT().ReadFile("state").Return([]byte(tenSecAgoStr), nil)

	lastImport, dur := DetermineWaitTime(iom, "state", time.Minute)
	assert.NotNil(t, lastImport, "Expected lastImport not to be nil")
	assert.InEpsilon(t, time.Duration(time.Second*50), dur, 1)
}

func TestDetermineWaitTimeBadRead(t *testing.T) {
	ctrl := gomock.NewController(t)
	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ReadFile("state").Return(nil, errors.New("bad read"))
	iom.EXPECT().DeleteFile("state").Return(nil)

	lastImport, dur := DetermineWaitTime(iom, "state", time.Minute)
	assert.Nil(t, lastImport, "Expected lastImport to be nil")
	assert.Equal(t, time.Duration(time.Minute*20), dur)
}

func TestDetermineWaitTimeBadValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ReadFile("state").Return([]byte("bad"), nil)
	iom.EXPECT().DeleteFile("state").Return(nil)

	lastImport, dur := DetermineWaitTime(iom, "state", time.Minute)
	assert.Nil(t, lastImport, "Expected lastImport to be nil")
	assert.Equal(t, time.Duration(time.Minute*20), dur)
}

func TestWriteStateFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().WriteFile("state", gomock.Any(), fs.FileMode(0644)).DoAndReturn(func(path string, contents []byte, perm fs.FileMode) error {
		unix, err := strconv.ParseInt(string(contents), 10, 64)
		assert.NoError(t, err)
		assert.InEpsilon(t, time.Now().Unix(), unix, 2)

		return nil
	})

	WriteStateFile(iom, "state")
}

func TestCheckWriteNoRead(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	id := util.Ptr("99999")
	ctx := context.Background()

	iom := servermock.NewMockDetectionstore(ctrl)

	// No pending ID to read
	shouldFail := CheckWriteNoRead(ctx, iom, nil)
	assert.False(t, shouldFail)

	// Error querying ES
	iom.EXPECT().GetDetectionByPublicId(gomock.Any(), *id).Return(nil, errors.New("connection error"))

	shouldFail = CheckWriteNoRead(ctx, iom, id)
	assert.True(t, shouldFail)

	// Detection still not found
	iom.EXPECT().GetDetectionByPublicId(gomock.Any(), *id).Return(nil, nil)

	shouldFail = CheckWriteNoRead(ctx, iom, id)
	assert.True(t, shouldFail)

	// Successfully read back the missing ID
	iom.EXPECT().GetDetectionByPublicId(gomock.Any(), *id).Return(&model.Detection{}, nil)

	shouldFail = CheckWriteNoRead(ctx, iom, id)
	assert.False(t, shouldFail)
}

func TestAddUser(t *testing.T) {
	user := model.User{
		FirstName: "fn",
		LastName:  "ln",
		Email:     "em",
	}
	assert.Equal(t, "foo bar, fn ln", AddUser("foo bar", &user, ", "))

	user.FirstName = ""
	user.LastName = ""
	assert.Equal(t, "foo bar, em", AddUser("foo bar", &user, ", "))

	user.Email = ""
	assert.Equal(t, "foo bar", AddUser("foo bar", &user, ", "))

	user.FirstName = "foo"
	user.LastName = "bar"
	assert.Equal(t, "foo bar", AddUser("foo bar", &user, ", "))
}

func TestEscapeDoubleQuotes(t *testing.T) {
	tests := []struct {
		Name      string
		Input     string
		ExpOutput string
	}{
		{
			Name:      "Nothing to escape",
			Input:     "ab",
			ExpOutput: "ab",
		},
		{
			Name:      "Simple",
			Input:     `a"b`,
			ExpOutput: `a\"b`,
		},
		{
			Name:      "Pre-Escaped (No Change)",
			Input:     `a\"b`,
			ExpOutput: `a\"b`,
		},
		{
			Name:      "Complicated",
			Input:     `a\\"b`,
			ExpOutput: `a\\\"b`,
		},
		{
			Name:      "Complicated Pre-Escaped (No Change)",
			Input:     `a\\\"b`,
			ExpOutput: `a\\\"b`,
		},
		{
			Name:      "Multiple Quotes",
			Input:     `a"b"c`,
			ExpOutput: `a\"b\"c`,
		},
		{
			Name:      "Only Quotes",
			Input:     `"""`,
			ExpOutput: `\"\"\"`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			escaped := EscapeDoubleQuotes(test.Input)
			assert.Equal(t, test.ExpOutput, escaped)
		})
	}
}

func TestProxyToTransportOptions(t *testing.T) {
	tests := []struct {
		Name     string
		Proxy    string
		Opts     transport.ProxyOptions
		ExpError *string
	}{
		{
			Name:  "Empty",
			Proxy: "",
			Opts:  transport.ProxyOptions{},
		},
		{
			Name:  "No Auth",
			Proxy: "http://localhost:8080",
			Opts: transport.ProxyOptions{
				URL: "http://localhost:8080",
			},
		},
		{
			Name:  "No Port",
			Proxy: "http://proxyHost",
			Opts: transport.ProxyOptions{
				URL: "http://proxyHost",
			},
		},
		{
			Name:  "With Auth",
			Proxy: "http://user:pass@proxyHost:3128",
			Opts: transport.ProxyOptions{
				URL:      "http://proxyHost:3128",
				Username: "user",
				Password: "pass",
			},
		},
		{
			Name:  "Assume HTTP Schema",
			Proxy: "proxyHost",
			Opts: transport.ProxyOptions{
				URL: "http://proxyHost",
			},
		},
		{
			Name:     "Invalid URL",
			Proxy:    "%",
			ExpError: util.Ptr(`parse "%": invalid URL escape "%"`),
			Opts:     transport.ProxyOptions{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			opts, err := proxyToTransportOptions(test.Proxy)
			if test.ExpError != nil {
				assert.Error(t, err)
				assert.Equal(t, *test.ExpError, err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, test.Opts, opts)
		})
	}
}

func TestDeduplicateByPublicId(t *testing.T) {
	tests := []struct {
		Name      string
		InputIds  []string
		ExpOutput []string
	}{
		{
			Name:      "Empty",
			InputIds:  []string{},
			ExpOutput: []string{},
		},
		{
			Name:      "No Duplicates",
			InputIds:  []string{"1", "2", "3"},
			ExpOutput: []string{"1", "2", "3"},
		},
		{
			Name:      "Only Duplicates",
			InputIds:  []string{"1", "1", "1", "1", "1", "1", "1", "1", "1", "1"},
			ExpOutput: []string{"1"},
		},
		{
			Name:      "Mixed",
			InputIds:  []string{"1", "2", "1", "3", "2", "4", "1", "5", "2", "6"},
			ExpOutput: []string{"1", "2", "3", "4", "5", "6"},
		},
		{
			Name:      "One Duplicate",
			InputIds:  []string{"1", "2", "3", "4", "5", "6", "1"},
			ExpOutput: []string{"1", "2", "3", "4", "5", "6"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			dets := make([]*model.Detection, 0, len(test.InputIds))
			for _, id := range test.InputIds {
				dets = append(dets, &model.Detection{PublicID: id})
			}

			deduped := DeduplicateByPublicId(dets)

			output := make([]string, 0, len(deduped))
			for _, det := range deduped {
				output = append(output, det.PublicID)
			}

			assert.Equal(t, test.ExpOutput, output)
		})
	}
}

func TestCheckTemplate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)

	// note: after the first time DoesTemplateExist returns true, it will not be called
	// again no matter how many times CheckTemplate is called.
	detStore.EXPECT().DoesTemplateExist(ctx, "so-detection").Return(false, nil)
	detStore.EXPECT().DoesTemplateExist(ctx, "so-detection").Return(true, nil).Times(1)

	templateFound = false

	results := []bool{}
	for i := 0; i < 10; i++ {
		result := CheckTemplate(ctx, detStore)
		results = append(results, result)
	}

	assert.Equal(t, []bool{false, true, true, true, true, true, true, true, true, true}, results)
	assert.Equal(t, true, templateFound)
}

func TestUpdateRepos(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	branch := "branch"

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07",
			Dir:      true,
		},
		&handmock.MockDirEntry{
			Filename: "8adef80777f0755badbefb8313d1cdd93fc3c3fd50a4bebf0de289b5a3a93bac",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "baseRepoFolder/9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07", nil).Return(false, false, false)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/bf8fb6b1214693731c049b7b1b2822c7831a4bcfd5530e24ddb5e7153ca54c4e", "http://github.com/user/repo2", &branch).Return(nil)
	iom.EXPECT().RemoveAll("baseRepoFolder/8adef80777f0755badbefb8313d1cdd93fc3c3fd50a4bebf0de289b5a3a93bac").Return(nil)

	isRunning := true

	repos := []*model.RuleRepo{
		{
			Repo: "http://github.com/user/repo1",
		},
		{
			Repo:   "http://github.com/user/repo2",
			Branch: &branch,
		},
	}

	allRepos, anythingNew, err := UpdateRepos(&isRunning, "baseRepoFolder", repos, iom)
	assert.NoError(t, err)
	assert.Len(t, allRepos, len(repos))
	assert.Equal(t, &RepoOnDisk{
		Repo: repos[0],
		Path: "baseRepoFolder/9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07",
	}, allRepos[0])
	assert.Equal(t, &RepoOnDisk{
		Repo:        repos[1],
		Path:        "baseRepoFolder/bf8fb6b1214693731c049b7b1b2822c7831a4bcfd5530e24ddb5e7153ca54c4e",
		WasModified: true,
	}, allRepos[1])
	assert.True(t, anythingNew)
}

func TestUpdateReposFailToClone(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	branch := "branch"

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07",
			Dir:      true,
		},
		&handmock.MockDirEntry{
			Filename: "8adef80777f0755badbefb8313d1cdd93fc3c3fd50a4bebf0de289b5a3a93bac",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/bf8fb6b1214693731c049b7b1b2822c7831a4bcfd5530e24ddb5e7153ca54c4e", "http://github.com/user/repo2", &branch).Return(errors.New("unexpected error"))

	isRunning := true

	repos := []*model.RuleRepo{
		{
			Repo:   "http://github.com/user/repo2",
			Branch: &branch,
		},
		{
			Repo: "http://github.com/user/repo1",
		},
	}

	allRepos, anythingNew, err := UpdateRepos(&isRunning, "baseRepoFolder", repos, iom)
	assert.Error(t, err)
	assert.Nil(t, allRepos)
	assert.False(t, anythingNew)
}

func TestUpdateReposAllowedRepoErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	branch := "branch"

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "baseRepoFolder/9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07", &branch).Return(true, false, false)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/bf8fb6b1214693731c049b7b1b2822c7831a4bcfd5530e24ddb5e7153ca54c4e", "http://github.com/user/repo2", nil).Return(transport.ErrEmptyRemoteRepository)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/accd1a60dae04a7debe8cb75b0744a0cc62a10a280e8bf1badfa0eaa803d0955", "file:///nsm/rules/repo3", nil).Return(transport.ErrRepositoryNotFound)

	isRunning := true

	repos := []*model.RuleRepo{
		{
			Repo:   "http://github.com/user/repo1",
			Branch: &branch,
		},
		{
			Repo: "http://github.com/user/repo2",
		},
		{
			Repo: "file:///nsm/rules/repo3",
		},
	}

	allRepos, anythingNew, err := UpdateRepos(&isRunning, "baseRepoFolder", repos, iom)
	assert.NoError(t, err)
	assert.Len(t, allRepos, 1)
	assert.Equal(t, &RepoOnDisk{
		Repo:        repos[0],
		Path:        "baseRepoFolder/9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07",
		WasModified: true,
	}, allRepos[0])
	assert.True(t, anythingNew)
}

func TestUpdateReposRepoRemoteGoneError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	branch := "branch"

	iom := mock.NewMockIOManager(ctrl)
	// 1. repo has been cloned before and exists on disk
	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07",
			Dir:      true,
		},
	}, nil)
	// 2. the remote repository no longer exists
	iom.EXPECT().PullRepo(gomock.Any(), "baseRepoFolder/9f9f0b566520a18e7754f06a0e5359cfa390726dbc0cf8383aad2d88b9f5db07", &branch).Return(false, false, true)
	// 3. We DO NOT delete the repo for recloning, we do not process other repos in the config's list

	isRunning := true

	repos := []*model.RuleRepo{
		{
			Repo:   "http://github.com/user/repo1",
			Branch: &branch,
		},
		{
			Repo: "http://github.com/user/repo2",
		},
	}

	allRepos, anythingNew, err := UpdateRepos(&isRunning, "baseRepoFolder", repos, iom)
	assert.Len(t, allRepos, 0)
	assert.False(t, anythingNew)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrRepoRemoteGone)
}
