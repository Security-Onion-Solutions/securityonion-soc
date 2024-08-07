// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/tj/assert"
	"go.uber.org/mock/gomock"
)

func TestTruncateMap(t *testing.T) {
	errMap := map[string]error{
		"db6c06c4-bf3b-421c-aa88-15672b88c743": errors.New("error 1"),
		"db92dd33-a3ad-49cf-8c2c-608c3e30ace0": errors.New("error 2"),
		"dbc1f800-0fe0-4bc0-9c66-292c2abe3f78": errors.New("error 3"),
		"Random key":                           errors.New("random value"),
	}

	// Test truncating to one element
	truncatedErrMap := TruncateMap(errMap, 2)
	assert.Equal(t, 2, len(truncatedErrMap), "Truncated map should have exactly two elements.")

	// Ensure the key in the truncated map exists in the original map and has the correct error message
	for key, val := range truncatedErrMap {
		assert.Equal(t, errMap[key], val, "Error messages should match for truncated keys.")
	}

	// Test truncating to more elements than exist in the map
	truncatedErrMap = TruncateMap(errMap, 10)
	assert.Equal(t, len(errMap), len(truncatedErrMap), "Truncated map should equal the original map in size when the limit exceeds the number of map elements.")

	// Test truncating to zero elements
	truncatedErrMap = TruncateMap(errMap, 0)
	assert.Equal(t, 0, len(truncatedErrMap), "Truncated map should have no elements when limit is 0.")
}

func TestTruncateList(t *testing.T) {
	tests := []struct {
		Name       string
		Array      []int
		TruncateTo uint
		ExpArray   []int
	}{
		{
			Name:       "Empty",
			Array:      []int{},
			TruncateTo: 10,
			ExpArray:   []int{},
		},
		{
			Name:       "Below Limit",
			Array:      []int{0},
			TruncateTo: 10,
			ExpArray:   []int{0},
		},
		{
			Name:       "At Limit",
			Array:      []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			TruncateTo: 10,
			ExpArray:   []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			Name:       "Above Limit",
			Array:      []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			TruncateTo: 5,
			ExpArray:   []int{0, 1, 2, 3, 4},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			truncated := TruncateList(test.Array, test.TruncateTo)
			assert.Equal(t, test.ExpArray, truncated)
		})
	}
}

func TestDetermineWaitTimeNoState(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().ReadFile("state").Return(nil, fs.ErrNotExist)

	lastImport, dur := DetermineWaitTime(mio, "state", time.Minute)

	assert.Nil(t, lastImport, "Expected lastImport to be nil")
	assert.Equal(t, time.Minute*20, dur, "Expected duration to be 20 minutes")
}

func TestDetermineWaitTime(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	tenSecAgo := time.Now().Unix() - 10
	tenSecAgoStr := strconv.FormatInt(tenSecAgo, 10)

	mio.EXPECT().ReadFile("state").Return([]byte(tenSecAgoStr), nil)

	lastImport, dur := DetermineWaitTime(mio, "state", time.Minute)
	assert.NotNil(t, lastImport, "Expected lastImport not to be nil")
	assert.InEpsilon(t, time.Duration(time.Second*50), dur, 1)
}

func TestDetermineWaitTimeBadRead(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().ReadFile("state").Return(nil, errors.New("bad read"))
	mio.EXPECT().DeleteFile("state").Return(nil)

	lastImport, dur := DetermineWaitTime(mio, "state", time.Minute)
	assert.Nil(t, lastImport, "Expected lastImport to be nil")
	assert.Equal(t, time.Duration(time.Minute*20), dur)
}

func TestDetermineWaitTimeBadValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().ReadFile("state").Return([]byte("bad"), nil)
	mio.EXPECT().DeleteFile("state").Return(nil)

	lastImport, dur := DetermineWaitTime(mio, "state", time.Minute)
	assert.Nil(t, lastImport, "Expected lastImport to be nil")
	assert.Equal(t, time.Duration(time.Minute*20), dur)
}

func TestWriteStateFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().WriteFile("state", gomock.Any(), fs.FileMode(0644)).DoAndReturn(func(path string, contents []byte, perm fs.FileMode) error {
		unix, err := strconv.ParseInt(string(contents), 10, 64)
		assert.NoError(t, err)
		assert.InEpsilon(t, time.Now().Unix(), unix, 2)

		return nil
	})

	WriteStateFile(mio, "state")
}

func TestCheckWriteNoRead(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	id := util.Ptr("99999")
	ctx := context.Background()

	mio := servermock.NewMockDetectionstore(ctrl)

	// No pending ID to read
	shouldFail := CheckWriteNoRead(ctx, mio, nil)
	assert.False(t, shouldFail)

	// Error querying ES
	mio.EXPECT().GetDetectionByPublicId(gomock.Any(), *id).Return(nil, errors.New("connection error"))

	shouldFail = CheckWriteNoRead(ctx, mio, id)
	assert.True(t, shouldFail)

	// Detection still not found
	mio.EXPECT().GetDetectionByPublicId(gomock.Any(), *id).Return(nil, nil)

	shouldFail = CheckWriteNoRead(ctx, mio, id)
	assert.True(t, shouldFail)

	// Successfully read back the missing ID
	mio.EXPECT().GetDetectionByPublicId(gomock.Any(), *id).Return(&model.Detection{}, nil)

	shouldFail = CheckWriteNoRead(ctx, mio, id)
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

	results := []bool{}
	for i := 0; i < 10; i++ {
		result := CheckTemplate(ctx, detStore)
		results = append(results, result)
	}

	assert.Equal(t, []bool{false, true, true, true, true, true, true, true, true, true}, results)
}

func TestUpdateRepos(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo1",
			Dir:      true,
		},
		&handmock.MockDirEntry{
			Filename: "repo3",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "baseRepoFolder/repo1").Return(false, false)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/repo2", "http://github.com/user/repo2", util.Ptr("branch")).Return(nil)
	iom.EXPECT().RemoveAll("baseRepoFolder/repo3").Return(nil)

	isRunning := true

	repos := []*model.RuleRepo{
		{
			Repo: "http://github.com/user/repo1",
		},
		{
			Repo:   "http://github.com/user/repo2",
			Branch: util.Ptr("branch"),
		},
	}

	allRepos, anythingNew, err := UpdateRepos(&isRunning, "baseRepoFolder", repos, iom)
	assert.NoError(t, err)
	assert.Len(t, allRepos, len(repos))
	assert.Equal(t, &RepoOnDisk{
		Repo: repos[0],
		Path: "baseRepoFolder/repo1",
	}, allRepos[0])
	assert.Equal(t, &RepoOnDisk{
		Repo:        repos[1],
		Path:        "baseRepoFolder/repo2",
		WasModified: true,
	}, allRepos[1])
	assert.True(t, anythingNew)
}
