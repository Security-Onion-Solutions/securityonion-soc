// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package handmock

import (
	"io/fs"
	"time"
)

type MockDirEntry struct {
	Filename string
	Dir      bool
	FMode    fs.FileMode
}

func (mde *MockDirEntry) Name() string {
	return mde.Filename
}

func (mde *MockDirEntry) IsDir() bool {
	return mde.Dir
}

func (mde *MockDirEntry) Type() fs.FileMode {
	return mde.FMode
}

func (mde *MockDirEntry) ModTime() time.Time {
	return time.Now()
}

func (mde *MockDirEntry) Mode() fs.FileMode {
	return mde.FMode
}

func (mde *MockDirEntry) Size() int64 {
	return 100
}

func (mde *MockDirEntry) Sys() any {
	return nil
}

func (mde *MockDirEntry) Info() (fs.FileInfo, error) {
	return mde, nil
}
