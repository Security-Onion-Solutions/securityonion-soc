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
