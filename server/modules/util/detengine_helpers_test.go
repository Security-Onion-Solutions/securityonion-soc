package util

import (
	"errors"
	"io/fs"
	"strconv"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/util/mock"
	"github.com/tj/assert"
	"go.uber.org/mock/gomock"
)

func TestDetermineWaitTimeNoState(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().ReadFile("state").Return(nil, fs.ErrNotExist)

	dur := DetermineWaitTime(mio, "state", time.Minute)
	assert.Equal(t, time.Duration(time.Minute*20), dur)
}

func TestDetermineWaitTime(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	tenSecAgo := time.Now().Unix() - 10
	tenSecAgoStr := strconv.FormatInt(tenSecAgo, 10)

	mio.EXPECT().ReadFile("state").Return([]byte(tenSecAgoStr), nil)

	dur := DetermineWaitTime(mio, "state", time.Minute)
	assert.InEpsilon(t, time.Duration(time.Second*50), dur, 1)
}

func TestDetermineWaitTimeBadRead(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().ReadFile("state").Return(nil, errors.New("bad read"))
	mio.EXPECT().DeleteFile("state").Return(nil)

	dur := DetermineWaitTime(mio, "state", time.Minute)
	assert.Equal(t, time.Duration(time.Minute*20), dur)
}

func TestDetermineWaitTimeBadValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	mio := mock.NewMockIOManager(ctrl)

	mio.EXPECT().ReadFile("state").Return([]byte("bad"), nil)
	mio.EXPECT().DeleteFile("state").Return(nil)

	dur := DetermineWaitTime(mio, "state", time.Minute)
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
