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
