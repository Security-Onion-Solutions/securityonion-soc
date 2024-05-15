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
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
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
