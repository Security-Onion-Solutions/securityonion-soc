package detections

import (
	"context"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestUpdateOverrideNote(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	note := strings.Repeat("a", MAX_OVERRIDE_NOTE_LENGTH+1)

	// Test that note exceeds maximum length
	valid, err := UpdateOverrideNote(ctx, detStore, "detectId", 0, note)

	assert.False(t, valid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "note exceeds maximum length")

	// Test that the overrideIndex is out of range
	detStore.EXPECT().GetDetection(ctx, "detectId").Return(&model.Detection{}, nil)
	note = "note"

	valid, err = UpdateOverrideNote(ctx, detStore, "detectId", 0, note)

	assert.False(t, valid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "override index out of range")

	// Sunny day success
	detStore.EXPECT().GetDetection(ctx, "detectId").Return(&model.Detection{Overrides: []*model.Override{{}}}, nil)
	detStore.EXPECT().UpdateDetection(gomock.Any(), &model.Detection{Overrides: []*model.Override{{Note: note}}}).DoAndReturn(func(c context.Context, det *model.Detection) (*model.Detection, error) {
		assert.True(t, modcontext.ReadSkipAudit(c))
		return nil, nil
	})

	valid, err = UpdateOverrideNote(ctx, detStore, "detectId", 0, note)

	assert.True(t, valid)
	assert.NoError(t, err)

	// unable to read database, should return valid=true and error
	detStore.EXPECT().GetDetection(ctx, "detectId").Return(nil, assert.AnError)

	valid, err = UpdateOverrideNote(ctx, detStore, "detectId", 0, note)

	assert.True(t, valid)
	assert.Error(t, err)
}
