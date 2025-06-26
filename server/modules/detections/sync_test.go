package detections

import (
	"context"
	"sync"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestSyncScheduler(t *testing.T) {
	tests := []struct {
		Name      string
		InitMock  func(*testing.T, context.Context, *servermock.MockDetectionstore, *mock.MockDetailedDetectionEngine, *SyncSchedulerParams, *model.EngineState, model.EngineName, *bool)
		CheckMock func(*testing.T, context.Context, *servermock.MockDetectionstore, *mock.MockDetailedDetectionEngine, *SyncSchedulerParams, *model.EngineState, model.EngineName, *bool)
	}{
		{
			Name: "Sunny Day",
			InitMock: func(t *testing.T, ctx context.Context, detStore *servermock.MockDetectionstore, eng *mock.MockDetailedDetectionEngine, syncParams *SyncSchedulerParams, engineState *model.EngineState, engName model.EngineName, isRunning *bool) {
				eng.EXPECT().ReadFile(gomock.Any()).Return([]byte("0"), nil)
				eng.EXPECT().ResumeIntegrityChecker()

				detStore.EXPECT().DoesTemplateExist(ctx, "so-detection").Return(true, nil)

				eng.EXPECT().PauseIntegrityChecker()
				eng.EXPECT().Sync(gomock.Any(), false).Return(nil)

				// second loop, make sure the engineState has been updated
				eng.EXPECT().ResumeIntegrityChecker().DoAndReturn(func() {
					*isRunning = false
				})

				eng.EXPECT().PauseIntegrityChecker()
			},
			CheckMock: func(t *testing.T, ctx context.Context, detStore *servermock.MockDetectionstore, eng *mock.MockDetailedDetectionEngine, syncParams *SyncSchedulerParams, engineState *model.EngineState, engName model.EngineName, isRunning *bool) {
				assert.False(t, *isRunning)

				assert.False(t, engineState.Importing)
				assert.False(t, engineState.IntegrityFailure)
				assert.False(t, engineState.Migrating)
				assert.False(t, engineState.MigrationFailure)
				assert.False(t, engineState.SyncFailure)
				assert.False(t, engineState.Syncing)
			},
		},
		{
			Name: "No ES Template on First Pass",
			InitMock: func(t *testing.T, ctx context.Context, detStore *servermock.MockDetectionstore, eng *mock.MockDetailedDetectionEngine, syncParams *SyncSchedulerParams, engineState *model.EngineState, engName model.EngineName, isRunning *bool) {
				eng.EXPECT().ReadFile(gomock.Any()).Return([]byte("0"), nil)
				eng.EXPECT().ResumeIntegrityChecker()

				detStore.EXPECT().DoesTemplateExist(ctx, "so-detection").Return(false, nil)

				eng.EXPECT().ResumeIntegrityChecker().DoAndReturn(func() {
					// because the template didn't exist, the engine should report
					// that the sync failed
					assert.False(t, engineState.Importing)
					assert.False(t, engineState.IntegrityFailure)
					assert.False(t, engineState.Migrating)
					assert.False(t, engineState.MigrationFailure)
					assert.True(t, engineState.SyncFailure)
					assert.False(t, engineState.Syncing)
				})

				detStore.EXPECT().DoesTemplateExist(ctx, "so-detection").Return(true, nil)
				eng.EXPECT().PauseIntegrityChecker()
				// expect a force sync because the last sync failed
				eng.EXPECT().Sync(gomock.Any(), true).Return(nil)

				// second loop, make sure the engineState has been updated
				eng.EXPECT().ResumeIntegrityChecker()

				eng.EXPECT().PauseIntegrityChecker().DoAndReturn(func() {
					*isRunning = false
				})
			},
			CheckMock: func(t *testing.T, ctx context.Context, detStore *servermock.MockDetectionstore, eng *mock.MockDetailedDetectionEngine, syncParams *SyncSchedulerParams, engineState *model.EngineState, engName model.EngineName, isRunning *bool) {
				assert.False(t, *isRunning)

				assert.False(t, engineState.Importing)
				assert.False(t, engineState.IntegrityFailure)
				assert.False(t, engineState.Migrating)
				assert.False(t, engineState.MigrationFailure)
				assert.False(t, engineState.SyncFailure)
				assert.False(t, engineState.Syncing)
			},
		},
	}

	ctrl := gomock.NewController(t)

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			// reset package level variables
			templateFound = false

			// build up mocks
			ctx := context.Background()
			detStore := servermock.NewMockDetectionstore(ctrl)
			eng := mock.NewMockDetailedDetectionEngine(ctrl)
			syncParams := &SyncSchedulerParams{
				SyncThread:    &sync.WaitGroup{},
				InterruptChan: make(chan bool, 1),
			}
			engineState := &model.EngineState{}
			engName := model.EngineName("test")
			isRunning := util.Ptr(true)

			test.InitMock(t, ctx, detStore, eng, syncParams, engineState, engName, isRunning)

			SyncScheduler(ctx, detStore, eng, syncParams, engineState, engName, isRunning)

			test.CheckMock(t, ctx, detStore, eng, syncParams, engineState, engName, isRunning)
		})
	}
}
