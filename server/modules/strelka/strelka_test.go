package strelka

import (
	"context"
	"io/fs"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/strelka/mock"
	"github.com/tj/assert"
	"go.uber.org/mock/gomock"
)

const simpleRule = `rule dummy {
	condition:
	  false
}`

func TestStrelkaModule(t *testing.T) {
	srv := &server.Server{
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
	}
	mod := NewStrelkaEngine(srv)

	assert.Implements(t, (*module.Module)(nil), mod)
	assert.Implements(t, (*server.DetectionEngine)(nil), mod)

	err := mod.Init(nil)
	assert.NoError(t, err)

	err = mod.Start()
	assert.NoError(t, err)

	assert.True(t, mod.IsRunning())

	err = mod.Stop()
	assert.NoError(t, err)

	assert.Equal(t, 1, len(srv.DetectionEngines))
	assert.Same(t, mod, srv.DetectionEngines[model.EngineNameStrelka])
}

func TestSyncSuricata(t *testing.T) {
	table := []struct {
		Name           string
		InitMock       func(*servermock.MockDetectionstore, *mock.MockIOManager)
		ExpectedErr    error
		ExpectedErrMap map[string]string
	}{
		{
			Name: "Enable Simple Rules",
			InitMock: func(mockDetStore *servermock.MockDetectionstore, mio *mock.MockIOManager) {
				mockDetStore.EXPECT().Query(gomock.Any(), gomock.Any(), gomock.Any()).Return([]interface{}{
					&model.Detection{
						PublicID:  "1",
						Engine:    model.EngineNameStrelka,
						Content:   simpleRule,
						IsEnabled: true,
					},
					&model.Detection{
						PublicID:  "2",
						Engine:    model.EngineNameStrelka,
						Content:   simpleRule,
						IsEnabled: true,
					},
				}, nil)

				mio.EXPECT().WriteFile(gomock.Any(), []byte(simpleRule+"\n"+simpleRule+"\n"), fs.FileMode(0644)).Return(nil)

				mio.EXPECT().ExecCommand(gomock.Cond(func(c any) bool {
					cmd := c.(*exec.Cmd)

					if !strings.HasSuffix(cmd.Path, "python3") {
						return false
					}

					if slices.Equal(cmd.Args, []string{"compileYaraPythonScriptPath", "yaraRulesFolder"}) {
						return false
					}

					return true
				})).Return([]byte{}, 0, time.Duration(0), nil)
			},
		},
		{
			Name: "No Enabled Rules",
			InitMock: func(mockDetStore *servermock.MockDetectionstore, mio *mock.MockIOManager) {
				mockDetStore.EXPECT().Query(gomock.Any(), gomock.Any(), gomock.Any()).Return([]interface{}{}, nil)
				mio.EXPECT().DeleteFile("yaraRulesFolder/enabled_rules.yar").Return(nil)
			},
		},
	}

	ctx := context.Background()

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDetStore := servermock.NewMockDetectionstore(ctrl)
			mio := mock.NewMockIOManager(ctrl)

			mod := NewStrelkaEngine(&server.Server{
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
				Detectionstore:   mockDetStore,
			})
			mod.srv.DetectionEngines[model.EngineNameSuricata] = mod
			mod.IOManager = mio

			mod.compileYaraPythonScriptPath = "compileYaraPythonScriptPath"
			mod.yaraRulesFolder = "yaraRulesFolder"

			test.InitMock(mockDetStore, mio)

			errMap, err := mod.SyncLocalDetections(ctx, nil)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)
		})
	}
}
