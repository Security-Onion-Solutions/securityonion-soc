package detections

import (
	"io/fs"
	"sort"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRefreshAiSummaries(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	isRunning := true
	localRepo := "file:///tmp/repo1"
	repo := "http://github.com/user/repo2"
	branch := "generated-summaries-published"
	summaries := `{"87e55c67-46f0-4a7b-a3c6-d473ab7e8392": { "Reviewed": false, "Summary": "ai text goes here"}, "a23077fc-a5ef-427f-92ab-d3de7f56834d": { "Reviewed": true, "Summary": "ai text goes here" } }`

	iom := mock.NewMockIOManager(ctrl)
	loader := mock.NewMockAiLoader(ctrl)

	// Airgapped test
	h := memory.New()
	lg := &log.Logger{Handler: h, Level: log.DebugLevel}
	logger := lg.WithField("test", true)

	// No calls to iom.PullRepo/iom.CloneRepo should be made
	loader.EXPECT().IsAirgapped().Return(true)
	iom.EXPECT().ReadFile("baseRepoFolder/repo1/detections-ai/sigma_summaries.yaml").Return([]byte(summaries), nil)
	loader.EXPECT().LoadAuxiliaryData(gomock.Any()).DoAndReturn(func(sums []*model.AiSummary) error {
		expected := []*model.AiSummary{
			{
				PublicId: "87e55c67-46f0-4a7b-a3c6-d473ab7e8392",
				Summary:  "ai text goes here",
			},
			{
				PublicId: "a23077fc-a5ef-427f-92ab-d3de7f56834d",
				Reviewed: true,
				Summary:  "ai text goes here",
			},
		}

		sort.Slice(sums, func(i, j int) bool {
			return sums[i].PublicId < sums[j].PublicId
		})

		assert.Equal(t, len(expected), len(sums))
		for i := range sums {
			assert.Equal(t, *expected[i], *sums[i])
		}

		return nil
	})

	err := RefreshAiSummaries(loader, model.SigLangSigma, &isRunning, "baseRepoFolder", localRepo, "", logger, iom)
	assert.NoError(t, err)

	assert.Equal(t, len(h.Entries), 5)

	msg := h.Entries[0]
	assert.Equal(t, msg.Message, "skipping AI summary update because airgap is enabled")
	assert.Equal(t, msg.Level, log.DebugLevel)

	msg = h.Entries[1]
	assert.Equal(t, msg.Message, "reading AI summaries")
	assert.Equal(t, msg.Level, log.InfoLevel)

	msg = h.Entries[2]
	assert.Equal(t, msg.Message, "successfully unmarshalled AI summaries, parsing...")
	assert.Equal(t, msg.Level, log.InfoLevel)

	msg = h.Entries[3]
	assert.Equal(t, msg.Message, "successfully parsed AI summaries")
	assert.Equal(t, msg.Level, log.InfoLevel)

	msg = h.Entries[4]
	assert.Equal(t, msg.Message, "successfully loaded AI summaries")
	assert.Equal(t, msg.Level, log.InfoLevel)

	// non-Airgapped test
	loader.EXPECT().IsAirgapped().Return(false)
	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{}, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/repo2", repo, &branch).Return(nil)
	iom.EXPECT().ReadFile("baseRepoFolder/repo2/detections-ai/sigma_summaries.yaml").Return([]byte(summaries), nil)
	loader.EXPECT().LoadAuxiliaryData(gomock.Any()).DoAndReturn(func(sums []*model.AiSummary) error {
		expected := []*model.AiSummary{
			{
				PublicId: "87e55c67-46f0-4a7b-a3c6-d473ab7e8392",
				Summary:  "ai text goes here",
			},
			{
				PublicId: "a23077fc-a5ef-427f-92ab-d3de7f56834d",
				Reviewed: true,
				Summary:  "ai text goes here",
			},
		}

		sort.Slice(sums, func(i, j int) bool {
			return sums[i].PublicId < sums[j].PublicId
		})

		assert.Equal(t, len(expected), len(sums))
		for i := range sums {
			assert.Equal(t, *expected[i], *sums[i])
		}

		return nil
	})

	lastSuccessfulAiUpdate = time.Time{}

	err = RefreshAiSummaries(loader, model.SigLangSigma, &isRunning, "baseRepoFolder", repo, branch, logger, iom)
	assert.NoError(t, err)
}
