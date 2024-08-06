package detections

import (
	"io/fs"
	"testing"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"

	"github.com/tj/assert"
	"go.uber.org/mock/gomock"
)

func TestRefreshAiSummaries(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	isRunning := true
	repo := "http://github.com/user/repo1"
	summaries := `{"87e55c67-46f0-4a7b-a3c6-d473ab7e8392": { "Reviewed": false, "Summary": "ai text goes here"}, "a23077fc-a5ef-427f-92ab-d3de7f56834d": { "Reviewed": true, "Summary": "ai text goes here" } }`

	iom := mock.NewMockIOManager(ctrl)
	loader := mock.NewMockAiLoader(ctrl)

	iom.EXPECT().ReadDir("baseRepoFolder").Return([]fs.DirEntry{}, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "baseRepoFolder/repo1", repo).Return(nil)
	iom.EXPECT().ReadFile("baseRepoFolder/repo1/detections-ai/sigma_summaries.yaml").Return([]byte(summaries), nil)
	loader.EXPECT().LoadAuxilleryData([]*model.AiSummary{
		{
			PublicId: "87e55c67-46f0-4a7b-a3c6-d473ab7e8392",
			Summary:  "ai text goes here",
		},
		{
			PublicId: "a23077fc-a5ef-427f-92ab-d3de7f56834d",
			Reviewed: true,
			Summary:  "ai text goes here",
		},
	}).Return(nil)

	logger := log.WithField("test", true)

	err := RefreshAiSummaries(loader, model.SigLangSigma, &isRunning, "baseRepoFolder", repo, iom, logger)
	assert.NoError(t, err)
}
