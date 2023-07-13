package agent

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

// idJobProcessor is a "sunny day" JobProcessor that simply appends the job id
// to the stream without panicking.
type idJobProcessor struct{}

func (jp *idJobProcessor) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	buf := bytes.NewBuffer([]byte{})

	if reader != nil {
		_, err := io.Copy(buf, reader)
		if err != nil {
			return nil, err
		}
	}

	_, err := buf.WriteString(strconv.Itoa(job.Id))
	if err != nil {
		return nil, err
	}

	return io.NopCloser(buf), nil
}

func (jp *idJobProcessor) CleanupJob(*model.Job) {}

func (jp *idJobProcessor) GetDataEpoch() time.Time {
	t, _ := time.Parse(time.RFC3339, "2022-01-01T00:00:00Z")
	return t
}

// panicProcessor is a JobProcessor that always returns an error.
type panicProcessor struct{}

func (jp *panicProcessor) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	return reader, errors.New("panic")
}

func (jp *panicProcessor) CleanupJob(*model.Job) {}

func (jp *panicProcessor) GetDataEpoch() time.Time {
	t, _ := time.Parse(time.RFC3339, "2021-01-01T00:00:00Z")
	return t
}

func TestProcessJob(t *testing.T) {
	// prep test object
	jm := &JobManager{}

	jm.AddJobProcessor(&idJobProcessor{})
	jm.AddJobProcessor(&panicProcessor{})

	// prep model
	job := &model.Job{
		Id: 101,
	}

	// test
	stream, err := jm.ProcessJob(job)

	// verify
	data, rerr := io.ReadAll(stream)
	assert.NoError(t, rerr)

	assert.Equal(t, "101", string(data))
	assert.ErrorContains(t, err, "panic")
}

func TestUpdateDataEpoch(t *testing.T) {
	// prep test object
	jm := &JobManager{
		node: &model.Node{},
	}

	panicProc := &panicProcessor{}

	jm.AddJobProcessor(&idJobProcessor{}) // later epoch
	jm.AddJobProcessor(panicProc)         // earlier epoch

	// test
	jm.updateDataEpoch()

	// verify
	assert.Equal(t, jm.node.EpochTime, panicProc.GetDataEpoch())
}

type ClientAuthMock struct{}

func (cam *ClientAuthMock) Authorize(*http.Request) error {
	return nil
}

func TestNoJobReady(t *testing.T) {
	// prep test object
	client := &web.Client{
		Auth: &ClientAuthMock{},
	}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
	}

	client.MockResponse(res, nil)

	jm := &JobManager{
		agent: &Agent{
			Client: client,
		},
		node: &model.Node{},
	}

	// test
	job, err := jm.PollPendingJobs()

	// verify
	assert.NoError(t, err)
	assert.Nil(t, job)
}
