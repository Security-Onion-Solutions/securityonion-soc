package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

type MockTransport struct {
	requests    []*http.Request
	responses   []*http.Response
	roundTripFn func(req *http.Request) (*http.Response, error)
}

func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests = append(t.requests, req)
	return t.roundTripFn(req)
}

func (t *MockTransport) AddResponse(res *http.Response) {
	if res.Body == nil {
		res.Body = http.NoBody
	}

	t.responses = append(t.responses, res)
}

func (t *MockTransport) GetRequests() []*http.Request {
	return t.requests
}

func newMockClient(t *testing.T) (*elasticsearch.Client, *MockTransport) {
	mocktrans := MockTransport{}
	mocktrans.roundTripFn = func(req *http.Request) (*http.Response, error) {
		if len(mocktrans.responses) != 0 {
			res := mocktrans.responses[0]
			mocktrans.responses = mocktrans.responses[1:]

			return res, nil
		} else {
			return nil, errors.New("unexpected call to client")
		}
	}

	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Transport: &mocktrans,
	})
	if err != nil {
		t.Fatalf("Error creating Elasticsearch client: %s", err)
	}

	return client, &mocktrans
}

func TestDetectionInit(t *testing.T) {
	t.Parallel()

	store := NewElasticCasestore(nil)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX, []string{"source.ip", "destination.ip"})
	assert.Equal(t, "myIndex", store.index)
	assert.Equal(t, "myAuditIndex", store.auditIndex)
	assert.Equal(t, 45, store.maxAssociations)
	assert.Equal(t, []string{"source.ip", "destination.ip"}, store.commonObservables)
}

func TestDetectionPrepareForSave(t *testing.T) {
	t.Parallel()

	store := NewElasticCasestore(nil)
	obj := &model.Auditable{
		Id: "myId",
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	actualId := store.prepareForSave(ctx, obj)

	assert.Equal(t, "myId", actualId)
	assert.Equal(t, "myRequestorId", obj.UserId)
	assert.Equal(t, "", obj.Id)
	assert.Nil(t, obj.UpdateTime)
}

func TestDetectionValidateIdValid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	err := store.validateId("12345", "test")
	assert.NoError(t, err)

	err = store.validateId("123456", "test")
	assert.NoError(t, err)

	err = store.validateId("1-2-A-b", "test")
	assert.NoError(t, err)

	err = store.validateId("1-2-a-b_2klj", "test")
	assert.NoError(t, err)

	err = store.validateId("12345678901234567890123456789012345678901234567890", "test")
	assert.NoError(t, err)
}

func TestDetectionValidateIdInvalid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	err := store.validateId("", "test")
	assert.Error(t, err)

	err = store.validateId("1", "test")
	assert.Error(t, err)

	err = store.validateId("a", "test")
	assert.Error(t, err)

	err = store.validateId("this is invalid since it has spaces", "test")
	assert.Error(t, err)

	err = store.validateId("'quotes'", "test")
	assert.Error(t, err)

	err = store.validateId("\"dblquotes\"", "test")
	assert.Error(t, err)

	err = store.validateId("123456789012345678901234567890123456789012345678901", "test")
	assert.Error(t, err)
}

func TestDetectionValidateStringValid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	err := store.validateString("12345", 6, "test")
	assert.NoError(t, err)

	err = store.validateString("123456", 6, "test")
	assert.NoError(t, err)

	err = store.validateString("", 6, "test")
	assert.NoError(t, err)
}

func TestDetectionValidateStringInvalid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	err := store.validateString("1234567", 6, "test")
	assert.Error(t, err)

	err = store.validateString("12345678", 6, "test")
	assert.Error(t, err)
}

func TestDetectionValidateCommentValid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	comment := &model.DetectionComment{}
	comment.Value = "myVal"

	err := store.validateComment(comment)
	assert.NoError(t, err)

	comment.Id = "123456"
	comment.UserId = "myUserId"
	for x := 1; x < 500; x++ {
		comment.Value += "this is my reasonably long value\n"
	}
	err = store.validateComment(comment)
	assert.NoError(t, err)
}

func TestDetectionValidateCommentInvalid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	comment := &model.DetectionComment{}

	comment.Id = "this is an invalid id"
	err := store.validateComment(comment)
	assert.EqualError(t, err, "invalid ID for commentId")
	comment.Id = ""

	comment.DetectionId = "this is an invalid id"
	err = store.validateComment(comment)
	assert.EqualError(t, err, "invalid ID for detectionId")
	comment.DetectionId = ""

	comment.UserId = "this is an invalid id"
	err = store.validateComment(comment)
	assert.EqualError(t, err, "invalid ID for userId")
	comment.UserId = ""

	comment.Kind = "myKind"
	err = store.validateComment(comment)
	assert.EqualError(t, err, "Field 'Kind' must not be specified")
	comment.Kind = ""

	comment.Operation = "myOperation"

	err = store.validateComment(comment)
	assert.EqualError(t, err, "Field 'Operation' must not be specified")
	comment.Operation = ""

	for x := 1; x < 30000; x++ {
		comment.Value += "this is my unreasonably long comment\n"
	}

	err = store.validateComment(comment)
	assert.EqualError(t, err, "value is too long (1109963/1000000)")
}

func TestValidateDetectionValid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{
		Auditable: model.Auditable{
			Id: "hJFpC44Bm7lAWCSuSwHa",
		},
		PublicID:    "123456",
		Title:       "myTitle",
		Description: "myDescription",
		Severity:    "kinda bad",
		Author:      "Jane Doe",
		Content:     "myContent",
		IsCommunity: true,
		Ruleset:     util.Ptr("myRuleset"),
		Tags:        []string{"myTag"},
		Engine:      "suricata",
		Language:    "suricata",
	}
	err := store.validateDetection(det)
	assert.NoError(t, err)
}

func TestValidateDetectionInvalid(t *testing.T) {
	t.Parallel()

	store := NewElasticDetectionstore(server.NewFakeAuthorizedServer(nil), nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{}

	det.Id = "this is an invalid id"
	err := store.validateDetection(det)
	assert.EqualError(t, err, "invalid ID for Id")
	det.Id = ""

	det.PublicID = "this is an invalid publicid"
	err = store.validateDetection(det)
	assert.EqualError(t, err, "invalid ID for publicId")
	det.PublicID = ""

	det.Title = strings.Repeat("a", LONG_STRING_MAX+1)
	err = store.validateDetection(det)
	assert.EqualError(t, err, "title is too long (1000001/1000000)")
	det.Title = ""

	det.Severity = model.Severity(strings.Repeat("a", SHORT_STRING_MAX+1))
	err = store.validateDetection(det)
	assert.EqualError(t, err, "severity is too long (101/100)")
	det.Severity = ""

	det.Author = strings.Repeat("a", SHORT_STRING_MAX+1)
	err = store.validateDetection(det)
	assert.EqualError(t, err, "author is too long (101/100)")
	det.Author = ""

	det.Content = strings.Repeat("a", LONG_STRING_MAX+1)
	err = store.validateDetection(det)
	assert.EqualError(t, err, "content is too long (1000001/1000000)")
	det.Content = ""

	det.IsCommunity = true
	det.Ruleset = util.Ptr(strings.Repeat("a", SHORT_STRING_MAX+1))
	err = store.validateDetection(det)
	assert.EqualError(t, err, "ruleset is too long (101/100)")
	det.Ruleset = nil
	det.IsCommunity = false

	for x := 1; x < 30000; x++ {
		det.Description += "this is my unreasonably long description\n"
	}

	err = store.validateDetection(det)
	assert.EqualError(t, err, "description is too long (1229959/1000000)")
	det.Description = "myDescription"

	det.Engine = "myEngine"
	err = store.validateDetection(det)
	assert.EqualError(t, err, "invalid engine")
	det.Engine = "suricata"

	det.Language = "Spanish"
	err = store.validateDetection(det)
	assert.EqualError(t, err, "invalid language")
	det.Language = "yara"
	err = store.validateDetection(det)
	assert.EqualError(t, err, "engine and language mismatch")
	det.Language = "suricata"

	det.Kind = "myKind"
	err = store.validateDetection(det)
	assert.EqualError(t, err, "Field 'Kind' must not be specified")
	det.Kind = ""

	det.Operation = "myOperation"
	err = store.validateDetection(det)
	assert.EqualError(t, err, "Field 'Operation' must not be specified")
	det.Operation = ""

	tag := ""
	for x := 1; x < 50; x++ {
		tag += "this is my unreasonably long tag\n"
	}

	det.Tags = append(det.Tags, tag)
	err = store.validateDetection(det)
	assert.EqualError(t, err, "Tag[0] is too long (1617/100)")
	det.Tags = nil

	for x := 1; x < 500; x++ {
		det.Tags = append(det.Tags, "myTag")
	}

	err = store.validateDetection(det)
	assert.EqualError(t, err, "Field 'Tags' contains excessive elements (499/50)")
	det.Tags = nil
}

func TestCreateDetectionValid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   true,
						"so_detection.isReporting": true,
						"so_detection.isCommunity": true,
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.createTime":  "2021-08-01T00:00:00Z",
						"so_detection.overrides": []interface{}{
							map[string]interface{}{
								"createdAt": "2021-08-01T00:00:00Z",
								"updatedAt": "2021-08-01T00:00:00Z",
							},
						},
						"so_kind": "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{
		Title:       "myTitle",
		Severity:    "low",
		Author:      "Jane Doe",
		Description: "myDescription",
		Content:     "myContent",
		IsEnabled:   true,
		IsReporting: true,
		IsCommunity: true,
		Ruleset:     util.Ptr("myRuleset"),
		Engine:      "suricata",
		Language:    "suricata",
		License:     "DRL",
		Overrides: []*model.Override{
			{},
		},
		Tags: []string{"myTag"},
	}

	body1 := `{"result":"created", "_id":"ABC123"}`
	body2 := `{"result":"created", "_id":"DEF456"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	postDet, err := store.CreateDetection(ctx, det)
	assert.NoError(t, err)

	assert.NotNil(t, det.CreateTime)
	assert.NotNil(t, postDet.CreateTime)
	assert.NotNil(t, postDet.UpdateTime)
	assert.NotNil(t, postDet.Overrides[0].CreatedAt)
	assert.NotNil(t, postDet.Overrides[0].UpdatedAt)
	assert.Equal(t, "detection", postDet.Kind)
	det.CreateTime = nil
	postDet.CreateTime = nil
	postDet.UpdateTime = nil
	postDet.Kind = ""
	postDet.Overrides = nil
	det.Overrides = nil

	assert.Equal(t, det, postDet)

	reqs := mocktrans.GetRequests()

	assert.Equal(t, 2, len(reqs))

	reqDet := extractSoDetectionFromRequestBody(t, reqs[0])
	assert.NotNil(t, reqDet.CreateTime)
	assert.Equal(t, 1, len(reqDet.Overrides))
	assert.NotNil(t, reqDet.Overrides[0].CreatedAt)
	assert.NotNil(t, reqDet.Overrides[0].UpdatedAt)
	reqDet.CreateTime = nil
	reqDet.Overrides = nil
	assert.Equal(t, det, reqDet)

	body, err := io.ReadAll(reqs[1].Body)
	assert.NoError(t, err)

	soauditdocid := gjson.Get(string(body), "so_audit_doc_id").Str
	assert.Equal(t, "ABC123", soauditdocid)

	rawDet := gjson.Get(string(body), "so_detection").Raw
	err = json.Unmarshal([]byte(rawDet), &reqDet)
	assert.NoError(t, err)

	assert.NotNil(t, reqDet.CreateTime)
	assert.Equal(t, 1, len(reqDet.Overrides))
	assert.NotNil(t, reqDet.Overrides[0].CreatedAt)
	assert.NotNil(t, reqDet.Overrides[0].UpdatedAt)
	reqDet.CreateTime = nil
	reqDet.Overrides = nil

	assert.Equal(t, det, reqDet)

	kind := gjson.Get(string(body), "so_kind").Str
	assert.Equal(t, "detection", kind)

	op := gjson.Get(string(body), "so_operation").Str
	assert.Equal(t, "create", op)
}

func TestCreateDetectionPublicIdCollision(t *testing.T) {
	t.Parallel()

	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Payload: map[string]interface{}{
						"so_detection.publicId": "123456",
						"so_kind":               "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, nil, 100) // client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{
		PublicID: "123456",
		Engine:   "suricata",
		Language: "suricata",
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	postDet, err := store.CreateDetection(ctx, det)
	assert.ErrorContains(t, err, "publicId already exists for this engine")
	assert.Nil(t, postDet)
}

func TestUpdateDetectionValid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	now, err := time.Parse(time.RFC3339, nowStr)
	assert.NoError(t, err)

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "hJFpC44Bm7lAWCSuSwHa",
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   true,
						"so_detection.isReporting": true,
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.overrides": []interface{}{
							map[string]interface{}{
								"type":      "modify",
								"createdAt": nowStr,
							},
						},
						"so_detection.createTime": "2021-08-01T00:00:00Z",
						"so_kind":                 "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{
		Auditable: model.Auditable{
			Id:         "hJFpC44Bm7lAWCSuSwHa",
			CreateTime: util.Ptr(now),
		},
		Title:       "myTitle",
		Severity:    "low",
		Author:      "Jane Doe",
		Description: "myDescription",
		Content:     "myContent",
		IsEnabled:   true,
		IsReporting: true,
		Ruleset:     util.Ptr("myRuleset"),
		Engine:      "suricata",
		Language:    "suricata",
		License:     "DRL",
		Tags:        []string{"myTag"},
		Overrides: []*model.Override{
			{
				Type:      "modify",
				CreatedAt: now,
			},
		},
	}

	body1 := `{"result":"updated", "_id":"ABC123"}`
	body2 := `{"result":"created", "_id":"DEF456"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	postDet, err := store.UpdateDetection(ctx, det)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(postDet.Overrides))
	assert.NotNil(t, postDet.Overrides[0].CreatedAt)
	assert.NotNil(t, postDet.Overrides[0].UpdatedAt)
	postDet.Overrides = nil
	det.Overrides = nil

	detWithoutId := util.Copy(det)

	assert.NotNil(t, det.CreateTime)
	assert.Nil(t, det.UpdateTime)
	assert.NotNil(t, postDet.CreateTime)
	assert.NotNil(t, postDet.UpdateTime)
	assert.Equal(t, "detection", postDet.Kind)
	det.CreateTime = nil
	postDet.CreateTime = nil
	postDet.UpdateTime = nil
	det.UserId = "myRequestorId"
	det.Kind = "detection"
	det.Id = "hJFpC44Bm7lAWCSuSwHa"

	assert.Equal(t, det, postDet)

	reqs := mocktrans.GetRequests()

	assert.Equal(t, 2, len(reqs))

	reqDet := extractSoDetectionFromRequestBody(t, reqs[0])
	assert.NotNil(t, reqDet.CreateTime)
	assert.Nil(t, reqDet.UpdateTime)
	reqDet.CreateTime = nil
	reqDet.UpdateTime = nil
	reqDet.Overrides = nil
	detWithoutId.CreateTime = nil
	assert.Equal(t, detWithoutId, reqDet)

	body, err := io.ReadAll(reqs[1].Body)
	assert.NoError(t, err)

	soauditdocid := gjson.Get(string(body), "so_audit_doc_id").Str
	assert.Equal(t, "ABC123", soauditdocid)

	rawDet := gjson.Get(string(body), "so_detection").Raw
	err = json.Unmarshal([]byte(rawDet), &reqDet)
	assert.NoError(t, err)

	assert.NotNil(t, reqDet.CreateTime)
	assert.Nil(t, reqDet.UpdateTime)
	assert.Equal(t, 1, len(reqDet.Overrides))
	reqDet.CreateTime = nil
	reqDet.UpdateTime = nil
	reqDet.Overrides = nil

	assert.Equal(t, detWithoutId, reqDet)

	kind := gjson.Get(string(body), "so_kind").Str
	assert.Equal(t, "detection", kind)

	op := gjson.Get(string(body), "so_operation").Str
	assert.Equal(t, "update", op)
}

func TestUpdateDetectionValidCommunity(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "hJFpC44Bm7lAWCSuSwHa",
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   false,
						"so_detection.isReporting": false,
						"so_detection.isCommunity": true,
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.overrides": []interface{}{
							map[string]interface{}{
								"type":      "modify",
								"createdAt": "2021-08-01T00:00:00Z",
							},
						},
						"so_detection.createTime": "2021-08-01T00:00:00Z",
						"so_kind":                 "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{
		Auditable: model.Auditable{
			Id: "hJFpC44Bm7lAWCSuSwHa",
		},
		IsEnabled:   true,
		IsReporting: true,
		Engine:      "suricata",
		Language:    "suricata",
	}

	body1 := `{"result":"updated", "_id":"ABC123"}` // create detection
	body2 := `{"result":"created", "_id":"DEF456"}` // create audit doc

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	_, err := store.UpdateDetection(ctx, det)
	assert.NoError(t, err)

	reqs := mocktrans.GetRequests()
	assert.Equal(t, 2, len(reqs))

	expected := &model.Detection{
		Auditable: model.Auditable{
			UserId:     "myRequestorId",
			Kind:       "detection",
			CreateTime: util.Ptr(time.Now()),
		},
		Title:       "myTitle",
		Description: "myDescription",
		Severity:    "low",
		Author:      "Jane Doe",
		Content:     "myContent",
		IsEnabled:   true,
		IsReporting: true,
		IsCommunity: true,
		Ruleset:     util.Ptr("myRuleset"),
		Engine:      "suricata",
		Language:    "suricata",
		License:     "DRL",
		Tags:        []string{"myTag"},
	}

	det = extractSoDetectionFromRequestBody(t, reqs[0])
	// borrow the only value we can't accurately predict
	expected.CreateTime = det.CreateTime

	assert.Equal(t, expected, det)
}

func TestUpdateDetectionInvalidCommunity(t *testing.T) {
	t.Parallel()

	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	// old rule that's not a community rule
	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "hJFpC44Bm7lAWCSuSwHa",
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   true,
						"so_detection.isReporting": true,
						"so_detection.isCommunity": false, // important
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.createTime":  "2021-08-01T00:00:00Z",
						"so_kind":                  "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, nil, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	// updated version of detection, isCommunity is true
	det := &model.Detection{
		Auditable: model.Auditable{
			Id:         "hJFpC44Bm7lAWCSuSwHa",
			CreateTime: util.Ptr(time.Now()),
		},
		Title:       "myTitle",
		Severity:    "low",
		Author:      "Jane Doe",
		Description: "myDescription",
		Content:     "myContent",
		IsEnabled:   true,
		IsReporting: true,
		IsCommunity: true,
		Ruleset:     util.Ptr("myRuleset"),
		Engine:      "suricata",
		Language:    "suricata",
		License:     "DRL",
		Tags:        []string{"myTag"},
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	postDet, err := store.UpdateDetection(ctx, det)

	assert.Nil(t, postDet)
	assert.ErrorContains(t, err, "existing non-community detection")
}

func TestUpdateDetectionInvalid404(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	det := &model.Detection{
		Auditable: model.Auditable{
			Id:         "hJFpC44Bm7lAWCSuSwHa",
			CreateTime: util.Ptr(time.Now()),
		},
		Title:       "myTitle",
		Severity:    "low",
		Author:      "Jane Doe",
		Description: "myDescription",
		Content:     "myContent",
		IsEnabled:   true,
		IsReporting: true,
		IsCommunity: true,
		Ruleset:     util.Ptr("myRuleset"),
		Engine:      "suricata",
		Language:    "suricata",
		License:     "DRL",
		Tags:        []string{"myTag"},
	}

	body1 := `{"result":"updated", "_id":"ABC123"}`
	body2 := `{"result":"created", "_id":"DEF456"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	postDet, err := store.UpdateDetection(ctx, det)

	assert.Nil(t, postDet)
	assert.ErrorContains(t, err, "not found")
}

func TestDeleteDetectionValid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "hJFpC44Bm7lAWCSuSwHa",
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   true,
						"so_detection.isReporting": true,
						"so_detection.isCommunity": true,
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.createTime":  "2021-08-01T00:00:00Z",
						"so_kind":                  "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	body1 := `{"result":"updated", "_id":"hJFpC44Bm7lAWCSuSwHa"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	old, err := store.DeleteDetection(ctx, "hJFpC44Bm7lAWCSuSwHa")
	assert.NoError(t, err)

	assert.NotNil(t, old)
	assert.Equal(t, "hJFpC44Bm7lAWCSuSwHa", old.Id)
}

func TestDeleteDetectionInvalid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakesrv.Eventstore = server.NewFakeEventstore()
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	body1 := `{"result":"updated", "_id":"hJFpC44Bm7lAWCSuSwHa"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	old, err := store.DeleteDetection(ctx, "hJFpC44Bm7lAWCSuSwHa")
	assert.Nil(t, old)
	assert.ErrorContains(t, err, "not found")
}

func TestDoesTemplateExistValid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	mocktrans.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	exists, err := store.DoesTemplateExist(ctx, "myIndex")
	assert.NoError(t, err)
	assert.True(t, exists)

	reqs := mocktrans.GetRequests()

	assert.Equal(t, 1, len(reqs))

	req := reqs[0]
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "/_index_template/myIndex", req.URL.Path)
}

func TestDoesTemplateExistInvalid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	mocktrans.AddResponse(&http.Response{
		StatusCode: 404,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	exists, err := store.DoesTemplateExist(ctx, "myIndex")
	assert.NoError(t, err)
	assert.False(t, exists)

	reqs := mocktrans.GetRequests()

	assert.Equal(t, 1, len(reqs))

	req := reqs[0]
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "/_index_template/myIndex", req.URL.Path)
}

func TestGetDetectionById(t *testing.T) {
	t.Parallel()

	client, _ := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "hJFpC44Bm7lAWCSuSwHa",
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   true,
						"so_detection.isReporting": true,
						"so_detection.isCommunity": true,
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.createTime":  "2021-08-01T00:00:00Z",
						"so_kind":                  "detection",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	det, err := store.GetDetectionByPublicId(ctx, "123456")
	assert.NoError(t, err)
	assert.NotNil(t, det)

	assert.Equal(t, 1, len(fakeStore.InputSearchCriterias))
	assert.Contains(t, fakeStore.InputSearchCriterias[0].RawQuery, `so_detection.publicId:"123456"`)
}

func TestUpdateDetectionFieldValid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)

	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	id := "ABC123"
	body1 := fmt.Sprintf(`{"get": {"_source":{"so_detection": {"id": "%s"}}}}`, id)
	body2 := `{"result":"updated", "_id":"DEF456"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})
	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	det, err := store.UpdateDetectionField(ctx, id, map[string]interface{}{
		"isEnabled": true,
	})
	assert.NoError(t, err)
	assert.Equal(t, id, det.Id)

	reqs := mocktrans.GetRequests()
	assert.Equal(t, 2, len(reqs))

	m := map[string]interface{}{}
	err = json.NewDecoder(reqs[0].Body).Decode(&m)

	assert.NoError(t, err)
	assert.Equal(t, `ctx._source.so_detection.isEnabled=true; ctx._source.so_detection.userId='myRequestorId'`, m["script"])
}

func TestUpdateDetectionFieldInvalid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)

	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	det, err := store.UpdateDetectionField(ctx, "ABC123", map[string]interface{}{
		"isCommunity": true,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported field: isCommunity")
	assert.Nil(t, det)

	reqs := mocktrans.GetRequests()
	assert.Equal(t, 0, len(reqs))
}

func TestGetAllCommunitySIDs(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "ABC123",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.isEnabled":   true,
						"so_detection.isReporting": true,
						"so_detection.isCommunity": true,
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.tags":        []interface{}{"myTag"},
						"so_detection.createTime":  "2021-08-01T00:00:00Z",
						"so_detection.overrides": []interface{}{
							map[string]interface{}{
								"createdAt": "2021-08-01T00:00:00Z",
								"updatedAt": "2021-08-01T00:00:00Z",
							},
						},
						"so_kind": "detection",
					},
				},
			},
		},
		{ // When querying for unlimited things, we need one search request that returns 0 results
			// or we get an infinite loop
			TotalEvents: 0,
		},
	}

	// double up the results, we're calling the function twice
	fakeStore.SearchResults = append(fakeStore.SearchResults, fakeStore.SearchResults...)

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	body := `{"hits": {"hits": [{"_source": {"so_detection": {"id": "ABC123"}}}]}}`

	// also twice
	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body)),
	})
	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	sids, err := store.GetAllCommunitySIDs(ctx, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sids))
	assert.NotNil(t, sids["ABC123"])

	sids, err = store.GetAllCommunitySIDs(ctx, util.Ptr(model.EngineName("suricata")))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sids))
	assert.NotNil(t, sids["ABC123"])

	criteria := fakeStore.InputSearchCriterias[0].RawQuery
	assert.Contains(t, criteria, `_index:"myIndex" AND so_kind:"detection"`)
	assert.NotContains(t, criteria, "detection.engine")

	criteria = fakeStore.InputSearchCriterias[2].RawQuery
	assert.Contains(t, criteria, `_index:"myIndex" AND so_kind:"detection" AND so_detection.engine:"suricata"`)
	assert.Contains(t, criteria, "detection.engine")
}

func TestGetDetectionHistory(t *testing.T) {
	t.Parallel()

	client, _ := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "ABC123",
					Payload: map[string]interface{}{
						"so_detection.userId":      "myRequestorId",
						"so_detection.publicId":    "",
						"so_detection.title":       "myTitle",
						"so_detection.severity":    "low",
						"so_detection.author":      "Jane Doe",
						"so_detection.description": "myDescription",
						"so_detection.content":     "myContent",
						"so_detection.ruleset":     "myRuleset",
						"so_detection.engine":      "suricata",
						"so_detection.language":    "suricata",
						"so_detection.license":     "DRL",
						"so_detection.createTime":  "2021-08-01T00:00:00Z",
						"so_kind":                  "detection",
					},
				},
				{
					Id: "DEF456",
					Payload: map[string]interface{}{
						"so_detectioncomment.value":       "First!",
						"so_detectioncomment.userId":      "myRequestorId",
						"so_detectioncomment.createTime":  "2021-08-01T00:00:00Z",
						"so_detectioncomment.detectionId": "ABC123",
						"so_kind":                         "detectioncomment",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	history, err := store.GetDetectionHistory(ctx, "ABC123")
	assert.NoError(t, err)

	assert.Equal(t, 2, len(history))
	assert.IsType(t, &model.Detection{}, history[0])
	assert.IsType(t, &model.DetectionComment{}, history[1])

	query := fakeStore.InputSearchCriterias[0].RawQuery
	assert.Contains(t, query, `audit_doc_id:"ABC123"`)
	assert.Contains(t, query, `detectioncomment.detectionId:"ABC123"`)
	assert.Contains(t, query, `_index:"myAuditIndex"`)
}

func TestCreateDetectionComment(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "ABC123",
					Payload: map[string]interface{}{
						"so_kind": "detection",
					},
				},
			},
		},
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "DEF456",
					Payload: map[string]interface{}{
						"so_kind": "detectioncomment",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	comment := &model.DetectionComment{
		Value:       "First!",
		DetectionId: "ABC123",
	}

	body1 := `{"result":"created", "_id":"DEF456"}`
	body2 := `{"result":"created", "_id":"GHI789"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})
	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	postComment, err := store.CreateComment(ctx, comment)
	assert.NoError(t, err)

	assert.NotNil(t, postComment)
}

func TestGetDetectionComments(t *testing.T) {
	t.Parallel()

	client, _ := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "DEF456",
					Payload: map[string]interface{}{
						"so_kind": "detectioncomment",
					},
				},
				{
					Id: "GHI789",
					Payload: map[string]interface{}{
						"so_kind": "detectioncomment",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	comments, err := store.GetComments(ctx, "ABC123")
	assert.NoError(t, err)

	assert.Equal(t, 2, len(comments))

	assert.Equal(t, 1, len(fakeStore.InputSearchCriterias))

	query := fakeStore.InputSearchCriterias[0].RawQuery

	assert.Contains(t, query, `detectioncomment.detectionId:"ABC123"`)
	assert.Contains(t, query, `kind:"detectioncomment"`)
}

func TestUpdateDetectionCommentValid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "ABC123",
					Payload: map[string]interface{}{
						"so_kind":                        "detectioncomment",
						"so_detectioncomment.createTime": "2021-08-01T00:00:00Z",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	body1 := `{"result":"updated", "_id":"ABC123"}`
	body2 := `{"result":"created", "_id":"DEF456"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})
	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	comment := &model.DetectionComment{
		Auditable: model.Auditable{
			Id: "ABC123",
		},
		Value:       "First!",
		DetectionId: "DEF456",
	}

	postComment, err := store.UpdateComment(ctx, comment)
	assert.NoError(t, err)

	assert.NotNil(t, postComment)
	assert.NotNil(t, postComment.CreateTime)
	assert.Equal(t, 2, len(fakeStore.InputSearchCriterias))
}

func TestUpdateDetectionCommentInvalid(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 0,
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	comment := &model.DetectionComment{
		Auditable: model.Auditable{
			Id: "ABC123",
		},
		Value:       "First!",
		DetectionId: "DEF456",
	}

	postComment, err := store.UpdateComment(ctx, comment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	assert.Nil(t, postComment)
	assert.Equal(t, 1, len(fakeStore.InputSearchCriterias))

	reqs := mocktrans.GetRequests()
	assert.Equal(t, 0, len(reqs))
}

func TestDeleteDetectionComment(t *testing.T) {
	t.Parallel()

	client, mocktrans := newMockClient(t)
	fakesrv := server.NewFakeAuthorizedServer(nil)
	fakeStore := server.NewFakeEventstore()

	fakeStore.SearchResults = []*model.EventSearchResults{
		{
			TotalEvents: 1,
			Events: []*model.EventRecord{
				{
					Id: "ABC123",
					Payload: map[string]interface{}{
						"so_kind":                        "detectioncomment",
						"so_detectioncomment.createTime": "2021-08-01T00:00:00Z",
					},
				},
			},
		},
	}

	fakesrv.Eventstore = fakeStore
	store := NewElasticDetectionstore(fakesrv, client, 100)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	body1 := `{"result":"deleted", "_id":"ABC123"}`
	body2 := `{"result":"created", "_id":"DEF456"}`

	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body1)),
	})
	mocktrans.AddResponse(&http.Response{
		Body: io.NopCloser(strings.NewReader(body2)),
	})

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	err := store.DeleteComment(ctx, "ABC123")
	assert.NoError(t, err)

	reqs := mocktrans.GetRequests()

	assert.Equal(t, 2, len(reqs))
	assert.Equal(t, http.MethodDelete, reqs[0].Method)
}

func extractSoDetectionFromRequestBody(t *testing.T, req *http.Request) *model.Detection {
	rawBody, err := io.ReadAll(req.Body)
	assert.NoError(t, err)

	reqDet := &model.Detection{}

	rawDet := gjson.Get(string(rawBody), "so_detection").Raw

	err = json.Unmarshal([]byte(rawDet), &reqDet)
	assert.NoError(t, err)

	return reqDet
}
