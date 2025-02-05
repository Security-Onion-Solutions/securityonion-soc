package server_test

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestHandlerCreateEvents(t *testing.T) {
	tests := []struct {
		Name         string
		RequestBody  []byte
		InitMock     func(*Server, *gomock.Controller, *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster)
		MockCheck    func(*Server)
		Code         int
		ResponseBody any
		Logs         []EntryMatcher
		Broadcasts   []BroadcastMatcher
	}{
		{
			Name:        "Sunny Day",
			RequestBody: []byte(`{"caseId": "123", "dateRange": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM", "dateRangeFormat": "2006/01/02 3:04:05 PM", "fields": {"count": "30", "rule.name": "GPL NETBIOS SMB-DS IPC$ unicode share access", "event.module": "suricata", "event.severity_label": "low", "rule.uuid": "2102466"}}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller, nonAsyncWG *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)
				mHostAuth := srv.Host.Authorizer.(*rbac.FakeAuthorizer)

				srv.Config.ClientParams.AlertingParams.MaxBulkEscalateEvents = 100

				fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, &model.EventSearchResults{
					TotalEvents: 2,
					Events: []*model.EventRecord{
						{
							Id: "1",
							Payload: map[string]interface{}{
								"@timestamp": specificTime,
							},
						},
						{
							Id: "2",
							Payload: map[string]interface{}{
								"@timestamp": specificTime,
							},
						},
					},
				})

				fakeCaseStore := srv.Casestore.(*mock.MockCasestore)
				fakeCaseStore.EXPECT().CreateRelatedEvents(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, events []*model.RelatedEvent) (int, map[string]error, error) {
					nonAsyncWG.Wait()

					assert.Equal(t, "test", ctx.Value(web.ContextKeyRunAsUsername))
					assert.Equal(t, "00000000-0000-0000-0000-000000000000", ctx.Value(web.ContextKeyRequestorId))
					_, hasDeadline := ctx.Deadline()
					assert.False(t, hasDeadline)

					assert.Equal(t, 2, len(events))
					assert.Equal(t, "123", events[0].CaseId)
					assert.Equal(t, "1", events[0].Fields["soc_id"])
					assert.Equal(t, specificTime, events[0].Fields["soc_timestamp"])
					assert.Equal(t, "123", events[1].CaseId)
					assert.Equal(t, "2", events[1].Fields["soc_id"])
					assert.Equal(t, specificTime, events[1].Fields["soc_timestamp"])

					return 2, nil, nil
				})

				asyncWG := &sync.WaitGroup{}
				asyncWG.Add(1)

				mHostAuth.Authorized = true

				mb := MockBroadcast(t, srv, func(bm BroadcastMessage) {
					asyncWG.Done()
				})

				return asyncWG, mb
			},
			MockCheck: func(srv *Server) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)

				assert.Len(t, fakeEventStore.InputSearchCriterias, 1)

				searchCriteria := fakeEventStore.InputSearchCriterias[0]
				assert.Contains(t, searchCriteria.RawQuery, `rule.name:"GPL NETBIOS SMB-DS IPC$ unicode share access"`)
				assert.Contains(t, searchCriteria.RawQuery, `event.module:"suricata"`)
				assert.Contains(t, searchCriteria.RawQuery, `event.severity_label:"low"`)
				assert.Contains(t, searchCriteria.RawQuery, `rule.uuid:"2102466"`)
				assert.Contains(t, searchCriteria.RawQuery, ` AND `)
				assert.Contains(t, searchCriteria.RawQuery, `NOT event.acknowledged:true`)
				assert.Contains(t, searchCriteria.RawQuery, `NOT event.escalated:true`)
				assert.NotContains(t, searchCriteria.RawQuery, ` OR `)
				assert.NotContains(t, searchCriteria.RawQuery, `count:"30"`)

				assert.Equal(t, 100, searchCriteria.EventLimit)

				assert.Equal(t, "2024-12-03T14:31:35Z", searchCriteria.BeginTime.Format("2006-01-02T15:04:05Z"))
				assert.Equal(t, "2024-12-04T14:31:35Z", searchCriteria.EndTime.Format("2006-01-02T15:04:05Z"))

				sort := searchCriteria.SortFields
				assert.Len(t, sort, 1)
				assert.Equal(t, "@timestamp", sort[0].Field)
				assert.Equal(t, "desc", sort[0].Order)
			},
			Code:         202,
			ResponseBody: []byte(`{"count":2}`),
			Logs: []EntryMatcher{
				handled,
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageContains("created related events"),
					LogFieldEq("test", true),
					LogFieldExists("errMap"),
				),
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogFieldEq("test", true),
					LogFieldEq("totalRequested", 2),
					LogFieldEq("totalCreated", 2),
					LogFieldExists("totalTime"),
					LogFieldExists("errMap"),
				),
			},
			Broadcasts: []BroadcastMatcher{
				NewBroadcastMatcher(
					BroadcastKindEq("related:bulkCreate"),
					BroadcastObjectFieldEq("verb", "create"),
					BroadcastObjectFieldEq("total", 2.0),
					BroadcastObjectFieldEq("modified", 2.0),
					BroadcastObjectFieldEq("error", 0.0),
				),
			},
		},
		{
			Name:        "Escalate Single Event",
			RequestBody: []byte(`{"caseId": "123", "dateRange": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM", "dateRangeFormat": "2006/01/02 3:04:05 PM", "fields": {"soc_id": "456", "event.severity_label": "low", "rule.uuid": "2102466"}, "acknowledge": true, "escalate": true}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller, nonAsyncWG *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)
				mHostAuth := srv.Host.Authorizer.(*rbac.FakeAuthorizer)

				fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, &model.EventSearchResults{
					TotalEvents: 1,
					Events: []*model.EventRecord{
						{
							Id:      "456",
							Payload: map[string]interface{}{},
						},
					},
				})

				fakeCaseStore := srv.Casestore.(*mock.MockCasestore)
				fakeCaseStore.EXPECT().CreateRelatedEvents(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, events []*model.RelatedEvent) (int, map[string]error, error) {
					nonAsyncWG.Wait()

					assert.Equal(t, "test", ctx.Value(web.ContextKeyRunAsUsername))
					assert.Equal(t, "00000000-0000-0000-0000-000000000000", ctx.Value(web.ContextKeyRequestorId))
					_, hasDeadline := ctx.Deadline()
					assert.False(t, hasDeadline)

					assert.Equal(t, 1, len(events))
					assert.Equal(t, "123", events[0].CaseId)
					assert.Equal(t, "456", events[0].Fields["soc_id"])

					return 1, nil, nil
				})

				asyncWG := &sync.WaitGroup{}
				asyncWG.Add(1)

				mHostAuth.Authorized = true

				mb := MockBroadcast(t, srv, func(bm BroadcastMessage) {
					asyncWG.Done()
				})

				return asyncWG, mb
			},
			MockCheck: func(srv *Server) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)

				assert.Len(t, fakeEventStore.InputSearchCriterias, 1)

				searchCriteria := fakeEventStore.InputSearchCriterias[0]
				assert.Contains(t, searchCriteria.RawQuery, `_id:"456"`)
				assert.NotContains(t, searchCriteria.RawQuery, ` OR `)
				// searching for a single event doesn't care what state that event is in
				assert.NotContains(t, searchCriteria.RawQuery, `event.acknowledged:true`)
				assert.NotContains(t, searchCriteria.RawQuery, `event.escalated:true`)

				assert.Equal(t, "2024-12-03T14:31:35Z", searchCriteria.BeginTime.Format("2006-01-02T15:04:05Z"))
				assert.Equal(t, "2024-12-04T14:31:35Z", searchCriteria.EndTime.Format("2006-01-02T15:04:05Z"))

				sort := searchCriteria.SortFields
				assert.Len(t, sort, 1)
				assert.Equal(t, "@timestamp", sort[0].Field)
				assert.Equal(t, "desc", sort[0].Order)
			},
			Code:         202,
			ResponseBody: []byte(`{"count":1}`),
			Logs: []EntryMatcher{
				handled,
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageContains("created related events"),
					LogFieldEq("test", true),
					LogFieldExists("errMap"),
				),
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogFieldEq("test", true),
					LogFieldEq("totalRequested", 1),
					LogFieldEq("totalCreated", 1),
					LogFieldExists("totalTime"),
					LogFieldExists("errMap"),
				),
			},
		},
		{
			Name:        "Invalid Body",
			RequestBody: []byte(`JSON goes here`),
			InitMock: func(srv *Server, ctrl *gomock.Controller, nonAsyncWG *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster) {
				return nil, nil
			},
			MockCheck:    func(srv *Server) {},
			Code:         400,
			ResponseBody: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:        "Search Fails",
			RequestBody: []byte(`{"caseId": "123", "dateRange": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM", "dateRangeFormat": "2006/01/02 3:04:05 PM", "fields": {"count": "30", "rule.name": "GPL NETBIOS SMB-DS IPC$ unicode share access", "event.module": "suricata", "event.severity_label": "low", "rule.uuid": "2102466"}}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller, nonAsyncWG *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)

				fakeEventStore.Err = errors.New("something went wrong")
				fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, &model.EventSearchResults{})

				return nil, nil
			},
			MockCheck:    func(srv *Server) {},
			Code:         500,
			ResponseBody: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:        "Nearly Sunny Day (errMap errors)",
			RequestBody: []byte(`{"caseId": "123", "dateRange": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM", "dateRangeFormat": "2006/01/02 3:04:05 PM", "fields": {"count": "30", "rule.name": "GPL NETBIOS SMB-DS IPC$ unicode share access", "event.module": "suricata", "event.severity_label": "low", "rule.uuid": "2102466"}}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller, nonAsyncWG *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)
				mHostAuth := srv.Host.Authorizer.(*rbac.FakeAuthorizer)

				fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, &model.EventSearchResults{
					TotalEvents: 2,
					Events: []*model.EventRecord{
						{
							Id: "1",
							Payload: map[string]interface{}{
								"@timestamp": specificTime,
							},
						},
						{
							Id: "2",
							Payload: map[string]interface{}{
								"@timestamp": specificTime,
							},
						},
					},
				})

				fakeCaseStore := srv.Casestore.(*mock.MockCasestore)
				fakeCaseStore.EXPECT().CreateRelatedEvents(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, events []*model.RelatedEvent) (int, map[string]error, error) {
					nonAsyncWG.Wait()

					assert.Equal(t, "test", ctx.Value(web.ContextKeyRunAsUsername))
					assert.Equal(t, "00000000-0000-0000-0000-000000000000", ctx.Value(web.ContextKeyRequestorId))
					_, hasDeadline := ctx.Deadline()
					assert.False(t, hasDeadline)

					assert.Equal(t, 2, len(events))
					assert.Equal(t, "123", events[0].CaseId)
					assert.Equal(t, "1", events[0].Fields["soc_id"])
					assert.Equal(t, specificTime, events[0].Fields["soc_timestamp"])
					assert.Equal(t, "123", events[1].CaseId)
					assert.Equal(t, "2", events[1].Fields["soc_id"])
					assert.Equal(t, specificTime, events[1].Fields["soc_timestamp"])

					return 1, map[string]error{
						"2": errors.New("something went wrong"),
					}, nil
				})

				asyncWG := &sync.WaitGroup{}
				asyncWG.Add(1)

				mHostAuth.Authorized = true

				mb := MockBroadcast(t, srv, func(bm BroadcastMessage) {
					asyncWG.Done()
				})

				return asyncWG, mb
			},
			MockCheck: func(srv *Server) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)

				assert.Len(t, fakeEventStore.InputSearchCriterias, 1)

				searchCriteria := fakeEventStore.InputSearchCriterias[0]
				assert.Contains(t, searchCriteria.RawQuery, `rule.name:"GPL NETBIOS SMB-DS IPC$ unicode share access"`)
				assert.Contains(t, searchCriteria.RawQuery, `event.module:"suricata"`)
				assert.Contains(t, searchCriteria.RawQuery, `event.severity_label:"low"`)
				assert.Contains(t, searchCriteria.RawQuery, `rule.uuid:"2102466"`)
				assert.Contains(t, searchCriteria.RawQuery, ` AND `)
				assert.NotContains(t, searchCriteria.RawQuery, ` OR `)
				assert.NotContains(t, searchCriteria.RawQuery, `count:"30"`)

				assert.Equal(t, "2024-12-03T14:31:35Z", searchCriteria.BeginTime.Format("2006-01-02T15:04:05Z"))
				assert.Equal(t, "2024-12-04T14:31:35Z", searchCriteria.EndTime.Format("2006-01-02T15:04:05Z"))

				sort := searchCriteria.SortFields
				assert.Len(t, sort, 1)
				assert.Equal(t, "@timestamp", sort[0].Field)
				assert.Equal(t, "desc", sort[0].Order)
			},
			Code:         202,
			ResponseBody: []byte(`{"count":2}`),
			Logs: []EntryMatcher{
				handled,
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageContains("created related events"),
					LogFieldEq("test", true),
					LogFieldExists("errMap"),
				),
				NewEntryMatcher(
					LogLevelEq(log.ErrorLevel),
					LogFieldEq("test", true),
					LogFieldEq("totalRequested", 2),
					LogFieldEq("totalCreated", 1),
					LogFieldExists("totalTime"),
					LogFieldExists("errMap"),
				),
			},
			Broadcasts: []BroadcastMatcher{
				NewBroadcastMatcher(
					BroadcastKindEq("related:bulkCreate"),
					BroadcastObjectFieldEq("verb", "create"),
					BroadcastObjectFieldEq("total", 2.0),
					BroadcastObjectFieldEq("modified", 1.0),
					BroadcastObjectFieldEq("error", 1.0),
				),
			},
		},
		{
			Name:        "Error During Async Portion",
			RequestBody: []byte(`{"caseId": "123", "dateRange": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM", "dateRangeFormat": "2006/01/02 3:04:05 PM", "fields": {"count": "30", "rule.name": "GPL NETBIOS SMB-DS IPC$ unicode share access", "event.module": "suricata", "event.severity_label": "low", "rule.uuid": "2102466"}}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller, nonAsyncWG *sync.WaitGroup) (*sync.WaitGroup, *MockBroadcaster) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)
				mHostAuth := srv.Host.Authorizer.(*rbac.FakeAuthorizer)

				fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, &model.EventSearchResults{
					TotalEvents: 2,
					Events: []*model.EventRecord{
						{
							Id: "1",
							Payload: map[string]interface{}{
								"@timestamp": specificTime,
							},
						},
						{
							Id: "2",
							Payload: map[string]interface{}{
								"@timestamp": specificTime,
							},
						},
					},
				})

				fakeCaseStore := srv.Casestore.(*mock.MockCasestore)
				fakeCaseStore.EXPECT().CreateRelatedEvents(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, events []*model.RelatedEvent) (int, map[string]error, error) {
					nonAsyncWG.Wait()

					assert.Equal(t, "test", ctx.Value(web.ContextKeyRunAsUsername))
					assert.Equal(t, "00000000-0000-0000-0000-000000000000", ctx.Value(web.ContextKeyRequestorId))
					_, hasDeadline := ctx.Deadline()
					assert.False(t, hasDeadline)

					assert.Equal(t, 2, len(events))
					assert.Equal(t, "123", events[0].CaseId)
					assert.Equal(t, "1", events[0].Fields["soc_id"])
					assert.Equal(t, specificTime, events[0].Fields["soc_timestamp"])
					assert.Equal(t, "123", events[1].CaseId)
					assert.Equal(t, "2", events[1].Fields["soc_id"])
					assert.Equal(t, specificTime, events[1].Fields["soc_timestamp"])

					return 1, map[string]error{
						"2": errors.New("something went wrong"),
					}, errors.New("something went REALLY wrong")
				})

				asyncWG := &sync.WaitGroup{}
				asyncWG.Add(1)

				mHostAuth.Authorized = true

				mb := MockBroadcast(t, srv, func(bm BroadcastMessage) {
					asyncWG.Done()
				})

				return asyncWG, mb
			},
			MockCheck: func(srv *Server) {
				fakeEventStore := srv.Eventstore.(*FakeEventstore)

				assert.Len(t, fakeEventStore.InputSearchCriterias, 1)

				searchCriteria := fakeEventStore.InputSearchCriterias[0]
				assert.Contains(t, searchCriteria.RawQuery, `rule.name:"GPL NETBIOS SMB-DS IPC$ unicode share access"`)
				assert.Contains(t, searchCriteria.RawQuery, `event.module:"suricata"`)
				assert.Contains(t, searchCriteria.RawQuery, `event.severity_label:"low"`)
				assert.Contains(t, searchCriteria.RawQuery, `rule.uuid:"2102466"`)
				assert.Contains(t, searchCriteria.RawQuery, ` AND `)
				assert.NotContains(t, searchCriteria.RawQuery, ` OR `)
				assert.NotContains(t, searchCriteria.RawQuery, `count:"30"`)

				assert.Equal(t, "2024-12-03T14:31:35Z", searchCriteria.BeginTime.Format("2006-01-02T15:04:05Z"))
				assert.Equal(t, "2024-12-04T14:31:35Z", searchCriteria.EndTime.Format("2006-01-02T15:04:05Z"))

				sort := searchCriteria.SortFields
				assert.Len(t, sort, 1)
				assert.Equal(t, "@timestamp", sort[0].Field)
				assert.Equal(t, "desc", sort[0].Order)
			},
			Code:         202,
			ResponseBody: []byte(`{"count":2}`),
			Logs: []EntryMatcher{
				handled,
				NewEntryMatcher(
					LogLevelEq(log.ErrorLevel),
					LogMessageEq("failed to create related events"),
					LogFieldEq("test", true),
					LogFieldEq("errMap", map[string]error{
						"2": errors.New("something went wrong"),
					}),
					LogFieldEq("error", "something went REALLY wrong"),
				),
				NewEntryMatcher(
					LogLevelEq(log.ErrorLevel),
					LogMessageEq("bulk create related events finished"),
					LogFieldEq("test", true),
					LogFieldEq("totalRequested", 2),
					LogFieldEq("totalCreated", 1),
					LogFieldExists("totalTime"),
					LogFieldExists("errMap"),
				),
			},
			Broadcasts: []BroadcastMatcher{
				NewBroadcastMatcher(
					BroadcastKindEq("related:bulkCreate"),
					BroadcastObjectFieldEq("verb", "create"),
					BroadcastObjectFieldEq("total", 2.0),
					BroadcastObjectFieldEq("modified", 1.0),
					BroadcastObjectFieldEq("error", 1.0),
				),
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewCaseHandler(srv)

			nonAsyncWG := &sync.WaitGroup{}
			nonAsyncWG.Add(1)

			asyncWG, mb := test.InitMock(srv, ctrl, nonAsyncWG)

			ctx := NewTestContext(nil)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "test")
			ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "00000000-0000-0000-0000-000000000000")

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "GET", "/case/events", bytes.NewReader(test.RequestBody))

			h.CreateEvents(w, r)
			nonAsyncWG.Done()

			if asyncWG != nil {
				asyncWG.Wait()
			}

			test.MockCheck(srv)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.ResponseBody.(type) {
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
			}

			if test.Logs != nil {
				if len(test.Logs) != len(mem.Entries) {
					t.Fatalf("Expected %d log entries, got %d", len(test.Logs), len(mem.Entries))
				}

				for i, matcher := range test.Logs {
					err := matcher.Validate(mem.Entries[i])
					if err != nil {
						t.Fatalf("Log entry %d is invalid: %s", i, err)
					}
				}
			}

			if test.Broadcasts != nil {
				if mb == nil {
					t.Fatalf("Expected broadcast messages, but no broadcaster was created")
				}
				if len(test.Broadcasts) != len(mb.Messages) {
					t.Fatalf("Expected %d broadcast messages, got %d", len(test.Broadcasts), len(mb.Messages))
				}

				for i, matcher := range test.Broadcasts {
					err := matcher.Validate(mb.Messages[i])
					if err != nil {
						t.Fatalf("Broadcast message %d is invalid: %s", i, err)
					}
				}
			}
		})
	}
}
