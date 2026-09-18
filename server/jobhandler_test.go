// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func newJobTestRequest(method, target string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())
	return req.WithContext(ctx)
}

func setupJobTestServer() (*Server, *FakeDatastore, *FakeNotifier) {
	srv := NewFakeAuthorizedServer(nil)
	fakeDs := srv.Datastore.(*FakeDatastore)
	fakeNotif := NewFakeNotifier()
	srv.Notifier = fakeNotif

	return srv, fakeDs, fakeNotif
}

func TestJobHandler_GetJob(t *testing.T) {
	srv, fakeDs, _ := setupJobTestServer()
	r := chi.NewRouter()
	RegisterJobRoutes(srv, r, "/job")

	// 1. Success
	targetJob := &model.Job{
		Id:     1001,
		Status: model.JobStatusCompleted,
		Kind:   "pcap",
	}
	fakeDs.GetJobResult = targetJob

	req := newJobTestRequest("GET", "/job/1001", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resJob model.Job
	err := json.Unmarshal(w.Body.Bytes(), &resJob)
	assert.NoError(t, err)
	assert.Equal(t, 1001, resJob.Id)

	// 2. Query param fallback
	req = newJobTestRequest("GET", "/job?jobId=1001", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// 3. Invalid Job ID (non-integer)
	req = newJobTestRequest("GET", "/job/invalid-id", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// 4. Job Not Found
	fakeDs.GetJobResult = nil
	req = newJobTestRequest("GET", "/job/9999", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestJobHandler_PostJob(t *testing.T) {
	srv, fakeDs, _ := setupJobTestServer()
	r := chi.NewRouter()
	RegisterJobRoutes(srv, r, "/job")

	// 1. Success
	jobData := map[string]interface{}{
		"kind":   "pcap",
		"nodeId": "sensor-1",
	}
	body, _ := json.Marshal(jobData)
	req := newJobTestRequest("POST", "/job/", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotNil(t, fakeDs.LastAddedJob)
	assert.Equal(t, "sensor-1", fakeDs.LastAddedJob.NodeId)

	// 2. Invalid JSON body
	req = newJobTestRequest("POST", "/job/", []byte("invalid-json{"))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// 3. AddJob datastore error
	fakeDs.AddJobErr = errors.New("cannot add job")
	req = newJobTestRequest("POST", "/job/", body)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestJobHandler_PutJob_And_NotificationTrigger(t *testing.T) {
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv, fakeDs, fakeNotif := setupJobTestServer()
	r := chi.NewRouter()
	RegisterJobRoutes(srv, r, "/job")

	// 1. Update job to completed -> triggers notification
	jobData := &model.Job{
		Id:     1002,
		Status: model.JobStatusCompleted,
		Kind:   "pcap",
		NodeId: "sensor-001",
		UserId: "user-id-1",
	}
	body, _ := json.Marshal(jobData)
	req := newJobTestRequest("PUT", "/job/", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, fakeDs.LastUpdatedJob)

	// Give goroutine a moment to dispatch notification
	time.Sleep(50 * time.Millisecond)
	assert.Len(t, fakeNotif.InputPayloads, 1)
	assert.Equal(t, model.SourcePcap, fakeNotif.InputPayloads[0].Source)
	assert.Equal(t, "PCAP #1002 (user1@somewhere.invalid)", fakeNotif.InputPayloads[0].Title)
	assert.Empty(t, fakeNotif.InputPayloads[0].Summary)
	assert.Equal(t, "user1@somewhere.invalid", fakeNotif.InputPayloads[0].Fields["user"])
	assert.Equal(t, "/#/job/1002", fakeNotif.InputPayloads[0].Links["👁"])
	assert.Equal(t, "/api/stream/1002?ext=pcap", fakeNotif.InputPayloads[0].Links["⬇"])

	// 2. Update job to pending/incomplete -> does not trigger notification
	fakeNotif.InputPayloads = nil
	pendingJobData := &model.Job{
		Id:     1003,
		Status: model.JobStatusIncomplete,
		Kind:   "pcap",
		NodeId: "sensor-001",
	}
	body, _ = json.Marshal(pendingJobData)
	req = newJobTestRequest("PUT", "/job/", body)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	time.Sleep(20 * time.Millisecond)
	assert.Empty(t, fakeNotif.InputPayloads)

	// 3. Invalid JSON
	req = newJobTestRequest("PUT", "/job/", []byte("invalid-json{"))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// 4. Datastore Update error (404)
	fakeDs.UpdateJobErr = errors.New("Job not found")
	req = newJobTestRequest("PUT", "/job/", body)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestJobHandler_DeleteJob(t *testing.T) {
	srv, fakeDs, _ := setupJobTestServer()
	r := chi.NewRouter()
	RegisterJobRoutes(srv, r, "/job")

	// 1. Success
	req := newJobTestRequest("DELETE", "/job/1004", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1004, fakeDs.LastDeletedJobId)

	// 2. Invalid jobId
	req = newJobTestRequest("DELETE", "/job/invalid-id", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// 3. DeleteJob datastore error
	fakeDs.DeleteJobErr = errors.New("permission denied")
	req = newJobTestRequest("DELETE", "/job/1004", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
