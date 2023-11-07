// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type ElasticDetectionstore struct {
	server          *server.Server
	index           string
	auditIndex      string
	maxAssociations int
	schemaPrefix    string
}

func NewElasticDetectionstore(srv *server.Server) *ElasticDetectionstore {
	return &ElasticDetectionstore{
		server: srv,
	}
}

func (store *ElasticDetectionstore) Init(index string, auditIndex string, maxAssociations int, schemaPrefix string) error {
	store.index = index
	store.auditIndex = auditIndex
	store.maxAssociations = maxAssociations
	store.schemaPrefix = schemaPrefix

	return nil
}

func (store *ElasticDetectionstore) validateId(id string, label string) error {
	var err error

	isValidId := regexp.MustCompile(`^[A-Za-z0-9-_]{5,50}$`).MatchString
	if !isValidId(id) {
		err = fmt.Errorf("invalid ID for %s", label)
	}

	return err
}

func (store *ElasticDetectionstore) validateString(str string, max int, label string) error {
	return store.validateStringRequired(str, 0, max, label)
}

func (store *ElasticDetectionstore) validateStringRequired(str string, min int, max int, label string) error {
	var err error

	length := len(str)
	if length > max {
		err = errors.New(fmt.Sprintf("%s is too long (%d/%d)", label, length, max))
	} else if length < min {
		err = errors.New(fmt.Sprintf("%s is too short (%d/%d)", label, length, min))
	}

	return err
}

func (store *ElasticDetectionstore) validateDetection(detect *model.Detection) error {
	var err error

	if err == nil && detect.Id != "" {
		err = store.validateId(detect.Id, "onionId")
	}

	if err == nil && detect.PublicID != "" {
		err = store.validateId(detect.PublicID, "publicId")
	}

	if err == nil && detect.Title != "" {
		err = store.validateString(detect.Title, LONG_STRING_MAX, "title")
	}

	if err == nil && detect.Severity != "" {
		err = store.validateString(string(detect.Severity), SHORT_STRING_MAX, "severity")
	}

	if err == nil && detect.Author != "" {
		err = store.validateString(detect.Author, SHORT_STRING_MAX, "author")
	}

	if err == nil && detect.Description != "" {
		err = store.validateString(detect.Description, LONG_STRING_MAX, "description")
	}

	if err == nil && detect.Content != "" {
		err = store.validateString(detect.Content, LONG_STRING_MAX, "content")
	}

	if err == nil && detect.Note != "" {
		err = store.validateString(detect.Note, LONG_STRING_MAX, "note")
	}

	if err == nil {
		_, okEngine := model.EnginesByName[detect.Engine]
		if !okEngine {
			err = errors.New("invalid engine")
		}
	}

	return err
}

func (store *ElasticDetectionstore) save(ctx context.Context, obj interface{}, kind string, id string) (*model.EventIndexResults, error) {
	var results *model.EventIndexResults
	var err error

	// if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
	document := convertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	results, err = store.server.Eventstore.Index(ctx, store.index, document, id)
	if err == nil {
		document[store.schemaPrefix+AUDIT_DOC_ID] = results.DocumentId

		if id == "" {
			document[store.schemaPrefix+"operation"] = "create"
		} else {
			document[store.schemaPrefix+"operation"] = "update"
		}

		_, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
		if err != nil {
			log.WithFields(log.Fields{
				"documentId": results.DocumentId,
				"kind":       kind,
			}).WithError(err).Error("Object indexed successfully however audit record failed to index")
		}
	}
	// }

	return results, err
}

func (store *ElasticDetectionstore) delete(ctx context.Context, obj interface{}, kind string, id string) error {
	var err error

	// if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
	err = store.server.Eventstore.Delete(ctx, store.index, id)
	if err == nil {
		document := convertObjectToDocumentMap(kind, obj, store.schemaPrefix)
		document[store.schemaPrefix+AUDIT_DOC_ID] = id
		document[store.schemaPrefix+"kind"] = kind
		document[store.schemaPrefix+"operation"] = "delete"

		_, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
		if err != nil {
			log.WithFields(log.Fields{
				"documentId": id,
				"kind":       kind,
			}).WithError(err).Error("Object deleted successfully however audit record failed to index")
		}
	}
	// }

	return err
}

func (store *ElasticDetectionstore) get(ctx context.Context, id string, kind string) (interface{}, error) {
	query := fmt.Sprintf(`_index:"%s" AND %skind:"%s" AND _id:"%s"`, store.index, store.schemaPrefix, kind, id)

	objects, err := store.getAll(ctx, query, 1)
	if err == nil {
		if len(objects) > 0 {
			return objects[0], err
		}

		err = errors.New("Object not found")
	}

	return nil, err
}

func (store *ElasticDetectionstore) getAll(ctx context.Context, query string, max int) ([]interface{}, error) {
	var err error
	var objects []interface{}

	// if err = store.server.CheckAuthorized(ctx, "read", "cases"); err == nil {
	criteria := model.NewEventSearchCriteria()
	format := "2006-01-02 3:04:05 PM"

	var zeroTime time.Time

	zeroTimeStr := zeroTime.Format(format)
	now := time.Now()
	endTime := now.Format(format)
	zone := now.Location().String()

	unlimited := false
	if max == -1 {
		max = 10000
		unlimited = true
	}

	sort := []interface{}{}

	for {
		err = criteria.Populate(query,
			zeroTimeStr+" - "+endTime, // timeframe range
			format,                    // timeframe format
			zone,                      // timezone
			"0",                       // no metrics
			strconv.Itoa(max))

		if err != nil {
			return nil, err
		}

		if unlimited {
			// need a deterministic sort order for paging
			criteria.SortFields = []*model.SortCriteria{
				{
					Field: "@timestamp",
					Order: "desc",
				},
			}

			if len(sort) != 0 {
				criteria.SearchAfter = sort
			}
		}

		var results *model.EventSearchResults

		results, err = store.server.Eventstore.Search(ctx, criteria)
		if err != nil {
			return nil, err
		}

		for _, event := range results.Events {
			var obj interface{}

			obj, err = convertElasticEventToObject(event, store.schemaPrefix)
			if err == nil {
				objects = append(objects, obj)
			} else {
				log.WithField("event", event).WithError(err).Error("Unable to convert case object")
			}
		}

		if !unlimited || len(results.Events) == 0 {
			break
		}

		sort = results.Events[len(results.Events)-1].Sort
	}

	// }

	return objects, err
}

func (store *ElasticDetectionstore) prepareForSave(ctx context.Context, obj *model.Auditable) string {
	obj.UserId = ctx.Value(web.ContextKeyRequestorId).(string)

	// Don't waste space by saving the these values which are already part of ES documents
	id := obj.Id
	obj.Id = ""
	obj.UpdateTime = nil

	return id
}

func (store *ElasticDetectionstore) CreateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	var err error

	err = store.validateDetection(detect)
	if err != nil {
		return nil, err
	}

	if detect.Id != "" {
		return nil, errors.New("Unexpected ID found in new comment")
	}

	now := time.Now()
	detect.CreateTime = &now

	var results *model.EventIndexResults

	results, err = store.save(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))
	if err == nil {
		// Read object back to get new modify date, etc
		detect, err = store.GetDetection(ctx, results.DocumentId)
	}

	return detect, err
}

func (store *ElasticDetectionstore) GetDetection(ctx context.Context, detectId string) (detect *model.Detection, err error) {
	err = store.validateId(detectId, "detectId")
	if err != nil {
		return nil, err
	}

	obj, err := store.get(ctx, detectId, "detection")
	if err == nil && obj != nil {
		detect = obj.(*model.Detection)
	}

	return detect, err
}

func (store *ElasticDetectionstore) UpdateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	err := store.validateDetection(detect)
	if err != nil {
		return nil, err
	}

	if detect.Id == "" {
		err = errors.New("Missing detection onion ID")
		return nil, err
	}

	var old *model.Detection

	old, err = store.GetDetection(ctx, detect.Id)
	if err != nil {
		return nil, err
	}

	var results *model.EventIndexResults

	// Preserve read-only fields
	detect.CreateTime = old.CreateTime

	results, err = store.save(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))
	if err != nil {
		return nil, err
	}

	// Read object back to get new modify date, etc
	return store.GetDetection(ctx, results.DocumentId)
}

func (store *ElasticDetectionstore) UpdateDetectionField(ctx context.Context, id string, field string, value any) (*model.Detection, bool, error) {
	var modified bool

	detect, err := store.GetDetection(ctx, id)
	if err != nil {
		return nil, false, err
	}

	switch strings.ToLower(field) {
	case "isenabled":
		bVal, ok := value.(bool)
		if !ok {
			return nil, false, fmt.Errorf("invalid value for field isEnabled (expected bool): %[1]v (%[1]T)", value)
		}

		if detect.IsEnabled != bVal {
			detect.IsEnabled = bVal
			modified = true
		}
	}

	err = store.validateDetection(detect)
	if err != nil {
		return nil, false, err
	}

	if modified {
		var results *model.EventIndexResults

		results, err = store.save(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))
		if err == nil {
			// Read object back to get new modify date, etc
			detect, err = store.GetDetection(ctx, results.DocumentId)
		}
	}

	return detect, modified, err
}

func (store *ElasticDetectionstore) DeleteDetection(ctx context.Context, onionID string) (*model.Detection, error) {
	detect, err := store.GetDetection(ctx, onionID)
	if err != nil {
		return nil, err
	}

	err = store.delete(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))

	return detect, err
}

func (store *ElasticDetectionstore) GetAllCommunitySIDs(ctx context.Context, engine *model.EngineName) (map[string]*model.Detection, error) {
	query := fmt.Sprintf(`_index:"%s" AND %skind:"%s"`, store.index, store.schemaPrefix, "detection")
	if engine != nil {
		query += fmt.Sprintf(` AND %sdetection.engine:"%s"`, store.schemaPrefix, *engine)
	}

	all, err := store.getAll(ctx, query, -1)
	if err != nil {
		return nil, err
	}

	sids := map[string]*model.Detection{}
	for _, det := range all {
		detection := det.(*model.Detection)
		sids[detection.PublicID] = detection
	}

	return sids, nil
}
