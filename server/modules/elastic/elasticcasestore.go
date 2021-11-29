// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "context"
  "errors"
  "fmt"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "strconv"
  "time"
)

const AUDIT_DOC_ID = "so_audit_doc_id"

type ElasticCasestore struct {
  server          *server.Server
  index           string
  auditIndex      string
  maxAssociations int
}

func NewElasticCasestore(srv *server.Server) *ElasticCasestore {
  return &ElasticCasestore{
    server: srv,
  }
}

func (store *ElasticCasestore) Init(index string, auditIndex string, maxAssociations int) error {
  store.index = index
  store.auditIndex = auditIndex
  store.maxAssociations = maxAssociations
  return nil
}

func (store *ElasticCasestore) prepareForSave(ctx context.Context, obj *model.Auditable) string {
  obj.UserId = ctx.Value(web.ContextKeyRequestorId).(string)

  // Don't waste space by saving the these values which are already part of ES documents
  id := obj.Id
  obj.Id = ""
  obj.UpdateTime = nil

  return id
}

func (store *ElasticCasestore) save(ctx context.Context, obj interface{}, kind string, id string) (*model.EventIndexResults, error) {
  var results *model.EventIndexResults
  var err error

  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    document := convertObjectToDocumentMap(kind, obj)
    document["kind"] = kind
    results, err = store.server.Eventstore.Index(ctx, store.index, document, id)
    if err == nil {
      document[AUDIT_DOC_ID] = results.DocumentId
      if id == "" {
        document["operation"] = "create"
      } else {
        document["operation"] = "update"
      }
      _, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
      if err != nil {
        log.WithFields(log.Fields{
          "documentId": results.DocumentId,
          "kind":       kind,
        }).WithError(err).Error("Object indexed successfully however audit record failed to index")
      }
    }
  }

  return results, err
}

func (store *ElasticCasestore) delete(ctx context.Context, obj interface{}, kind string, id string) error {
  var err error

  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    err = store.server.Eventstore.Delete(ctx, store.index, id)
    if err == nil {
      document := convertObjectToDocumentMap(kind, obj)
      document[AUDIT_DOC_ID] = id
      document["kind"] = kind
      document["operation"] = "delete"
      _, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
      if err != nil {
        log.WithFields(log.Fields{
          "documentId": id,
          "kind":       kind,
        }).WithError(err).Error("Object deleted successfully however audit record failed to index")
      }
    }
  }

  return err
}

func (store *ElasticCasestore) get(ctx context.Context, id string, kind string) (interface{}, error) {
  query := fmt.Sprintf(`_index:"%s" AND kind:"%s" AND _id:"%s"`, store.index, kind, id)
  objects, err := store.getAll(ctx, query, 1)
  if err == nil && len(objects) > 0 {
    return objects[0], err
  }
  return nil, err
}

func (store *ElasticCasestore) getAll(ctx context.Context, query string, max int) ([]interface{}, error) {
  var err error
  var objects []interface{}

  if err = store.server.CheckAuthorized(ctx, "read", "cases"); err == nil {
    criteria := model.NewEventSearchCriteria()
    format := "2006-01-02 3:04:05 PM"
    var zeroTime time.Time
    zeroTimeStr := zeroTime.Format(format)
    now := time.Now()
    endTime := now.Format(format)
    zone := now.Location().String()
    err = criteria.Populate(query,
      zeroTimeStr+" - "+endTime, // timeframe range
      format,                    // timeframe format
      zone,                      // timezone
      "0",                       // no metrics
      strconv.Itoa(max))

    if err == nil {
      var results *model.EventSearchResults
      results, err = store.server.Eventstore.Search(ctx, criteria)
      if err == nil {
        for _, event := range results.Events {
          var obj interface{}
          obj, err = convertElasticEventToObject(event)
          if err == nil {
            objects = append(objects, obj)
          } else {
            log.WithField("event", event).WithError(err).Error("Unable to convert case object")
          }
        }
      }
    }
  }

  return objects, err
}

func (store *ElasticCasestore) Create(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var err error

  if socCase.Id != "" {
    err = errors.New("Unexpected ID found in new case")
  } else {
    socCase.Status = model.CASE_STATUS_NEW
    now := time.Now()
    socCase.CreateTime = &now
    var results *model.EventIndexResults
    results, err = store.save(ctx, socCase, "case", store.prepareForSave(ctx, &socCase.Auditable))
    if err == nil {
      // Read object back to get new modify date, etc
      socCase, err = store.GetCase(ctx, results.DocumentId)
    }
  }
  return socCase, err
}

func (store *ElasticCasestore) Update(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var err error

  if socCase.Id == "" {
    err = errors.New("Missing case ID")
  } else {
    var oldCase *model.Case
    oldCase, err = store.GetCase(ctx, socCase.Id)
    if err == nil {
      // Preserve read-only fields
      socCase.CreateTime = oldCase.CreateTime
      socCase.CompleteTime = oldCase.CompleteTime
      socCase.StartTime = oldCase.StartTime
      var results *model.EventIndexResults
      results, err = store.save(ctx, socCase, "case", store.prepareForSave(ctx, &socCase.Auditable))
      if err == nil {
        // Read object back to get new modify date, etc
        socCase, err = store.GetCase(ctx, results.DocumentId)
      }
    }
  }
  return socCase, err
}

func (store *ElasticCasestore) GetCase(ctx context.Context, id string) (*model.Case, error) {
  obj, err := store.get(ctx, id, "case")
  if err == nil {
    return obj.(*model.Case), nil
  }
  return nil, err
}

func (store *ElasticCasestore) GetCaseHistory(ctx context.Context, caseId string) ([]interface{}, error) {
  query := fmt.Sprintf(`_index:"%s" AND (%s:"%s" OR comment.caseId:"%s")`, store.auditIndex, AUDIT_DOC_ID, caseId, caseId)
  return store.getAll(ctx, query, store.maxAssociations)
}

func (store *ElasticCasestore) CreateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  var err error

  if comment.Id != "" {
    return nil, errors.New("Unexpected ID found in new comment")
  } else if comment.CaseId == "" {
    return nil, errors.New("Missing Case ID in new comment")
  } else {
    now := time.Now()
    comment.CreateTime = &now
    var results *model.EventIndexResults
    results, err = store.save(ctx, comment, "comment", store.prepareForSave(ctx, &comment.Auditable))
    if err == nil {
      // Read object back to get new modify date, etc
      comment, err = store.GetComment(ctx, results.DocumentId)
    }
  }
  return comment, err
}

func (store *ElasticCasestore) GetComment(ctx context.Context, id string) (*model.Comment, error) {
  obj, err := store.get(ctx, id, "comment")
  if err == nil {
    return obj.(*model.Comment), nil
  }
  return nil, err
}

func (store *ElasticCasestore) GetComments(ctx context.Context, caseId string) ([]*model.Comment, error) {
  comments := make([]*model.Comment, 0)
  query := fmt.Sprintf(`_index:"%s" AND kind:"comment" AND comment.caseId:"%s" | sortby comment.createTime^`, store.index, caseId)
  objects, err := store.getAll(ctx, query, store.maxAssociations)
  if err == nil {
    for _, obj := range objects {
      comments = append(comments, obj.(*model.Comment))
    }
  }
  return comments, err
}

func (store *ElasticCasestore) UpdateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  var err error

  if comment.Id == "" {
    err = errors.New("Missing comment ID")
  } else {
    var old *model.Comment
    old, err = store.GetComment(ctx, comment.Id)
    if err == nil {
      // Preserve read-only fields
      comment.CreateTime = old.CreateTime
      var results *model.EventIndexResults
      results, err = store.save(ctx, comment, "comment", store.prepareForSave(ctx, &comment.Auditable))
      if err == nil {
        // Read object back to get new modify date, etc
        comment, err = store.GetComment(ctx, results.DocumentId)
      }
    }
  }
  return comment, err
}

func (store *ElasticCasestore) DeleteComment(ctx context.Context, id string) error {
  var err error

  var comment *model.Comment
  comment, err = store.GetComment(ctx, id)
  if err == nil {
    err = store.delete(ctx, comment, "comment", store.prepareForSave(ctx, &comment.Auditable))
  }

  return err
}
