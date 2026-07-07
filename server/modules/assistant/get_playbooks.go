// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &GetPlaybooksTool{}
	knownTools[t.GetName()] = t
}

type GetPlaybooksTool struct{}

func (t *GetPlaybooksTool) GetName() string {
	return "get_playbooks"
}

func (t *GetPlaybooksTool) GetDescription() string {
	return "Get playbooks for a given alert to guide investigation. Playbooks consist " +
		"of questions and sigma searches to help gather context about the alert. The searches " +
		"are executed and the results are returned along with the questions. If multiple playbooks " +
		"are available for the alert, you can specify a playbook_index (0-based) to get questions " +
		"from a specific playbook. Lower index playbooks are usually more specific to the alert."
}

func (t *GetPlaybooksTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"alert_id": {
					Type:        "string",
					Description: "The alert ID (event.id, log.id.uid, or soc_id)",
				},
				"playbook_index": {
					Type:        "integer",
					Description: "Optional index to get questions from a specific playbook (0-based, lower index playbooks are usually more specific)",
				},
			},
			Required: []string{"alert_id"},
		},
	}
}

type getPlaybookQuestionsArgs struct {
	AlertID       string `json:"alert_id"`
	PlaybookIndex *int   `json:"playbook_index,omitempty"`
}

func (t *GetPlaybooksTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &getPlaybookQuestionsArgs{}
	result = &model.ToolResponse{
		ToolName:       t.GetName(),
		OnBehalfOfUser: userId,
	}

	start := time.Now()
	defer func() {
		if result != nil {
			result.TimeToExecute = time.Since(start)
		}
	}()

	err = json.Unmarshal([]byte(params), args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	// go get playbooks
	event, err := server.FindEventBySocId(ctx, srv.Eventstore, args.AlertID, time.Time{})
	if err != nil {
		return nil, err
	}
	if event == nil {
		logger.WithField("alertId", args.AlertID).Error("no alert found with corresponding ID")
		return nil, errors.New("ERROR_ASSISTANT_NO_ALERT_FOUND")
	}

	detId, ok := event.Payload["rule.uuid"].(string)
	if !ok {
		logger.WithField("specifiedEvent", event).Error("event does not have a rule.uuid field")
		return nil, errors.New("ERROR_ASSISTANT_NO_ALERT_UUID_FIELD")
	}

	detection, err := srv.Detectionstore.GetDetectionByPublicId(ctx, detId)
	if err != nil {
		return nil, err
	}

	engInt, ok := srv.DetectionEngines.Load(detection.Engine)
	if ok {
		eng := engInt.(server.DetectionEngine)

		err = eng.ExtractDetails(detection)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"detectionEngine":   detection.Engine,
				"detectionPublicId": detection.PublicID,
			}).Error("unable to extract details from detection")
		}
	} else {
		logger.WithFields(log.Fields{
			"detectionEngine":   detection.Engine,
			"detectionPublicId": detection.PublicID,
		}).Error("retrieved detection with unsupported engine")
	}

	playbooks, err := srv.Playbookstore.GetPlaybooksForDetection(ctx, detection.PublicID, detection.Category, detection.Engine)
	if err != nil || len(playbooks) == 0 {
		logger.WithField("publicId", detection.PublicID).Error("failed to get playbooks for detection")
		return nil, errors.New("ERROR_ASSISTANT_PLAYBOOKS_RETRIEVAL_FAILED")
	}

	if args.PlaybookIndex != nil {
		if *args.PlaybookIndex < 0 || *args.PlaybookIndex >= len(playbooks) {
			return nil, fmt.Errorf("invalid playbook index %d, detection has %d playbooks", *args.PlaybookIndex, len(playbooks))
		}

		playbooks = playbooks[*args.PlaybookIndex : *args.PlaybookIndex+1]
	}

	err = srv.Playbookstore.ExecutePlaybookSearches(ctx, event, playbooks)

	result.Result = simplifyPlaybooks(playbooks)

	return result, nil
}

type SimplePlaybook struct {
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	SourceCreated     time.Time         `json:"created,omitempty"`
	SourceUpdated     *time.Time        `json:"modified,omitempty"`
	DetectionId       string            `json:"detection_id,omitempty"`
	DetectionCategory string            `json:"detection_category,omitempty"`
	DetectionType     string            `json:"detection_type,omitempty"`
	Contributors      []string          `json:"contributors,omitempty"`
	Questions         []*SimpleQuestion `json:"questions"`
}

type SimpleQuestion struct {
	Question     string  `json:"question"`
	Context      string  `json:"context"`
	Range        *string `json:"range,omitempty"`
	QueryResults any     `json:"queryResults"`
}

func simplifyPlaybooks(playbooks []*model.Playbook) []*SimplePlaybook {
	simplePlaybooks := make([]*SimplePlaybook, 0, len(playbooks))
	for _, pb := range playbooks {
		simpleQuestions := make([]*SimpleQuestion, 0, len(pb.Questions))

		for _, q := range pb.Questions {
			if len(q.QueryResults) != 0 {
				simpleQuestions = append(simpleQuestions, &SimpleQuestion{
					Question:     q.Question,
					Context:      q.Context,
					Range:        q.Range,
					QueryResults: filterEvents(q.QueryResults, q.QueryFields...),
				})
			}
		}

		simplePlaybooks = append(simplePlaybooks, &SimplePlaybook{
			Name:        pb.Name,
			Description: pb.Description,
			Questions:   simpleQuestions,
		})
	}

	return simplePlaybooks
}
