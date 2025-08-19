// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &GetPlaybookQuestionsTool{}
	knownTools[t.GetName()] = t
}

type GetPlaybookQuestionsTool struct{}

func (t *GetPlaybookQuestionsTool) GetName() string {
	return "get_playbook_questions"
}

func (t *GetPlaybookQuestionsTool) GetDescription() string {
	return "Get playbook questions for a given alert/detection to guide investigation"
}

func (t *GetPlaybookQuestionsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"alert_id": {
					Type:        "string",
					Description: "The alert/detection ID (event.id or rule.uuid)",
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

func (t *GetPlaybookQuestionsTool) Execute(ctx context.Context, srv *server.Server, params string) (result *model.ToolResponse, err error) {
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
		return nil, err
	}

	result.Parameters = args

	// go get playbooks
	query := fmt.Sprintf(`rule.uuid:"%[1]s" OR log.id.uid:"%[1]s"`, args.AlertID)
	criteria := model.NewEventSearchCriteria()

	err = criteria.Populate(query, "", "", "", "0", "1")
	if err != nil {
		return nil, err
	}

	events, err := srv.Eventstore.Search(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for alert: %w", err)
	}
	if events.TotalEvents == 0 || len(events.Events) == 0 {
		return nil, fmt.Errorf("no alert found with ID %s", args.AlertID)
	}

	event := events.Events[0]

	detId, ok := event.Payload["rule.uuid"].(string)
	if !ok {
		logger.WithField("event", event).Error("event does not have a rule.uuid field")
		return nil, fmt.Errorf("alert does not have a rule.uuid field")
	}

	detection, err := srv.Detectionstore.GetDetectionByPublicId(ctx, detId)
	if err != nil {
		return nil, fmt.Errorf("failed to get detection by ID %s: %w", detId, err)
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
		return nil, fmt.Errorf("failed to get playbooks for detection %s: %w", detection.PublicID, err)
	}

	if args.PlaybookIndex != nil {
		if *args.PlaybookIndex < 0 || *args.PlaybookIndex >= len(playbooks) {
			return nil, fmt.Errorf("invalid playbook index %d, detection has %d playbooks", *args.PlaybookIndex, len(playbooks))
		}

		playbooks = playbooks[*args.PlaybookIndex : *args.PlaybookIndex+1]
	}

	result.Result = simplifyPlaybooks(playbooks)

	return result, nil
}

type SimplePlaybook struct {
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	SourceCreated     time.Time         `json:"created" yaml:"created"`
	SourceUpdated     *time.Time        `json:"modified,omitempty" yaml:"modified,omitempty"`
	DetectionId       string            `json:"detection_id"`
	DetectionCategory string            `json:"detection_category"`
	DetectionType     string            `json:"detection_type"`
	Contributors      []string          `json:"contributors"`
	Questions         []*SimpleQuestion `json:"questions"`
}

type SimpleQuestion struct {
	Question      string   `json:"question"`
	Context       string   `json:"context"`
	Range         *string  `json:"range"`
	AnswerSources []string `yaml:"answer_sources"`
}

func simplifyPlaybooks(playbooks []*model.Playbook) []*SimplePlaybook {
	simplePlaybooks := make([]*SimplePlaybook, len(playbooks))
	for i, pb := range playbooks {
		simpleQuestions := make([]*SimpleQuestion, len(pb.Questions))
		for j, q := range pb.Questions {
			simpleQuestions[j] = &SimpleQuestion{
				Question:      q.Question,
				Context:       q.Context,
				Range:         q.Range,
				AnswerSources: q.AnswerSources,
			}
		}

		simplePlaybooks[i] = &SimplePlaybook{
			Name:              pb.Name,
			Description:       pb.Description,
			SourceCreated:     pb.SourceCreated,
			SourceUpdated:     pb.SourceUpdated,
			DetectionId:       pb.DetectionId,
			DetectionCategory: pb.DetectionCategory,
			DetectionType:     pb.DetectionType,
			Contributors:      pb.Contributors,
			Questions:         simpleQuestions,
		}
	}
	return simplePlaybooks
}
