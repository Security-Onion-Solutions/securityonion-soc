// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type Casestore interface {
	Create(ctx context.Context, newCase *model.Case) (*model.Case, error)
	Update(ctx context.Context, socCase *model.Case) (*model.Case, error)
	GetCase(ctx context.Context, caseId string) (*model.Case, error)
	GetCaseHistory(ctx context.Context, caseId string) ([]interface{}, error)

	CreateComment(ctx context.Context, newComment *model.Comment) (*model.Comment, error)
	GetComment(ctx context.Context, commentId string) (*model.Comment, error)
	GetComments(ctx context.Context, caseId string) ([]*model.Comment, error)
	UpdateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error)
	DeleteComment(ctx context.Context, id string) error

	CreateRelatedEvent(ctx context.Context, event *model.RelatedEvent) (*model.RelatedEvent, error)
	GetRelatedEvent(ctx context.Context, id string) (*model.RelatedEvent, error)
	GetRelatedEvents(ctx context.Context, caseId string) ([]*model.RelatedEvent, error)
	DeleteRelatedEvent(ctx context.Context, id string) error

	CreateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error)
	GetArtifact(ctx context.Context, id string) (*model.Artifact, error)
	GetArtifacts(ctx context.Context, caseId string, groupType string, groupId string) ([]*model.Artifact, error)
	DeleteArtifact(ctx context.Context, id string) error
	UpdateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error)

	CreateArtifactStream(ctx context.Context, artifactstream *model.ArtifactStream) (string, error)
	GetArtifactStream(ctx context.Context, id string) (*model.ArtifactStream, error)
	DeleteArtifactStream(ctx context.Context, id string) error
}
