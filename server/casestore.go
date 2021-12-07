// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
}
