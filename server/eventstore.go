// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
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

type Eventstore interface {
	Search(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error)
	Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error)
	Update(context context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error)
	Delete(context context.Context, index string, id string) error
	Acknowledge(context context.Context, criteria *model.EventAckCriteria) (*model.EventUpdateResults, error)
}
