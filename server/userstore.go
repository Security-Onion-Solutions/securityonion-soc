// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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

type Userstore interface {
  GetUsers(ctx context.Context) ([]*model.User, error)
  DeleteUser(ctx context.Context, id string) error
  GetUser(ctx context.Context, id string) (*model.User, error)
  UpdateUser(ctx context.Context, id string, user *model.User) error
}
