// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
  "context"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type KratosUserstore struct {
  server *server.Server
  client *web.Client
}

func NewKratosUserstore(server *server.Server) *KratosUserstore {
  return &KratosUserstore{
    server: server,
  }
}

func (kratos *KratosUserstore) Init(url string) error {
  kratos.client = web.NewClient(url, true)
  return nil
}

func (kratos *KratosUserstore) fetchUser(id string) (*KratosUser, error) {
  kratosUser := &KratosUser{}
  _, err := kratos.client.SendObject("GET", "/identities/"+id, "", &kratosUser, false)
  return kratosUser, err
}

func (kratos *KratosUserstore) GetUsers(ctx context.Context) ([]*model.User, error) {
  kratosUsers := make([]*KratosUser, 0, 0)

  if err := kratos.server.Authorizer.CheckContextOperationAuthorized(ctx, "read", "users"); err != nil {
    // User is only allowed to get their own user. Even though the user is already on
    // the context we have to fetch it again to ensure it's fully updated with the
    // latest user attributes.

    if requestorId, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
      log.WithFields(log.Fields{
        "requestorId": requestorId,
        "requestId":   ctx.Value(web.ContextKeyRequestId),
      }).Debug("Fetching own user for requestor ID")

      var kratosUser KratosUser
      _, err = kratos.client.SendObject("GET", "/identities/"+requestorId, "", &kratosUser, false)
      if err != nil {
        log.WithError(err).WithFields(log.Fields{
          "userId":    requestorId,
          "requestId": ctx.Value(web.ContextKeyRequestId),
        }).Error("Failed to fetch user from Kratos")
        return nil, err
      }
      kratosUsers = append(kratosUsers, &kratosUser)
    } else {
      // Missing context data, unlikely to occur
      return nil, err
    }
  } else {
    // User is allowed to view all users, go get them
    _, err := kratos.client.SendObject("GET", "/identities", "", &kratosUsers, false)
    if err != nil {
      log.WithError(err).WithFields(log.Fields{
        "requestId": ctx.Value(web.ContextKeyRequestId),
      }).Error("Failed to fetch users from Kratos")
      return nil, err
    }
  }

  // Convert the kratos users to SOC users
  users := make([]*model.User, 0, 0)
  for _, kratosUser := range kratosUsers {
    user := model.NewUser()
    kratosUser.copyToUser(user)
    kratos.server.Rolestore.PopulateUserRoles(ctx, user)
    users = append(users, user)
  }
  return users, nil
}

func (kratos *KratosUserstore) DeleteUser(ctx context.Context, id string) error {
  var err error
  if err = kratos.server.Authorizer.CheckContextOperationAuthorized(ctx, "delete", "users"); err != nil {
    log.WithFields(log.Fields{
      "id":        id,
      "requestId": ctx.Value(web.ContextKeyRequestId),
    }).Debug("Deleting user")
    _, err := kratos.client.SendObject("DELETE", "/identities/"+id, "", nil, false)
    if err != nil {
      log.WithError(err).WithFields(log.Fields{
        "requestId": ctx.Value(web.ContextKeyRequestId),
      }).Error("Failed to delete user from Kratos")
    }
  }
  return err
}

func (kratos *KratosUserstore) GetUser(ctx context.Context, id string) (*model.User, error) {
  var err error
  var user *model.User

  users, err := kratos.GetUsers(ctx)
  if err == nil {
    for _, testUser := range users {
      if testUser.Id == id {
        user = testUser
        break
      }
    }
  }
  return user, err
}

func (kratos *KratosUserstore) UpdateUser(ctx context.Context, id string, user *model.User) error {
  var err error
  if err = kratos.server.Authorizer.CheckContextOperationAuthorized(ctx, "write", "users"); err != nil {
    kratosUser, err := kratos.fetchUser(id)
    if err != nil {
      log.WithError(err).WithFields(log.Fields{
        "requestId": ctx.Value(web.ContextKeyRequestId),
      }).Error("Original user not found")
    } else {
      kratosUser.copyFromUser(user)
      _, err = kratos.client.SendObject("PUT", "/identities/"+id, kratosUser, nil, false)
      if err != nil {
        log.WithError(err).WithFields(log.Fields{
          "requestId": ctx.Value(web.ContextKeyRequestId),
        }).Error("Failed to update user in Kratos")
      }
    }
  }
  return err
}
