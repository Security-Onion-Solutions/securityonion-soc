// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type KratosUserstore struct {
  client          *web.Client
}

func NewKratosUserstore() *KratosUserstore {
  return &KratosUserstore {
  }
}

func (kratos* KratosUserstore) Init(url string) error {
  kratos.client = web.NewClient(url, true)
  return nil
}

func (kratos* KratosUserstore) fetchUser(id string) (*KratosUser, error) {
  kratosUser := &KratosUser{}
  _, err := kratos.client.SendObject("GET", "/identities/" + id, "", &kratosUser, false)
  return kratosUser, err
}

func (kratos* KratosUserstore) convertToUser(kratosUser *KratosUser) *model.User {
  user := &model.User {
    Id: kratosUser.Id,
    Email: kratosUser.Traits.Email,
    FirstName: kratosUser.Traits.FirstName,
    LastName: kratosUser.Traits.LastName,
    Role: kratosUser.Traits.Role,
  }
  return user
}

func (kratos* KratosUserstore) copyToKratosUser(user *model.User, kratosUser *KratosUser) {
  kratosUser.Traits.Email = user.Email
  kratosUser.Traits.FirstName = user.FirstName
  kratosUser.Traits.LastName = user.LastName
  kratosUser.Traits.Role = user.Role
  kratosUser.Addresses[0].Value = user.Email
  kratosUser.Addresses[0].Verified = true
}

func (kratos *KratosUserstore) GetUsers() ([]*model.User, error) {
  kratosUsers := make([]*KratosUser, 0, 0)
  _, err := kratos.client.SendObject("GET", "/identities", "", &kratosUsers, false)
  if err != nil {
    log.WithError(err).Error("Failed to fetch users from Kratos")
    return nil, err
  }
  users := make([]*model.User, 0, 0)
  for _, kratosUser := range kratosUsers {
    user := kratos.convertToUser(kratosUser)
    users = append(users, user)
  }
  return users, nil
}

func (kratos *KratosUserstore) DeleteUser(id string) error {
  log.WithField("id", id).Debug("Deleting user")
  _, err := kratos.client.SendObject("DELETE", "/identities/" + id, "", nil, false)
  if err != nil {
    log.WithError(err).Error("Failed to delete user from Kratos")
  }
  return err
}

func (kratos *KratosUserstore) GetUser(id string) (*model.User, error) {
  kratosUser, err := kratos.fetchUser(id)
  if err != nil {
    log.WithError(err).Error("Failed to fetch user from Kratos")
    return nil, err
  }
  return kratos.convertToUser(kratosUser), nil
}

func (kratos *KratosUserstore) UpdateUser(id string, user *model.User) error {
  kratosUser, err := kratos.fetchUser(id)
  if err != nil {
    log.WithError(err).Error("Original user not found")
  } else {
    kratos.copyToKratosUser(user, kratosUser)
    _, err = kratos.client.SendObject("PUT", "/identities/" + id, kratosUser, nil, false)
    if err != nil {
      log.WithError(err).Error("Failed to update user in Kratos")
    } 
  }
  return err
}
