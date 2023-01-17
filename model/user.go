// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "time"
)

type User struct {
  Id             string    `json:"id"`
  CreateTime     time.Time `json:"createTime"`
  UpdateTime     time.Time `json:"updateTime"`
  Email          string    `json:"email"`
  FirstName      string    `json:"firstName"`
  LastName       string    `json:"lastName"`
  MfaStatus      string    `json:"mfaStatus"`
  Note           string    `json:"note"`
  Roles          []string  `json:"roles"`
  Status         string    `json:"status"`
  SearchUsername string    `json:"searchUsername"`
}

func NewUser() *User {
  return &User{
    CreateTime:     time.Now(),
    Email:          "",
    FirstName:      "",
    LastName:       "",
    Note:           "",
    Status:         "",
    SearchUsername: "",
  }
}

func (user *User) String() string {
  return user.Id
}
