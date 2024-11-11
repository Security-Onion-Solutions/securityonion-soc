// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"time"
)

const MAX_EMAIL_LEN = 100
const MAX_FIRSTNAME_LEN = 100
const MAX_LASTNAME_LEN = 100
const MAX_NOTE_LEN = 100
const MAX_ROLE_LEN = 50
const MAX_USER_ID_LEN = 36
const MAX_SEARCH_USERNAME_LEN = 50

type User struct {
	Id              string    `json:"id"`
	CreateTime      time.Time `json:"createTime"`
	UpdateTime      time.Time `json:"updateTime"`
	Email           string    `json:"email"`
	FirstName       string    `json:"firstName"`
	LastName        string    `json:"lastName"`
	TotpStatus      string    `json:"totpStatus"`
	OidcStatus      string    `json:"oidcStatus"`
	WebauthnStatus  string    `json:"webauthnStatus"`
	Note            string    `json:"note"`
	Roles           []string  `json:"roles"`
	Status          string    `json:"status"`
	SearchUsername  string    `json:"searchUsername"`
	Password        string    `json:"password"`
	PasswordChanged bool      `json:"passwordChanged"`
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
		Password:       "",
	}
}

func (user *User) String() string {
	return user.Id
}

func (user *User) Verify() error {
	if len(user.Id) > MAX_USER_ID_LEN {
		return errors.New("ERROR_USER_ID_TOO_LONG")
	}

	if len(user.FirstName) > MAX_FIRSTNAME_LEN {
		return errors.New("ERROR_FIRSTNAME_TOO_LONG")
	}

	if len(user.LastName) > MAX_LASTNAME_LEN {
		return errors.New("ERROR_LASTNAME_TOO_LONG")
	}

	if len(user.Note) > MAX_NOTE_LEN {
		return errors.New("ERROR_NOTE_TOO_LONG")
	}

	if len(user.SearchUsername) > MAX_SEARCH_USERNAME_LEN {
		return errors.New("ERROR_SEARCH_USERNAME_TOO_LONG")
	}

	for _, role := range user.Roles {
		if len(role) > MAX_ROLE_LEN {
			return errors.New("ERROR_ROLE_TOO_LONG")
		}
	}

	return nil
}
