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
	// The ID assigned to this user by the server. This is a read-only field.
	Id string `json:"id" example:"3610b2cf-a2e7-4037-9c51-227f0c2e79ff"`
	// The date and time that this user was created. This is a read-only field.
	CreateTime time.Time `json:"createTime" example:"2024-11-14T15:03:22Z"`
	// The date and time that this user was last modified. This is a read-only field.
	UpdateTime time.Time `json:"updateTime,omitempty" example:"2024-11-14T15:33:02Z"`
	// The email address for this user.
	Email string `json:"email" example:"someone@somewhere.invalid"`
	// The user's first name.
	FirstName string `json:"firstName" example:"John"`
	// The user's last name, or family name.
	LastName string `json:"lastName" example:"Smith"`
	// The TOTP MFA status for this user. This is a read-only field.
	TotpStatus string `json:"totpStatus" example:"enabled"`
	// The OIDC status for this user. This is a read-only field.
	OidcStatus string `json:"oidcStatus" example:"enabled"`
	// The WebAuthn (Passwordless) status for this user. This status field is not ready for production use. This is a read-only field.
	WebauthnStatus string `json:"webauthnStatus" example:"enabled"`
	// A custom note about this user.
	Note string `json:"note" example:"Employment terminated on Nov 10, 2023"`
	// A list of assigned roles to this user.
	Roles []string `json:"roles" example:"limited-analyst"`
	// The login status of this user.
	Status string `json:"status" example:"locked"`
	// An alternate username (typically an email address) to use when performing backend (Ex: Elasticsearch) data searches and updates.
	SearchUsername string `json:"searchUsername" example:"someoneelse@somewhere.invalid"`
	// The password must have a length of at least 8 characters and no more than 72 characters and cannot contain the following: ' " $ \
	Password string `json:"password"`
	// A rough determination of whether this user has changed their password since the user was created. Technically this can only detect if the user has been updated after creation and is therefore an imperfect estimator for whether the password has been changed. This is a read-only field.
	PasswordChanged bool `json:"passwordChanged"`
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
