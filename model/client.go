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

const MAX_CLIENT_ID_LEN = 55
const MAX_CLIENT_NAME_LEN = 50
const MAX_PERMISSION_LEN = 50

type Client struct {
	// The ID assigned to this API client
	Id string `json:"id" example:"socl_my_new_api_client"`
	// The date and time when this API client was created
	CreateTime time.Time `json:"createTime" example:"2024-12-03T21:04:59.970640998Z"`
	// The date and time when this API client was last modified
	UpdateTime time.Time `json:"updateTime" example:"0001-01-01T00:00:00Z"`
	// The client name
	Name string `json:"name" example:"My New API Client"`
	// The generated client secret (only returned on new client creation and regeneration of the secret)
	Secret string `json:"secret" example:"ERa5jp9Z6WbLm1YC5FCM"`
	// The list of permissions assigned to this client
	Permissions []string `json:"permissions" example:"events/read,cases/read,cases/write"`
	// An optional note to associate with this API client
	Note string `json:"note" example:"This client is used for automating case observable attachments"`
	// An optional Elasticsearch user that this client will run as when accessing event data
	SearchUsername string `json:"searchUsername" example:""`
}

func NewClient() *Client {
	return &Client{
		CreateTime: time.Now(),
		Name:       "",
	}
}

func (client *Client) String() string {
	return client.Id
}

func (client *Client) Verify() error {
	if len(client.Id) > MAX_CLIENT_ID_LEN {
		return errors.New("ERROR_CLIENT_ID_TOO_LONG")
	}

	if len(client.Name) > MAX_CLIENT_NAME_LEN {
		return errors.New("ERROR_NAME_TOO_LONG")
	}

	if len(client.Note) > MAX_NOTE_LEN {
		return errors.New("ERROR_NOTE_TOO_LONG")
	}

	if len(client.SearchUsername) > MAX_SEARCH_USERNAME_LEN {
		return errors.New("ERROR_SEARCH_USERNAME_TOO_LONG")
	}

	for _, perm := range client.Permissions {
		if len(perm) > MAX_PERMISSION_LEN {
			return errors.New("ERROR_PERMISSION_TOO_LONG")
		}
	}

	return nil
}
