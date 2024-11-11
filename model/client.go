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
	Id             string    `json:"id"`
	CreateTime     time.Time `json:"createTime"`
	UpdateTime     time.Time `json:"updateTime"`
	Name           string    `json:"name"`
	Secret         string    `json:"secret"`
	Permissions    []string  `json:"permissions"`
	Note           string    `json:"note"`
	SearchUsername string    `json:"searchUsername"`
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
