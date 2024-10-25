// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"
)

type Client struct {
	Id         string    `json:"id"`
	CreateTime time.Time `json:"createTime"`
	UpdateTime time.Time `json:"updateTime"`
	Name       string    `json:"name"`
	Secret     string    `json:"secret"`
	Roles      []string  `json:"roles"`
	Note       string    `json:"note"`
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
