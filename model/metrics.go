// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "time"

// MetricSample represents a single data point in a time-series metric dataset.
type MetricSample struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// MetricPanel defines the specification, metrics source, layout, and visual parameters for a single panel on the metrics dashboard.
type MetricPanel struct {
	ID        string   `json:"id" example:"cpu"`
	Title     string   `json:"title,omitempty" example:"CPU Usage"`
	TitleKey  string   `json:"titleKey,omitempty" example:"metricsCpuUsage"`
	Type      string   `json:"type" example:"Xy"`
	Metric    string   `json:"metric" example:"cpu"`
	Keys      []string `json:"keys" example:"[\"cpu_used\"]"`
	Labels    []string `json:"labels,omitempty" example:"[\"CPU\"]"`
	LabelKeys []string `json:"labelKeys,omitempty" example:"[\"cpu\"]"`
	Colors    []string `json:"colors,omitempty" example:"[\"#4dc9f6\"]"`
	Width     int      `json:"width" example:"6"`
	Height    int      `json:"height" example:"250"`
	Units     string   `json:"units,omitempty" example:"%"`
}

// MetricsDashboard holds the complete collection of visualization panel configurations for the grid metrics dashboard.
type MetricsDashboard struct {
	Panels []MetricPanel `json:"panels"`
}
