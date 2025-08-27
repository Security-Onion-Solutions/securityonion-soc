package model

import "time"

type AssistantSession struct {
	Auditable
	Title      string     `json:"title"`
	DeleteTime *time.Time `json:"deleteTime,omitempty"`
	Tags       []string   `json:"tags"`
}
