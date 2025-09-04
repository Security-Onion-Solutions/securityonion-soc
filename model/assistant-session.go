package model

import "time"

type AssistantSession struct {
	Auditable
	Title      string     `json:"title"`
	SessionId  string     `json:"sessionId"`
	DeleteTime *time.Time `json:"deleteTime,omitempty"`
	Tags       []string   `json:"tags"`
}
