package model

import "time"

type AssistantSession struct {
	Auditable
	Title      string     `json:"title" example:"Can you write a suricata rule for me?"`
	SessionId  string     `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
	DeleteTime *time.Time `json:"deleteTime,omitempty" example:"2025-09-05T15:33:00.000Z"`
	Tags       []string   `json:"tags" example:"investigation"`
}
