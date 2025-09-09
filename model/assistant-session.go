package model

import "time"

// @Description A session for a user chatting with the Assistant.
type AssistantSession struct {
	Auditable
	// The title of the session. Usually the first message sent by the user.
	Title string `json:"title" example:"Can you write a suricata rule for me?"`
	// The session identifier.
	SessionId string `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
	// The time the session was deleted.
	DeleteTime *time.Time `json:"deleteTime,omitempty" example:"2025-09-05T15:33:00.000Z"`
	// Metadata about the session.
	Tags []string `json:"tags" example:"investigation"`
}
