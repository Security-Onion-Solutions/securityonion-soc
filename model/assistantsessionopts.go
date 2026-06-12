package model

import "time"

type GetSessionsOpts struct {
	includeDeleted  bool
	userId          string
	sessionId       string
	usage           bool
	descendants     bool
	skipMessageMeta bool
	start           time.Time
	end             time.Time
}

func (gso *GetSessionsOpts) IncludeDeleted() bool {
	return gso.includeDeleted
}

func (gso *GetSessionsOpts) UserId() string {
	return gso.userId
}

func (gso *GetSessionsOpts) SessionId() string {
	return gso.sessionId
}

func (gso *GetSessionsOpts) Range() (time.Time, time.Time) {
	return gso.start, gso.end
}

func (gso *GetSessionsOpts) Usage() bool {
	return gso.usage
}

// Descendants reports whether the query should also return all delegated
// sub-sessions descending from the matched session (recursively, any depth).
func (gso *GetSessionsOpts) Descendants() bool {
	return gso.descendants
}

// MessageMeta reports whether the store should derive per-session metadata from
// the session's messages (e.g. update time). On by default; internal callers
// that only need the session record itself opt out to save a query.
func (gso *GetSessionsOpts) MessageMeta() bool {
	return !gso.skipMessageMeta
}

type GetSessionsOpt func(*GetSessionsOpts)

func GetSessionsWithIncludeDeleted(includeDeleted bool) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.includeDeleted = includeDeleted
	}
}

func GetSessionsWithUserId(userId string) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.userId = userId
	}
}

func GetSessionsWithSessionId(sessionId string) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.sessionId = sessionId
	}
}

func GetSessionsWithRange(start time.Time, end time.Time) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.start = start
		gso.end = end
	}
}

func GetSessionsWithUsage(usage bool) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.usage = usage
	}
}

// GetSessionsWithDescendants, when combined with GetSessionsWithSessionId, makes
// GetSessions also return every delegated sub-session descending from the matched
// session, to any depth (A delegates to B, B to C -> requesting A returns A, B, C).
func GetSessionsWithDescendants(descendants bool) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.descendants = descendants
	}
}

// GetSessionsWithMessageMeta(false) skips deriving per-session metadata from the
// session's messages, saving a query when only the session record is needed.
func GetSessionsWithMessageMeta(messageMeta bool) GetSessionsOpt {
	return func(gso *GetSessionsOpts) {
		gso.skipMessageMeta = !messageMeta
	}
}
