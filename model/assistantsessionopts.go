package model

import "time"

type GetSessionsOpts struct {
	includeDeleted bool
	userId         string
	sessionId      string
	usage          bool
	start          time.Time
	end            time.Time
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
