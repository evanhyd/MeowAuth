package storages

import (
	"io"
)

type ProfileAccessor interface {
	CreateUser(profile UserProfile, hashedPassword string) (UserProfile, error)
	GetUserProfile(userId string) (UserProfile, error)
	GetUserPasswordHash(userId string) (string, error)
	UpdateUserProfile(profile UserProfile) error
	UpdateUserPassword(userId string, hashedPassword string) error
}

type SessionAccessor interface {
	CreateSession(userId string) (UserSession, error)
	RefreshSession(token string) (UserSession, error)
	DeleteAllSessions(userId string) error
}

type Storage interface {
	io.Closer
	ProfileAccessor
	SessionAccessor
}
