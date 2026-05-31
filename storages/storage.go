package storages

import (
	"io"
)

type UserStorer interface {
	CreateUser(profile UserProfile, passwordHash string) (UserProfile, error)
	GetUserProfile(userId string) (UserProfile, error)
	GetUserCredential(userId string) (UserCredential, error)
	UpdateUserProfile(profile UserProfile) error
	UpdateUserCredential(userId string, passwordHash string) error

	CreateSession(userId string) (UserSession, error)
	RefreshSession(token string) (UserSession, error)
	DeleteSession(sessionId int64) error
}

type Storage interface {
	UserStorer
	io.Closer
}
