package storages

import (
	"database/sql"
	_ "embed"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

const jwtTokenLifetime = 30 * 24 * time.Hour

//go:embed schema.sql
var schemaSQL string

var _ Storage = &SQLiteStorage{}

type SQLiteStorage struct {
	dbPath    string
	db        *sql.DB
	jwtSecret []byte
}

func NewSQLiteStorage(dbPath string, jwtSecret []byte) *SQLiteStorage {
	storage := &SQLiteStorage{dbPath: dbPath, jwtSecret: jwtSecret}

	var err error
	storage.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		slog.Error("failed to open SQLite database", "error", err)
		return nil
	}
	if _, err := storage.db.Exec(schemaSQL); err != nil {
		slog.Error("failed to create schema", "error", err)
		return nil
	}

	return storage
}

func (s *SQLiteStorage) generateJWT(userId string, expiresAt int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userId,
		"exp": expiresAt,
	})
	return token.SignedString(s.jwtSecret)
}

func (s *SQLiteStorage) CreateUser(profile UserProfile, passwordHash string) (UserProfile, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return UserProfile{}, err
	}
	defer tx.Rollback()

	profile.RegistrationDate = time.Now().Unix()

	_, err = tx.Exec(
		"INSERT INTO user_profile (user_id, username, language, registration_date) VALUES (?, ?, ?, ?)",
		profile.UserID, profile.Username, profile.Language, profile.RegistrationDate,
	)
	if err != nil {
		return UserProfile{}, err
	}

	_, err = tx.Exec(
		"INSERT INTO user_credential (user_id, password_hash) VALUES (?, ?)",
		profile.UserID, passwordHash,
	)
	if err != nil {
		return UserProfile{}, err
	}

	if err = tx.Commit(); err != nil {
		return UserProfile{}, err
	}

	return profile, nil
}

func (s *SQLiteStorage) GetUserProfile(userId string) (UserProfile, error) {
	var u UserProfile
	err := s.db.QueryRow(
		"SELECT user_id, username, language, registration_date FROM user_profile WHERE user_id = ?",
		userId,
	).Scan(&u.UserID, &u.Username, &u.Language, &u.RegistrationDate)

	return u, err
}

func (s *SQLiteStorage) GetUserCredential(userId string) (UserCredential, error) {
	var u UserCredential
	err := s.db.QueryRow(
		"SELECT user_id, password_hash FROM user_credential WHERE user_id = ?",
		userId,
	).Scan(&u.UserID, &u.PasswordHash)

	return u, err
}

func (s *SQLiteStorage) UpdateUserProfile(profile UserProfile) error {
	_, err := s.db.Exec(
		"UPDATE user_profile SET username = ?, language = ? WHERE user_id = ?",
		profile.Username, profile.Language, profile.UserID,
	)
	return err
}

func (s *SQLiteStorage) UpdateUserCredential(userId string, passwordHash string) error {
	_, err := s.db.Exec(
		"UPDATE user_credential SET password_hash = ? WHERE user_id = ?",
		passwordHash, userId,
	)
	return err
}

func (s *SQLiteStorage) CreateSession(userId string) (UserSession, error) {
	// Generate JWT.
	createdAt := time.Now().Unix()
	expiresAt := time.Now().Add(jwtTokenLifetime).Unix()
	token, err := s.generateJWT(userId, expiresAt)
	if err != nil {
		return UserSession{}, err
	}

	session := UserSession{
		UserID:    userId,
		Token:     token,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	res, err := s.db.Exec(
		"INSERT INTO user_session (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
		session.UserID, session.Token, session.CreatedAt, session.ExpiresAt,
	)
	if err != nil {
		return UserSession{}, err
	}

	session.SessionID, err = res.LastInsertId()
	if err != nil {
		return UserSession{}, err
	}

	return session, nil
}

func (s *SQLiteStorage) RefreshSession(oldToken string) (UserSession, error) {
	var session UserSession

	err := s.db.QueryRow(
		"SELECT session_id, user_id, token, created_at, expires_at FROM user_session WHERE token = ?",
		oldToken,
	).Scan(&session.SessionID, &session.UserID, &session.Token, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		return UserSession{}, err
	}

	if time.Now().Unix() > session.ExpiresAt {
		_ = s.DeleteSession(session.SessionID)
		return UserSession{}, errors.New("session expired")
	}

	// Generate the new JWT.
	session.ExpiresAt = time.Now().Add(jwtTokenLifetime).Unix()
	session.Token, err = s.generateJWT(session.UserID, session.ExpiresAt)
	if err != nil {
		return UserSession{}, err
	}

	_, err = s.db.Exec(
		"UPDATE user_session SET token = ?, expires_at = ? WHERE session_id = ?",
		session.Token, session.ExpiresAt, session.SessionID,
	)
	if err != nil {
		return UserSession{}, err
	}

	return session, nil
}

func (s *SQLiteStorage) DeleteSession(sessionId int64) error {
	_, err := s.db.Exec("DELETE FROM user_session WHERE session_id = ?", sessionId)
	return err
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}
