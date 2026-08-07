package storages

import (
	"database/sql"
	_ "embed"
	"log/slog"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

const jwtTokenLifetime = 7 * 24 * time.Hour

//go:embed schema.sql
var schemaSQL string

var _ Storage = &SQLiteStorage{}

type SQLiteStorage struct {
	db        *sql.DB
	jwtSecret []byte
}

func NewSQLiteStorage(dbPath string, jwtSecret []byte) *SQLiteStorage {
	storage := &SQLiteStorage{jwtSecret: jwtSecret}

	var err error
	storage.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		slog.Error("failed to open SQLite database", "error", err)
		panic("failed to open SQLite database")
	}

	if _, err := storage.db.Exec(schemaSQL); err != nil {
		slog.Error("failed to create schema", "error", err)
		panic("failed to create schema")
	}

	return storage
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLiteStorage) CreateUser(profile UserProfile, hashedPassword string) (UserProfile, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return UserProfile{}, err
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT INTO user_profile (user_id, username, language, registration_date) VALUES (?, ?, ?, ?)",
		profile.UserId, profile.Username, profile.Language, profile.RegistrationDate)
	if err != nil {
		return UserProfile{}, err
	}

	_, err = tx.Exec("INSERT INTO user_credential (user_id, password_hash) VALUES (?, ?)",
		profile.UserId, hashedPassword)
	if err != nil {
		return UserProfile{}, err
	}

	if err := tx.Commit(); err != nil {
		return UserProfile{}, err
	}

	return profile, nil
}

func (s *SQLiteStorage) GetUserProfile(userId string) (UserProfile, error) {
	var p UserProfile
	err := s.db.QueryRow("SELECT user_id, username, language, registration_date FROM user_profile WHERE user_id = ?", userId).
		Scan(&p.UserId, &p.Username, &p.Language, &p.RegistrationDate)
	if err != nil {
		return UserProfile{}, err
	}
	return p, nil
}

func (s *SQLiteStorage) GetUserPasswordHash(userId string) (string, error) {
	var p string
	err := s.db.QueryRow("SELECT password_hash FROM user_credential WHERE user_id = ?", userId).Scan(&p)
	if err != nil {
		return "", err
	}
	return p, nil
}

func (s *SQLiteStorage) UpdateUserProfile(profile UserProfile) error {
	_, err := s.db.Exec("UPDATE user_profile SET username = ?, language = ? WHERE user_id = ?",
		profile.Username, profile.Language, profile.UserId)
	return err
}

func (s *SQLiteStorage) UpdateUserPassword(userId string, hashedPassword string) error {
	_, err := s.db.Exec("UPDATE user_credential SET password_hash = ? WHERE user_id = ?",
		hashedPassword, userId)
	return err
}

func (s *SQLiteStorage) CreateSession(userId string) (UserSession, error) {
	now := time.Now()
	exp := now.Add(jwtTokenLifetime)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   userId,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
		ID:        strconv.FormatInt(now.UnixNano(), 10),
	})

	tokenStr, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return UserSession{}, err
	}

	session := UserSession{
		Token:     tokenStr,
		UserId:    userId,
		CreatedAt: now.Unix(),
		ExpiresAt: exp.Unix(),
	}

	_, err = s.db.Exec("INSERT INTO user_session (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		session.Token, session.UserId, session.CreatedAt, session.ExpiresAt)
	if err != nil {
		return UserSession{}, err
	}

	return session, nil
}

func (s *SQLiteStorage) RefreshSession(token string) (UserSession, error) {
	var userId string
	now := time.Now().Unix()

	// Verify the existing token is in the database and has not expired
	err := s.db.QueryRow("SELECT user_id FROM user_session WHERE token = ? AND expires_at > ?", token, now).Scan(&userId)
	if err != nil {
		return UserSession{}, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return UserSession{}, err
	}
	defer tx.Rollback()

	// Delete the old session
	_, err = tx.Exec("DELETE FROM user_session WHERE token = ?", token)
	if err != nil {
		return UserSession{}, err
	}

	if err := tx.Commit(); err != nil {
		return UserSession{}, err
	}

	// Generate and return a new session
	return s.CreateSession(userId)
}

func (s *SQLiteStorage) DeleteAllSessions(userId string) error {
	_, err := s.db.Exec("DELETE FROM user_session WHERE user_id = ?", userId)
	return err
}
