package storages

import (
	"database/sql"
	"testing"
	"time"
)

// setupTestDB is a fixture that initializes an in-memory SQLite database
func setupTestDB(t *testing.T) *SQLiteStorage {
	t.Helper()

	storage := NewSQLiteStorage(":memory:", []byte("test_secret_key"))
	if storage == nil {
		t.Fatal("failed to initialize in-memory SQLite storage")
	}

	t.Cleanup(func() {
		storage.Close()
	})

	return storage
}

func TestProfileAccessor(t *testing.T) {
	s := setupTestDB(t)

	userID := "user-123"
	originalProfile := UserProfile{
		UserId:           userID,
		Username:         "testuser",
		Language:         LangEnglish,
		RegistrationDate: time.Now().Unix(),
	}
	initialPasswordHash := "hash_123"

	t.Run("CreateUser", func(t *testing.T) {
		created, err := s.CreateUser(originalProfile, initialPasswordHash)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		if created.UserId != userID {
			t.Errorf("Expected userID %s, got %s", userID, created.UserId)
		}
	})

	t.Run("GetUserProfile", func(t *testing.T) {
		retrieved, err := s.GetUserProfile(userID)
		if err != nil {
			t.Fatalf("GetUserProfile failed: %v", err)
		}
		if retrieved.Username != originalProfile.Username {
			t.Errorf("Expected username %s, got %s", originalProfile.Username, retrieved.Username)
		}
		if retrieved.Language != originalProfile.Language {
			t.Errorf("Expected language %d, got %d", originalProfile.Language, retrieved.Language)
		}
	})

	t.Run("UpdateUserProfile", func(t *testing.T) {
		updatedProfile := UserProfile{
			UserId:           userID,
			Username:         "new_testuser",
			Language:         LangFrench,
			RegistrationDate: originalProfile.RegistrationDate,
		}

		err := s.UpdateUserProfile(updatedProfile)
		if err != nil {
			t.Fatalf("UpdateUserProfile failed: %v", err)
		}

		retrieved, err := s.GetUserProfile(userID)
		if err != nil {
			t.Fatalf("GetUserProfile after update failed: %v", err)
		}
		if retrieved.Username != "new_testuser" {
			t.Errorf("Expected updated username 'new_testuser', got %s", retrieved.Username)
		}
		if retrieved.Language != LangFrench {
			t.Errorf("Expected updated language %d, got %d", LangFrench, retrieved.Language)
		}
	})

	t.Run("UpdateUserPassword", func(t *testing.T) {
		newPasswordHash := "hash_456"
		err := s.UpdateUserPassword(userID, newPasswordHash)
		if err != nil {
			t.Fatalf("UpdateUserPassword failed: %v", err)
		}

		// Verify directly against the database since there is no GetUserPassword in the interface
		var dbHash string
		err = s.db.QueryRow("SELECT password_hash FROM user_credential WHERE user_id = ?", userID).Scan(&dbHash)
		if err != nil {
			t.Fatalf("Failed to query updated password hash: %v", err)
		}
		if dbHash != newPasswordHash {
			t.Errorf("Expected password hash %s, got %s", newPasswordHash, dbHash)
		}
	})
}

func TestSessionAccessor(t *testing.T) {
	s := setupTestDB(t)

	// Seed a user to satisfy the foreign key constraint on user_session
	userID := "user-456"
	_, err := s.CreateUser(UserProfile{
		UserId:           userID,
		Username:         "sessionuser",
		Language:         LangEnglish,
		RegistrationDate: time.Now().Unix(),
	}, "dummy_hash")
	if err != nil {
		t.Fatalf("Failed to seed user: %v", err)
	}

	var activeToken string

	t.Run("CreateSession", func(t *testing.T) {
		session, err := s.CreateSession(userID)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		if session.Token == "" {
			t.Error("Expected valid token, got empty string")
		}
		if session.UserId != userID {
			t.Errorf("Expected session userID %s, got %s", userID, session.UserId)
		}
		if session.ExpiresAt <= session.CreatedAt {
			t.Error("ExpiresAt should be greater than CreatedAt")
		}

		// Verify session was inserted into the database
		var dbUserID string
		err = s.db.QueryRow("SELECT user_id FROM user_session WHERE token = ?", session.Token).Scan(&dbUserID)
		if err != nil {
			t.Fatalf("Failed to query created session: %v", err)
		}

		activeToken = session.Token
	})

	t.Run("RefreshSession", func(t *testing.T) {
		// Sleep briefly to ensure the new token has a different IssuedAt timestamp
		time.Sleep(1 * time.Second)

		newSession, err := s.RefreshSession(activeToken)
		if err != nil {
			t.Fatalf("RefreshSession failed: %v", err)
		}
		if newSession.Token == activeToken {
			t.Error("Expected new token after refresh, got the same token")
		}
		if newSession.UserId != userID {
			t.Errorf("Expected new session userID %s, got %s", userID, newSession.UserId)
		}

		// Verify old session is deleted
		var count int
		err = s.db.QueryRow("SELECT COUNT(*) FROM user_session WHERE token = ?", activeToken).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query old session: %v", err)
		}
		if count != 0 {
			t.Error("Expected old session to be deleted from the database")
		}

		// Verify new session is stored
		err = s.db.QueryRow("SELECT COUNT(*) FROM user_session WHERE token = ?", newSession.Token).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query new session: %v", err)
		}
		if count != 1 {
			t.Error("Expected new session to be stored in the database")
		}
	})
}

func TestGetUserPasswordHash(t *testing.T) {
	s := setupTestDB(t)

	userID := "hash_test_user"
	expectedHash := "super_secret_hash_value"
	profile := UserProfile{
		UserId:           userID,
		Username:         "hashtester",
		Language:         LangEnglish,
		RegistrationDate: time.Now().Unix(),
	}

	// 1. Setup: Create user with the expected hash
	_, err := s.CreateUser(profile, expectedHash)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// 2. Test successful retrieval
	retrievedHash, err := s.GetUserPasswordHash(userID)
	if err != nil {
		t.Fatalf("GetUserPasswordHash failed: %v", err)
	}
	if retrievedHash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, retrievedHash)
	}

	// 3. Test retrieval for non-existent user
	_, err = s.GetUserPasswordHash("non_existent_user")
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows for non-existent user, got: %v", err)
	}
}

func TestDeleteAllSessions(t *testing.T) {
	s := setupTestDB(t)

	userID := "session_del_user"
	otherUserID := "other_user"

	s.CreateUser(UserProfile{
		UserId:           userID,
		Username:         "sessiondeleter",
		Language:         LangEnglish,
		RegistrationDate: time.Now().Unix(),
	}, "dummy_hash")

	s.CreateUser(UserProfile{
		UserId:           otherUserID,
		Username:         "other",
		Language:         LangEnglish,
		RegistrationDate: time.Now().Unix(),
	}, "dummy_hash")

	// 1. Setup: Create multiple sessions for the target user
	_, err := s.CreateSession(userID)
	if err != nil {
		t.Fatalf("Failed to create session 1: %v", err)
	}

	// Brief sleep to ensure distinct timestamps/tokens if execution is too fast
	time.Sleep(10 * time.Millisecond)

	_, err = s.CreateSession(userID)
	if err != nil {
		t.Fatalf("Failed to create session 2: %v", err)
	}

	// Setup: Create a session for a different user to verify isolation
	_, err = s.CreateSession(otherUserID)
	if err != nil {
		t.Fatalf("Failed to create session for other user: %v", err)
	}

	// Verify target user sessions exist
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM user_session WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count sessions: %v", err)
	}
	if count != 2 {
		t.Fatalf("Expected 2 sessions before deletion, found %d", count)
	}

	// 2. Test DeleteAllSessions
	err = s.DeleteAllSessions(userID)
	if err != nil {
		t.Fatalf("DeleteAllSessions failed: %v", err)
	}

	// 3. Verify target user sessions were deleted
	err = s.db.QueryRow("SELECT COUNT(*) FROM user_session WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count sessions after deletion: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 sessions after deletion, found %d", count)
	}

	// 4. Verify other user's session was NOT deleted
	err = s.db.QueryRow("SELECT COUNT(*) FROM user_session WHERE user_id = ?", otherUserID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count other user sessions: %v", err)
	}
	if count != 1 {
		t.Errorf("DeleteAllSessions incorrectly affected other users, expected 1 session left, found %d", count)
	}
}
