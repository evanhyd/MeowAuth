package storages

import (
	"testing"
	"time"
)

// setupTestDB initializes an in-memory SQLite database for isolated testing.
func setupTestDB(t *testing.T) *SQLiteStorage {
	dbPath := "file::memory:?cache=shared"
	secret := []byte("super-secret-test-key")
	storage := NewSQLiteStorage(dbPath, secret)
	if storage == nil {
		t.Fatal("failed to initialize test database")
	}
	return storage
}

func TestUserOperations(t *testing.T) {
	storage := setupTestDB(t)
	defer storage.Close()

	userID := "user-123"
	username := "testuser"
	passwordHash := "hashed-password-string"

	t.Run("CreateUser", func(t *testing.T) {
		profile := UserProfile{
			UserID:   userID,
			Username: username,
			Language: LangEnglish,
		}

		createdProfile, err := storage.CreateUser(profile, passwordHash)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if createdProfile.UserID != userID {
			t.Errorf("expected UserID %s, got %s", userID, createdProfile.UserID)
		}
		if createdProfile.RegistrationDate <= 0 {
			t.Error("expected valid registration date timestamp")
		}
	})

	t.Run("GetUserProfile", func(t *testing.T) {
		profile, err := storage.GetUserProfile(userID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if profile.Username != username {
			t.Errorf("expected Username %s, got %s", username, profile.Username)
		}
	})

	t.Run("GetUserCredential", func(t *testing.T) {
		cred, err := storage.GetUserCredential(userID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if cred.PasswordHash != passwordHash {
			t.Errorf("expected hash %s, got %s", passwordHash, cred.PasswordHash)
		}
	})

	t.Run("UpdateUserProfile", func(t *testing.T) {
		newUsername := "updateduser"
		err := storage.UpdateUserProfile(UserProfile{
			UserID:   userID,
			Username: newUsername,
			Language: LangEnglish,
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		profile, _ := storage.GetUserProfile(userID)
		if profile.Username != newUsername {
			t.Errorf("expected Username %s, got %s", newUsername, profile.Username)
		}
	})

	t.Run("UpdateUserCredential", func(t *testing.T) {
		newPasswordHash := "new-super-secure-hash"

		err := storage.UpdateUserCredential(userID, newPasswordHash)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		cred, err := storage.GetUserCredential(userID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if cred.PasswordHash != newPasswordHash {
			t.Errorf("expected hash %s, got %s", newPasswordHash, cred.PasswordHash)
		}
	})
}

func TestSessionOperations(t *testing.T) {
	storage := setupTestDB(t)
	defer storage.Close()

	// Seed a user required for the foreign key constraint
	userID := "user-456"
	_, err := storage.CreateUser(UserProfile{UserID: userID, Username: "sessionuser"}, "hash")
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	var activeToken string
	var sessionID int64
	var initialExpiresAt int64

	t.Run("CreateSession", func(t *testing.T) {
		session, err := storage.CreateSession(userID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if session.Token == "" {
			t.Error("expected token to be generated")
		}
		if session.ExpiresAt <= time.Now().Unix() {
			t.Error("expected expiration date to be in the future")
		}

		activeToken = session.Token
		sessionID = session.SessionID
		initialExpiresAt = session.ExpiresAt
	})

	t.Run("RefreshSession", func(t *testing.T) {
		// Sleep briefly to ensure the time.Now().Unix() calculation for the new JWT is distinct
		time.Sleep(2 * time.Second)

		newSession, err := storage.RefreshSession(activeToken)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if newSession.Token == activeToken {
			t.Error("expected token to be rotated, but it remained the same")
		}
		if newSession.ExpiresAt < initialExpiresAt {
			t.Error("expected new expiration date to be extended")
		}

		// Update activeToken for the next test
		activeToken = newSession.Token
	})

	t.Run("DeleteSession", func(t *testing.T) {
		err := storage.DeleteSession(sessionID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Attempting to refresh a deleted session should fail
		_, err = storage.RefreshSession(activeToken)
		if err == nil {
			t.Error("expected error refreshing deleted session, got nil")
		}
	})
}
