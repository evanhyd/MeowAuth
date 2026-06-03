package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meowauth/storages"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// --- 1. Mock Storage Implementation ---

var _ storages.Storage = &mockStorage{}

type mockStorage struct {
	users       map[string]storages.UserProfile
	credentials map[string]storages.UserCredential
	sessions    map[int64]storages.UserSession
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		users:       make(map[string]storages.UserProfile),
		credentials: make(map[string]storages.UserCredential),
		sessions:    make(map[int64]storages.UserSession),
	}
}

func (m *mockStorage) CreateUser(profile storages.UserProfile, passwordHash string) (storages.UserProfile, error) {
	if _, exists := m.users[profile.UserID]; exists {
		return storages.UserProfile{}, errors.New("user already exists")
	}
	profile.RegistrationDate = time.Now().Unix()
	m.users[profile.UserID] = profile
	m.credentials[profile.UserID] = storages.UserCredential{UserID: profile.UserID, PasswordHash: passwordHash}
	return profile, nil
}

func (m *mockStorage) GetUserProfile(userId string) (storages.UserProfile, error) {
	if user, exists := m.users[userId]; exists {
		return user, nil
	}
	return storages.UserProfile{}, errors.New("not found")
}

func (m *mockStorage) GetUserCredential(userId string) (storages.UserCredential, error) {
	if cred, exists := m.credentials[userId]; exists {
		return cred, nil
	}
	return storages.UserCredential{}, errors.New("not found")
}

func (m *mockStorage) UpdateUserProfile(profile storages.UserProfile) error {
	return nil
}

func (m *mockStorage) UpdateUserCredential(userId string, passwordHash string) error {
	if cred, exists := m.credentials[userId]; exists {
		cred.PasswordHash = passwordHash
		m.credentials[userId] = cred
		return nil
	}
	return errors.New("user not found")
}

func (m *mockStorage) CreateSession(userId string) (storages.UserSession, error) {
	sessionID := int64(len(m.sessions) + 1)
	session := storages.UserSession{
		SessionID: sessionID,
		UserID:    userId,
		Token:     generateValidTestToken(userId),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	m.sessions[sessionID] = session
	return session, nil
}

func (m *mockStorage) RefreshSession(token string) (storages.UserSession, error) {
	if token == "invalid_token" {
		return storages.UserSession{}, errors.New("invalid or expired session token")
	}
	return storages.UserSession{
		SessionID: 99,
		UserID:    "user123",
		Token:     "new_rotated_token",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

func (m *mockStorage) DeleteSession(sessionId int64) error { return nil }
func (m *mockStorage) Close() error                        { return nil }

// --- 2. Test Helpers ---

var testSecret = []byte("super-secret-test-key")

func setupTestHandler() (*AuthHandler, *mockStorage) {
	mockDB := newMockStorage()
	handler := NewAuthHandler(mockDB, testSecret)
	return handler, mockDB
}

func generateValidTestToken(userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	str, _ := token.SignedString(testSecret)
	return str
}

// --- 3. The Unit Tests ---

func TestRegisterHandler(t *testing.T) {
	handler, mockDB := setupTestHandler()
	mockDB.CreateUser(storages.UserProfile{UserID: "duplicate_user"}, "hash")

	tests := []struct {
		name           string
		payload        RegisterRequest
		expectedStatus int
	}{
		{
			name: "Valid Registration",
			payload: RegisterRequest{
				UserID:   "user123",
				Username: "evan",
				Password: "SecurePassword1!",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Duplicate UserID",
			payload: RegisterRequest{
				UserID:   "duplicate_user",
				Username: "evan_clone",
				Password: "SecurePassword1!",
			},
			expectedStatus: http.StatusConflict,
		},
		{
			name: "Invalid UserID Format",
			payload: RegisterRequest{
				UserID:   "bad",
				Username: "evan",
				Password: "SecurePassword1!",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid Password Format",
			payload: RegisterRequest{
				UserID:   "user1234",
				Username: "evan",
				Password: "weakpassword",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(reqBody))
			rr := httptest.NewRecorder()
			handler.Register(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tc.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	handler, mockDB := setupTestHandler()

	hash, _ := bcrypt.GenerateFromPassword([]byte("C0rrect_P@ss!"), bcrypt.DefaultCost)
	mockDB.CreateUser(storages.UserProfile{UserID: "valid_user"}, string(hash))

	tests := []struct {
		name           string
		payload        LoginRequest
		expectedStatus int
	}{
		{
			name: "Valid Login",
			payload: LoginRequest{
				UserID:   "valid_user",
				Password: "C0rrect_P@ss!",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Wrong Password",
			payload: LoginRequest{
				UserID:   "valid_user",
				Password: "Wr0ng_P@ssword!",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "User Not Found",
			payload: LoginRequest{
				UserID:   "ghost_user",
				Password: "P@ssword123!",
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(reqBody))
			rr := httptest.NewRecorder()
			handler.Login(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tc.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestRefreshHandler(t *testing.T) {
	handler, _ := setupTestHandler()

	tests := []struct {
		name           string
		payload        RefreshRequest
		expectedStatus int
	}{
		{
			name:           "Valid Token Refresh",
			payload:        RefreshRequest{Token: "valid_old_token"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid Token Refresh",
			payload:        RefreshRequest{Token: "invalid_token"},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tc.payload)
			req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(reqBody))
			rr := httptest.NewRecorder()
			handler.Refresh(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

func TestMeHandler(t *testing.T) {
	handler, mockDB := setupTestHandler()
	validUserID := "user_token_test"
	mockDB.users[validUserID] = storages.UserProfile{UserID: validUserID, Username: "token_guy"}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "Valid Token",
			authHeader:     "Bearer " + generateValidTestToken(validUserID),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing Header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Signature",
			authHeader:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fakeclaims.fakesignature",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rr := httptest.NewRecorder()
			handler.Me(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

func TestResetPasswordHandler(t *testing.T) {
	handler, mockDB := setupTestHandler()
	validUserID := "reset_guy"
	mockDB.CreateUser(storages.UserProfile{UserID: validUserID}, "old_hash")

	tests := []struct {
		name           string
		authHeader     string
		payload        ResetPasswordRequest
		expectedStatus int
	}{
		{
			name:           "Valid Reset",
			authHeader:     "Bearer " + generateValidTestToken(validUserID),
			payload:        ResetPasswordRequest{NewPassword: "N3w_S3cure_P@ss!"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing Auth Header",
			authHeader:     "",
			payload:        ResetPasswordRequest{NewPassword: "N3w_S3cure_P@ss!"},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Malformed JSON Body",
			authHeader:     "Bearer " + generateValidTestToken(validUserID),
			payload:        ResetPasswordRequest{},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody []byte
			if tc.name == "Malformed JSON Body" {
				reqBody = []byte(`{ bad_json }`)
			} else {
				reqBody, _ = json.Marshal(tc.payload)
			}

			req := httptest.NewRequest(http.MethodPut, "/password", bytes.NewReader(reqBody))
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.ResetPassword(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}
