package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meowauth/storages" // adjust import path

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// --- Mock Storage for Unit Testing ---

type MockStorage struct {
	users    map[string]storages.UserProfile
	passHash map[string]string
	sessions map[string]storages.UserSession
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		users:    make(map[string]storages.UserProfile),
		passHash: make(map[string]string),
		sessions: make(map[string]storages.UserSession),
	}
}

func (m *MockStorage) Close() error { return nil }

func (m *MockStorage) CreateUser(profile storages.UserProfile, hashedPassword string) error {
	if _, exists := m.users[profile.UserId]; exists {
		return errors.New("user already exists")
	}
	m.users[profile.UserId] = profile
	m.passHash[profile.UserId] = hashedPassword
	return nil
}

func (m *MockStorage) GetUserProfile(UserId string) (storages.UserProfile, error) {
	p, ok := m.users[UserId]
	if !ok {
		return storages.UserProfile{}, errors.New("not found")
	}
	return p, nil
}

func (m *MockStorage) UpdateUserProfile(profile storages.UserProfile) error {
	m.users[profile.UserId] = profile
	return nil
}

func (m *MockStorage) UpdateUserPassword(UserId string, hashedPassword string) error {
	m.passHash[UserId] = hashedPassword
	return nil
}

func (m *MockStorage) GetUserPasswordHash(UserId string) (string, error) {
	h, ok := m.passHash[UserId]
	if !ok {
		return "", errors.New("not found")
	}
	return h, nil
}

func (m *MockStorage) CreateSession(UserId string) (storages.UserSession, error) {
	session := storages.UserSession{
		Token:     "mock_token_" + UserId,
		UserId:    UserId,
		CreatedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	m.sessions[session.Token] = session
	return session, nil
}

func (m *MockStorage) RefreshSession(token string) (storages.UserSession, error) {
	s, ok := m.sessions[token]
	if !ok {
		return storages.UserSession{}, errors.New("invalid token")
	}
	delete(m.sessions, token)
	return m.CreateSession(s.UserId)
}

func (m *MockStorage) DeleteAllSessions(UserId string) error {
	for k, v := range m.sessions {
		if v.UserId == UserId {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *MockStorage) DeleteAllExpiredSessions() error {
	panic("not implemented")
}

func generateTestJWT(subject string, secret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: subject,
	})
	tokenString, _ := token.SignedString(secret)
	return tokenString
}

// --- Test Cases ---

func TestRegisterService(t *testing.T) {
	mockStore := NewMockStorage()
	handler := NewAuthHandler(mockStore, []byte("secret"))

	tests := []struct {
		name         string
		method       string
		payload      RegisterRequest
		expectedCode int
	}{
		{
			name:   "Valid Registration",
			method: http.MethodPost,
			payload: RegisterRequest{
				UserId:   "yudahe",
				Username: "Yuda",
				Language: storages.LangEnglish,
				Password: "Str0ngPassword!",
			},
			expectedCode: http.StatusCreated,
		},
		{
			name:   "Invalid Method",
			method: http.MethodGet,
			payload: RegisterRequest{
				UserId:   "yudahe2",
				Password: "Str0ngPassword!",
			},
			expectedCode: http.StatusMethodNotAllowed,
		},
		{
			name:   "Invalid UserId",
			method: http.MethodPost,
			payload: RegisterRequest{
				UserId:   "yu", // too short
				Username: "Yuda",
				Password: "Str0ngPassword!",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:   "Invalid Password",
			method: http.MethodPost,
			payload: RegisterRequest{
				UserId:   "yudahe3",
				Username: "Yuda",
				Password: "weak", // too short, no special char
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(tt.method, "/register", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			handler.RegisterService(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedCode, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestLoginService(t *testing.T) {
	mockStore := NewMockStorage()
	handler := NewAuthHandler(mockStore, []byte("secret"))

	// Pre-populate a user for login testing
	password := "ValidP@ssw0rd!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mockStore.CreateUser(storages.UserProfile{
		UserId:   "yuda2026",
		Username: "Yuda",
	}, string(hashedPassword))

	tests := []struct {
		name         string
		payload      LoginRequest
		expectedCode int
	}{
		{
			name: "Valid Login",
			payload: LoginRequest{
				UserId:   "yuda2026",
				Password: password,
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "Invalid Password",
			payload: LoginRequest{
				UserId:   "yuda2026",
				Password: "WrongPassword!",
			},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name: "Non-existent User",
			payload: LoginRequest{
				UserId:   "ghostuser",
				Password: password,
			},
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			handler.LoginService(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedCode, rr.Code, rr.Body.String())
			}

			if tt.expectedCode == http.StatusOK {
				var resp LoginResponse
				json.NewDecoder(rr.Body).Decode(&resp)
				if resp.Token == "" {
					t.Errorf("Expected a token in response, got empty string")
				}
			}
		})
	}
}
func TestRefreshService(t *testing.T) {
	storage := NewMockStorage()
	handler := &AuthHandler{storage: storage}

	// Setup valid session in mock storage
	validSession, _ := storage.CreateSession("testuser")

	tests := []struct {
		name           string
		method         string
		body           any
		expectedStatus int
	}{
		{
			name:           "Valid Refresh",
			method:         http.MethodPost,
			body:           RefreshRequest{Token: validSession.Token},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Method Not Allowed",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Invalid JSON",
			method:         http.MethodPost,
			body:           "invalid-json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid Token",
			method:         http.MethodPost,
			body:           RefreshRequest{Token: "non_existent_token"},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			if str, ok := tt.body.(string); ok {
				reqBody = []byte(str)
			} else if tt.body != nil {
				reqBody, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/refresh", bytes.NewBuffer(reqBody))
			rr := httptest.NewRecorder()

			handler.RefreshService(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}
		})
	}
}

func TestResetPasswordService(t *testing.T) {
	secret := []byte("testsecret")
	storage := NewMockStorage()
	handler := &AuthHandler{storage: storage, secret: secret}

	// Setup a user and session in mock storage
	userID := "testuser"
	originalHash, _ := bcrypt.GenerateFromPassword([]byte("OldPass123!"), bcrypt.MinCost)
	storage.CreateUser(storages.UserProfile{UserId: userID, Username: "Test"}, string(originalHash))
	storage.CreateSession(userID)

	validJWT := generateTestJWT(userID, secret)

	tests := []struct {
		name           string
		method         string
		body           any
		expectedStatus int
	}{
		{
			name:   "Valid Reset",
			method: http.MethodPost,
			body: ResetPasswordRequest{
				Token:    validJWT,
				Password: "NewValidPassword123!",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Method Not Allowed",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Invalid JSON",
			method:         http.MethodPost,
			body:           "invalid-json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid Password Format",
			method: http.MethodPost,
			body: ResetPasswordRequest{
				Token:    validJWT,
				Password: "weak", // Fails format validation
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid JWT Token",
			method: http.MethodPost,
			body: ResetPasswordRequest{
				Token:    "invalid.jwt.token",
				Password: "NewValidPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			if str, ok := tt.body.(string); ok {
				reqBody = []byte(str)
			} else if tt.body != nil {
				reqBody, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/reset-password", bytes.NewBuffer(reqBody))
			rr := httptest.NewRecorder()

			handler.ResetPasswordService(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}
		})
	}

	// Verify the session was deleted after a successful password reset
	if len(storage.sessions) != 0 {
		t.Errorf("expected all sessions to be deleted, found %d", len(storage.sessions))
	}
}

func TestMeService(t *testing.T) {
	secret := []byte("testsecret")
	storage := NewMockStorage()
	handler := &AuthHandler{storage: storage, secret: secret}

	// Setup a user in mock storage
	userID := "testuser"
	storage.CreateUser(storages.UserProfile{UserId: userID, Username: "Test", Language: 0}, "hashedpass")

	validJWT := generateTestJWT(userID, secret)
	missingUserJWT := generateTestJWT("ghostuser", secret)

	tests := []struct {
		name           string
		method         string
		body           any
		expectedStatus int
	}{
		{
			name:           "Valid Request",
			method:         http.MethodPost,
			body:           MeRequest{Token: validJWT},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Method Not Allowed",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Invalid JSON",
			method:         http.MethodPost,
			body:           "invalid-json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Missing Token",
			method:         http.MethodPost,
			body:           MeRequest{Token: ""},
			expectedStatus: http.StatusUnauthorized, // As defined in your updated handler
		},
		{
			name:           "Invalid Token",
			method:         http.MethodPost,
			body:           MeRequest{Token: "invalid.token.string"},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "User Not Found",
			method:         http.MethodPost,
			body:           MeRequest{Token: missingUserJWT},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			if str, ok := tt.body.(string); ok {
				reqBody = []byte(str)
			} else if tt.body != nil {
				reqBody, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/me", bytes.NewBuffer(reqBody))
			rr := httptest.NewRecorder()

			handler.MeService(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}
		})
	}
}
