package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"meowauth/storages"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	storage     storages.Storage
	jwtSecret   []byte
	userIdRegex *regexp.Regexp
}

func NewAuthHandler(storage storages.Storage, secret []byte) *AuthHandler {
	return &AuthHandler{
		storage:     storage,
		jwtSecret:   secret,
		userIdRegex: regexp.MustCompile(`(?i)^[a-z0-9_.]{6,20}$`),
	}
}

// --- Request Structs ---

type RegisterRequest struct {
	UserID   string            `json:"user_id"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	Language storages.Language `json:"language"`
}

type LoginRequest struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	Token string `json:"token"`
}

type ResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// --- Response Structs ---

type ErrorResponse struct {
	Error string `json:"error"`
}

type AuthResponse struct {
	SessionID int64  `json:"session_id"`
	UserID    string `json:"user_id"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type SuccessResponse struct {
	Status string `json:"status"`
}

// --- Helpers ---

func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	sendJSON(w, code, ErrorResponse{Error: msg})
}

// verifyToken checks the JWT signature and extracts the user id.
func (h *AuthHandler) verifyToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return h.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims structure")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("user_id (sub) missing from token")
	}

	return userID, nil
}

// Helper to extract and verify the JWT from the Authorization header
func (h *AuthHandler) getUserIDFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return h.verifyToken(parts[1])
}

func verifyPassword(s string) bool {
	hasMinLen := len(s) >= 8
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	if !hasMinLen {
		return false
	}

	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// --- Handlers ---

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !h.userIdRegex.MatchString(req.UserID) {
		sendError(
			w,
			"user id must be between 6-20 characters long consists of only letters, numbers, underscore, or period",
			http.StatusBadRequest,
		)
		return
	}

	if !verifyPassword(req.Password) {
		sendError(w,
			"password must be at least 8 characters and include an uppercase letter, a lowercase letter, a number, and a special character",
			http.StatusBadRequest,
		)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	profile := storages.UserProfile{
		UserID:   req.UserID,
		Username: req.Username,
		Language: req.Language,
	}

	createdProfile, err := h.storage.CreateUser(profile, string(hash))
	if err != nil {
		sendError(w, "failed to create user, user id may already exist", http.StatusConflict)
		return
	}

	sendJSON(w, http.StatusCreated, createdProfile)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Filter out obviously bad credentials.
	if !h.userIdRegex.MatchString(req.UserID) || !verifyPassword(req.Password) {
		sendError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	cred, err := h.storage.GetUserCredential(req.UserID)
	if err != nil {
		sendError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(req.Password)); err != nil {
		sendError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	session, err := h.storage.CreateSession(req.UserID)
	if err != nil {
		sendError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	sendJSON(w, http.StatusOK, AuthResponse{
		SessionID: session.SessionID,
		UserID:    session.UserID,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	session, err := h.storage.RefreshSession(req.Token)
	if err != nil {
		sendError(w, "invalid or expired session token", http.StatusUnauthorized)
		return
	}

	sendJSON(w, http.StatusOK, AuthResponse{
		SessionID: session.SessionID,
		UserID:    session.UserID,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, err := h.getUserIDFromHeader(r)
	if err != nil {
		sendError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	profile, err := h.storage.GetUserProfile(userID)
	if err != nil {
		sendError(w, "user not found", http.StatusNotFound)
		return
	}

	sendJSON(w, http.StatusOK, profile)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	userID, err := h.getUserIDFromHeader(r)
	if err != nil {
		sendError(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !verifyPassword(req.NewPassword) {
		sendError(w,
			"password must be at least 8 characters and include an uppercase letter, a lowercase letter, a number, and a special character",
			http.StatusBadRequest,
		)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		sendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := h.storage.UpdateUserCredential(userID, string(hash)); err != nil {
		sendError(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	sendJSON(w, http.StatusOK, SuccessResponse{Status: "password updated successfully"})
}
