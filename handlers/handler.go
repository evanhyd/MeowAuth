package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"meowauth/storages"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	storage storages.Storage
	secret  []byte
}

func NewAuthHandler(storage storages.Storage, jwtSecret []byte) *AuthHandler {
	return &AuthHandler{storage: storage, secret: jwtSecret}
}

// Extract token information.
func (h *AuthHandler) verifyToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return h.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token claims")
}

// 3-20 characters long, contains only alphanumeric characters, and has at least one letter.
func (h *AuthHandler) isValidUserId(userId string) bool {
	length := utf8.RuneCountInString(userId)
	if length < 3 || length > 20 {
		return false
	}

	hasLetter := false
	for _, char := range userId {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			return false
		}
		if unicode.IsLetter(char) {
			hasLetter = true
		}
	}

	return hasLetter
}

// 8-30 characters long and contains at least one letter, one number, and one special character.
func (h *AuthHandler) isValidPassword(password string) bool {
	length := utf8.RuneCountInString(password)
	if length < 8 || length > 30 {
		return false
	}

	var hasLetter, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsLetter(char):
			hasLetter = true
		case unicode.IsNumber(char): // Matches digits in many scripts
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasLetter && hasNumber && hasSpecial
}

func (h *AuthHandler) RegisterService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if !h.isValidUserId(req.UserId) {
		sendError(w, http.StatusBadRequest, "invalid user_id format")
		return
	}
	if !h.isValidPassword(req.Password) {
		sendError(w, http.StatusBadRequest, "invalid password format")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to process password")
		return
	}

	profile := storages.UserProfile{
		UserId:           req.UserId,
		Username:         req.Username,
		Language:         req.Language,
		RegistrationDate: time.Now().Unix(),
	}

	if err := h.storage.CreateUser(profile, string(hashedPassword)); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	sendJSON(w, http.StatusCreated, RegisterResponse{})
}

func (h *AuthHandler) LoginService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	hash, err := h.storage.GetUserPasswordHash(req.UserId)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		sendError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	session, err := h.storage.CreateSession(req.UserId)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	sendJSON(w, http.StatusOK, LoginResponse{Token: session.Token})
}

func (h *AuthHandler) RefreshService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	newSession, err := h.storage.RefreshSession(req.Token)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	sendJSON(w, http.StatusOK, RefreshResponse{Token: newSession.Token})
}

func (h *AuthHandler) ResetPasswordService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if !h.isValidPassword(req.NewPassword) {
		sendError(w, http.StatusBadRequest, "invalid new password format")
		return
	}

	verifiedToken, err := h.verifyToken(req.Token)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to process password")
		return
	}

	if err := h.storage.UpdateUserPassword(verifiedToken.Subject, string(hashedPassword)); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	if err := h.storage.DeleteAllSessions(verifiedToken.Subject); err != nil {
		sendError(w, http.StatusInternalServerError, "failed to invalidate existing sessions")
		return
	}

	sendJSON(w, http.StatusOK, ResetPasswordResponse{})
}

func (h *AuthHandler) MeService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// 1. Decode the token from the JSON body instead of the headers
	var req MeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if req.Token == "" {
		sendError(w, http.StatusUnauthorized, "missing token in body")
		return
	}

	// 2. Verify the token extracted from the request body
	verifiedToken, err := h.verifyToken(req.Token)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	profile, err := h.storage.GetUserProfile(verifiedToken.Subject)
	if err != nil {
		sendError(w, http.StatusNotFound, "user profile not found")
		return
	}

	// 3. Wrap the response in the MeResponse struct to match your design
	sendJSON(w, http.StatusOK, MeResponse{
		UserId:           profile.UserId,
		Username:         profile.Username,
		Language:         profile.Language,
		RegistrationDate: profile.RegistrationDate,
	})
}
