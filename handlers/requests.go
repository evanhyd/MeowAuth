package handlers

import (
	"encoding/json"
	"net/http"
)

// Enum
type Language = int64

const (
	LangEnglish Language = iota
	LangFrench
	LangChinese
	LangJapanese
)

// Request
type RegisterRequest struct {
	UserId   string   `json:"user_id"`
	Username string   `json:"username"`
	Language Language `json:"language"`
	Password string   `json:"password"`
}

type LoginRequest struct {
	UserId   string `json:"user_id"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	Token string `json:"token"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type MeRequest struct {
	Token string `json:"token"`
}

// Response
type ErrorResponse struct {
	Error string `json:"error"`
}

type RegisterResponse struct {
}

type RefreshResponse struct {
	Token string `json:"token"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ResetPasswordResponse struct {
}

type MeResponse struct {
	UserId           string   `json:"user_id"`
	Username         string   `json:"username"`
	Language         Language `json:"language"`
	RegistrationDate int64    `json:"registration_date"` // Unix
}

// Helper
func sendJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func sendError(w http.ResponseWriter, code int, msg string) {
	sendJSON(w, code, ErrorResponse{Error: msg})
}
