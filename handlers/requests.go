package handlers

import (
	"encoding/json"
	"meowauth/storages"
	"net/http"
)

// Request
type RegisterRequest struct {
	UserId   string            `json:"user_id"`
	Username string            `json:"username"`
	Language storages.Language `json:"language"`
	Password string            `json:"password"`
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

// Response
type ErrorResponse struct {
	Error string `json:"error"`
}

type RegisterResponse struct {
	Profile storages.UserProfile `json:"profile"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type RefreshResponse struct {
	Token string `json:"token"`
}

type ResetPasswordResponse struct {
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
