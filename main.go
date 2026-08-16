package main

import (
	"flag"
	"log/slog"
	"meowauth/handlers"
	"meowauth/loggers"
	"meowauth/storages"
	"net/http"
	"os"
	"time"
)

func cleanUpTokens(storage storages.Storage) {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		if err := storage.DeleteAllExpiredSessions(); err != nil {
			slog.Error("failed to clean up expired tokens", "error", err)
		}
	}
}

func main() {
	logFlag := flag.String("log", "", "The log file path.")
	jwtKeyFlag := flag.String("key", "", "The JWT key file path.")
	dbFlag := flag.String("db", "", "The database file path.")
	portFlag := flag.String("port", "80", "The server port. Default to 80.")
	flag.Parse()

	// Logger.
	logger := loggers.InitializeGlobalLogger(*logFlag)
	defer logger.Close()

	// JWT key.
	jwtKey, err := os.ReadFile(*jwtKeyFlag)
	if err != nil {
		slog.Error("failed to read jwt key", "error", err)
		return
	}

	// SQL storage.
	storage := storages.NewSQLiteStorage(*dbFlag, jwtKey)
	if storage == nil {
		return
	}
	defer storage.Close()

	go cleanUpTokens(storage)

	// Start the server.
	authAPI := handlers.NewAuthHandler(storage, jwtKey)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", authAPI.RegisterService)
	mux.HandleFunc("POST /auth/login", authAPI.LoginService)
	mux.HandleFunc("POST /auth/refresh", authAPI.RefreshService)
	mux.HandleFunc("POST /auth/reset-password", authAPI.ResetPasswordService)
	mux.HandleFunc("POST /users/me", authAPI.MeService)

	slog.Info("server starting", "port", *portFlag)
	if err := http.ListenAndServe(":"+*portFlag, mux); err != nil {
		slog.Error("server failed", "error", err)
	}
}
