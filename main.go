package main

import (
	"flag"
	"log/slog"
	"meowauth/handlers"
	"meowauth/loggers"
	"meowauth/storages"
	"net/http"
	"os"
)

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

	// Start the server.
	authAPI := handlers.NewAuthHandler(storage, jwtKey)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", authAPI.Register)
	mux.HandleFunc("POST /login", authAPI.Login)
	mux.HandleFunc("POST /refresh", authAPI.Refresh)
	mux.HandleFunc("GET /me", authAPI.Me)
	mux.HandleFunc("PUT /reset_password", authAPI.ResetPassword)

	slog.Info("server starting", "port", *portFlag)
	if err := http.ListenAndServe(":"+*portFlag, mux); err != nil {
		slog.Error("server failed", "error", err)
	}
}
