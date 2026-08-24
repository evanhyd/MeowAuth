# MeowAuth

MeowAuth is a small, self-hosted authentication service written in Go. It provides user registration, password-based login, JWT session management, password resets, and access to the current user's profile.

## Features

- SQLite-backed user profiles, credentials, and sessions
- Bcrypt password hashing
- Seven-day JWT session tokens with refresh-token rotation
- Password reset that invalidates existing sessions
- JSON responses and structured logging through Go's `log/slog`
- Automatic daily cleanup of expired sessions

## Requirements

- Go `1.25.6` or a compatible newer Go toolchain
- A writable directory for the SQLite database and log output
- A secret file containing the key used to sign JWTs

## Getting Started

Clone the project and download its dependencies:

```sh
git clone <repository-url>
cd MeowAuth
go mod download
```

Create a private JWT signing key. The application reads the complete contents of the file, so keep it out of source control:

```sh
openssl rand -base64 32 > jwt.key
```

Start the service:

```sh
go run . -key ./jwt.key -db ./meowauth.db -log ./meowauth.log -port 8080
```

The SQLite schema is created automatically when the service starts. The available command-line flags are:

| Flag | Default | Description |
| --- | --- | --- |
| `-key` | empty | Path to the JWT signing-key file. Required for a usable server. |
| `-db` | empty | Path to the SQLite database file. |
| `-log` | empty | Path to the append-only JSON log file. |
| `-port` | `80` | TCP port on which the HTTP server listens. |

## Using the Service

All endpoints use `POST` with a JSON request body. Tokens are sent in the JSON body as `token` fields.

Register a user:

```sh
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"userId":"yudahe","username":"Yuda","language":0,"password":"Str0ngPassword!"}'
```

Log in and save the returned token:

```sh
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"userId":"yudahe","password":"Str0ngPassword!"}'
```

Use the token to retrieve the current profile:

```sh
curl -X POST http://localhost:8080/users/me \
  -H "Content-Type: application/json" \
  -d '{"token":"<token-from-login>"}'
```

The `language` value is an integer: `0` for English, `1` for French, `2` for Chinese, or `3` for Japanese. User IDs are lowercased by the server and must contain 3-20 letters and numbers, including at least one letter. Passwords must contain 8-30 characters, including a letter, a number, and a punctuation or symbol character.

The service also exposes `POST /auth/refresh` to rotate a valid session token and `POST /auth/reset-password` to change a password and invalidate the user's existing sessions.

## Development

Run the test suite:

```sh
go test ./...
```

Build a binary:

```sh
go build -o meowauth .
```

The project layout is intentionally small:

| Directory/file | Purpose |
| --- | --- |
| `main.go` | CLI flags, server setup, and route registration |
| `handlers/` | HTTP handlers, request/response types, and handler tests |
| `storages/` | Storage interfaces, SQLite implementation, and schema |
| `loggers/` | Global structured logger setup |
| `LICENSE` | MIT license |

## Support

For help, start with the source and tests in this repository. The handler tests document expected status codes and representative request behavior. For a defect or feature request, open an issue in the hosting repository with:

- the command and configuration used to start MeowAuth
- the request and response status (remove credentials and tokens)
- relevant log messages
- a minimal reproduction, when possible

Do not include JWT keys, passwords, session tokens, or the SQLite database in bug reports.

## Contributing

Contributions are welcome. Before opening a pull request:

1. Create a focused branch for the change.
2. Add or update tests for behavior changes.
3. Run `gofmt` on changed Go files and run `go test ./...`.
4. Describe the behavior change and any operational or compatibility impact.

Please keep changes focused, avoid committing generated databases or secrets, and preserve the existing JSON API unless a breaking change is intentional and clearly documented.

## Maintainer

MeowAuth is maintained by **UnboxTheCat**. See [`LICENSE`](LICENSE) for licensing details.

## License

MeowAuth is released under the MIT License. See [`LICENSE`](LICENSE).