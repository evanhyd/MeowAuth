package storages

type Language int

const (
	LangEnglish Language = iota
	LangFrench
	LangChinese
	LangJapanese
)

type UserProfile struct {
	UserID           string
	Username         string
	Language         Language
	RegistrationDate int64 // Unix
}

type UserCredential struct {
	UserID       string
	PasswordHash string
}

type UserSession struct {
	SessionID int64
	UserID    string
	Token     string
	CreatedAt int64 // Unix
	ExpiresAt int64 // Unix
}
