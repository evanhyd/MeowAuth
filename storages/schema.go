package storages

type Language = int64

const (
	LangEnglish Language = iota
	LangFrench
	LangChinese
	LangJapanese
)

type UserProfile struct {
	UserId           string
	Username         string
	Language         Language
	RegistrationDate int64 // Unix
}

type UserCredential struct {
	UserId       string
	PasswordHash string
}

type UserSession struct {
	Token     string
	UserId    string
	CreatedAt int64 // Unix
	ExpiresAt int64 // Unix
}
