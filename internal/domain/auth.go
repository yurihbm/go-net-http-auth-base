package domain

type AuthDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password"`
}

type RefreshTokenDTO struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type AuthService interface {
	Authenticate(dto AuthDTO) (string, string, error)
	VerifyToken(token string) (string, error)
	RefreshToken(refreshToken string) (string, string, error)
}
