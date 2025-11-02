package domain

type User struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

type CreateUserDTO struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password"`
}

type UserUpdateDTO struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

type UsersService interface {
	GetByUUID(string) (*User, error)
	GetByEmail(string) (*User, error)
	Create(CreateUserDTO) (*User, error)
	Update(string, UserUpdateDTO) error
	Delete(string) error
}

type UsersRepository interface {
	FindByUUID(string) (*User, error)
	FindByEmail(string) (*User, error)
	Create(User) (*User, error)
	Update(User) error
	Delete(string) error
}
