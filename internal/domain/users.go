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
	GetByUUID(uuid string) (*User, error)
	GetByEmail(email string) (*User, error)
	Create(user CreateUserDTO) (*User, error)
	Update(uuid string, user UserUpdateDTO) error
	Delete(uuid string) error
}

type UsersRepository interface {
	FindByUUID(uuid string) (*User, error)
	FindByEmail(email string) (*User, error)
	Create(user User) (*User, error)
	Update(user User) error
	Delete(uuid string) error
}
