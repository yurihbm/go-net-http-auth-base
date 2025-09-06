package domain

type AuthMethod string

const (
	AuthMethodEmail  AuthMethod = "email"
	AuthMethodGoogle AuthMethod = "google"
)

type User struct {
	UUID         string     `json:"uuid"`
	Name         string     `json:"name"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	CreatedAt    int64      `json:"created_at"`
	UpdatedAt    int64      `json:"updated_at"`
	AuthMethod   AuthMethod `json:"auth_method"`
}

type CreateUserDTO struct {
	Name       string     `json:"name" binding:"required"`
	Email      string     `json:"email" binding:"required,email"`
	Password   *string    `json:"password"`
	AuthMethod AuthMethod `json:"auth_method" binding:"required,oneof=email google"`
}

type UserUpdateDTO struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

type UsersService interface {
	GetByUUID(uuid string) (*User, error)
	Create(user *CreateUserDTO) (*User, error)
	Update(uuid string, user *UserUpdateDTO) error
	Delete(uuid string) error
}

type UsersRepository interface {
	FindByUUID(uuid string) (*User, error)
	Create(user *User) error
	Update(user *User) error
	Delete(uuid string) error
}
