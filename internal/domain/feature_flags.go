package domain

import "context"

type FeatureFlag struct {
	UUID            string `json:"uuid"`
	Key             string `json:"key"`
	Description     string `json:"description"`
	EnabledGlobally bool   `json:"enabled_globally"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
}

type FeatureFlagDetails struct {
	FeatureFlag
	UserUUIDs []string `json:"user_uuids"`
}

type CreateFeatureFlagDTO struct {
	Key             string `json:"key"              validate:"required,min=2,max=64"`
	Description     string `json:"description"      validate:"max=255"`
	EnabledGlobally bool   `json:"enabled_globally"`
}

type UpdateFeatureFlagDTO struct {
	Description     *string `json:"description,omitempty"      validate:"omitempty,max=255"`
	EnabledGlobally *bool   `json:"enabled_globally,omitempty"`
}

type ListFeatureFlagsDTO struct {
	Cursor *string
	Limit  int
}

// An empty userUUID is an anonymous caller, who only gets the globally enabled flags.
type FeatureFlagsService interface {
	Create(context.Context, CreateFeatureFlagDTO) (*FeatureFlag, error)
	GetByUUID(context.Context, string) (*FeatureFlagDetails, error)
	Update(ctx context.Context, uuid string, dto UpdateFeatureFlagDTO) (*FeatureFlag, error)
	Delete(context.Context, string) error
	List(ctx context.Context, dto ListFeatureFlagsDTO) (*Page[FeatureFlag], error)
	AddUser(ctx context.Context, flagUUID string, userUUID string) error
	RemoveUser(ctx context.Context, flagUUID string, userUUID string) error
	ListEnabledKeys(ctx context.Context, userUUID string) ([]string, error)
	IsEnabled(ctx context.Context, key string, userUUID string) (bool, error)
}

type FeatureFlagsRepository interface {
	Create(context.Context, FeatureFlag) (*FeatureFlag, error)
	FindDetailsByUUID(context.Context, string) (*FeatureFlagDetails, error)
	Update(ctx context.Context, uuid string, dto UpdateFeatureFlagDTO) (*FeatureFlag, error)
	Delete(context.Context, string) error
	List(ctx context.Context, dto ListFeatureFlagsDTO) ([]FeatureFlag, int64, error)
	AddUser(ctx context.Context, flagUUID string, userUUID string) error
	RemoveUser(ctx context.Context, flagUUID string, userUUID string) error
	// ListEnabledKeys returns the keys enabled for the user, sorted by key. A nil userUUID is an anonymous caller and only gets the globally enabled flags.
	ListEnabledKeys(ctx context.Context, userUUID *string) ([]string, error)
}
