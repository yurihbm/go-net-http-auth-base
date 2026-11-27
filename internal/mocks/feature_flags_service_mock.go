package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type FeatureFlagsServiceMock struct {
	mock.Mock
}

var _ domain.FeatureFlagsService = (*FeatureFlagsServiceMock)(nil)

func (m *FeatureFlagsServiceMock) Create(ctx context.Context, dto domain.CreateFeatureFlagDTO) (*domain.FeatureFlag, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.FeatureFlag), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsServiceMock) GetByUUID(ctx context.Context, uuid string) (*domain.FeatureFlagDetails, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.FeatureFlagDetails), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsServiceMock) Update(ctx context.Context, uuid string, dto domain.UpdateFeatureFlagDTO) (*domain.FeatureFlag, error) {
	args := m.Called(uuid, dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.FeatureFlag), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsServiceMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *FeatureFlagsServiceMock) List(ctx context.Context, dto domain.ListFeatureFlagsDTO) (*domain.Page[domain.FeatureFlag], error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.Page[domain.FeatureFlag]), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsServiceMock) AddUser(ctx context.Context, flagUUID string, userUUID string) error {
	args := m.Called(flagUUID, userUUID)
	return args.Error(0)
}

func (m *FeatureFlagsServiceMock) RemoveUser(ctx context.Context, flagUUID string, userUUID string) error {
	args := m.Called(flagUUID, userUUID)
	return args.Error(0)
}

func (m *FeatureFlagsServiceMock) ListEnabledKeys(ctx context.Context, userUUID string) ([]string, error) {
	args := m.Called(userUUID)
	if args.Get(0) != nil {
		return args.Get(0).([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsServiceMock) IsEnabled(ctx context.Context, key string, userUUID string) (bool, error) {
	args := m.Called(key, userUUID)
	return args.Bool(0), args.Error(1)
}
