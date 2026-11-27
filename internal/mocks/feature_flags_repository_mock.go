package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type FeatureFlagsRepositoryMock struct {
	mock.Mock
}

var _ domain.FeatureFlagsRepository = (*FeatureFlagsRepositoryMock)(nil)

func (m *FeatureFlagsRepositoryMock) Create(ctx context.Context, flag domain.FeatureFlag) (*domain.FeatureFlag, error) {
	args := m.Called(flag)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.FeatureFlag), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsRepositoryMock) FindDetailsByUUID(ctx context.Context, uuid string) (*domain.FeatureFlagDetails, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.FeatureFlagDetails), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsRepositoryMock) Update(ctx context.Context, uuid string, dto domain.UpdateFeatureFlagDTO) (*domain.FeatureFlag, error) {
	args := m.Called(uuid, dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.FeatureFlag), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *FeatureFlagsRepositoryMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *FeatureFlagsRepositoryMock) List(ctx context.Context, dto domain.ListFeatureFlagsDTO) ([]domain.FeatureFlag, int64, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).([]domain.FeatureFlag), args.Get(1).(int64), args.Error(2)
	}
	return nil, 0, args.Error(2)
}

func (m *FeatureFlagsRepositoryMock) AddUser(ctx context.Context, flagUUID string, userUUID string) error {
	args := m.Called(flagUUID, userUUID)
	return args.Error(0)
}

func (m *FeatureFlagsRepositoryMock) RemoveUser(ctx context.Context, flagUUID string, userUUID string) error {
	args := m.Called(flagUUID, userUUID)
	return args.Error(0)
}

func (m *FeatureFlagsRepositoryMock) ListEnabledKeys(ctx context.Context, userUUID *string) ([]string, error) {
	args := m.Called(userUUID)
	if args.Get(0) != nil {
		return args.Get(0).([]string), args.Error(1)
	}
	return nil, args.Error(1)
}
