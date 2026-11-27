package services

import (
	"context"
	"slices"

	"go-net-http-auth-base/internal/domain"
)

type featureFlagsService struct {
	repo domain.FeatureFlagsRepository
}

func NewFeatureFlagsService(repo domain.FeatureFlagsRepository) domain.FeatureFlagsService {
	return &featureFlagsService{repo: repo}
}

func (s *featureFlagsService) Create(ctx context.Context, dto domain.CreateFeatureFlagDTO) (*domain.FeatureFlag, error) {
	return s.repo.Create(ctx, domain.FeatureFlag{
		Key:             dto.Key,
		Description:     dto.Description,
		EnabledGlobally: dto.EnabledGlobally,
	})
}

func (s *featureFlagsService) GetByUUID(ctx context.Context, uuid string) (*domain.FeatureFlagDetails, error) {
	return s.repo.FindDetailsByUUID(ctx, uuid)
}

func (s *featureFlagsService) Update(ctx context.Context, uuid string, dto domain.UpdateFeatureFlagDTO) (*domain.FeatureFlag, error) {
	return s.repo.Update(ctx, uuid, dto)
}

func (s *featureFlagsService) Delete(ctx context.Context, uuid string) error {
	return s.repo.Delete(ctx, uuid)
}

func (s *featureFlagsService) List(ctx context.Context, dto domain.ListFeatureFlagsDTO) (*domain.Page[domain.FeatureFlag], error) {
	limit := dto.Limit
	dto.Limit++
	flags, total, err := s.repo.List(ctx, dto)
	if err != nil {
		return nil, err
	}

	return domain.NewPage(flags, total, limit, func(f domain.FeatureFlag) string { return f.UUID }), nil
}

func (s *featureFlagsService) AddUser(ctx context.Context, flagUUID string, userUUID string) error {
	return s.repo.AddUser(ctx, flagUUID, userUUID)
}

func (s *featureFlagsService) RemoveUser(ctx context.Context, flagUUID string, userUUID string) error {
	return s.repo.RemoveUser(ctx, flagUUID, userUUID)
}

func (s *featureFlagsService) ListEnabledKeys(ctx context.Context, userUUID string) ([]string, error) {
	var user *string
	if userUUID != "" {
		user = &userUUID
	}

	keys, err := s.repo.ListEnabledKeys(ctx, user)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, nil
}

func (s *featureFlagsService) IsEnabled(ctx context.Context, key string, userUUID string) (bool, error) {
	keys, err := s.ListEnabledKeys(ctx, userUUID)
	if err != nil {
		return false, err
	}
	return slices.Contains(keys, key), nil
}
