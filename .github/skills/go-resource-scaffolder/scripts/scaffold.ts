import fs from 'fs';
import path from 'path';

// Get resource name from arguments
const resourceNameArg = process.argv[2];

if (!resourceNameArg) {
    console.error("Usage: npx tsx scaffold.ts <ResourceName>");
    console.error("Example: npx tsx scaffold.ts Product");
    process.exit(1);
}

// Helper functions for casing
function capitalize(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function camelize(str: string): string {
    return str.charAt(0).toLowerCase() + str.slice(1);
}

function pluralize(str: string): string {
    if (str.endsWith('y')) {
        return str.slice(0, -1) + 'ies';
    }
    return str + 's';
}

const Resource = capitalize(resourceNameArg);
const resource = camelize(resourceNameArg);
const Resources = pluralize(Resource);
const resources = pluralize(resource);

console.log(`Scaffolding resource: ${Resource}`);

// Define paths
const dirs = {
    domain: path.join('internal', 'domain'),
    repositories: path.join('internal', 'repositories'),
    services: path.join('internal', 'services'),
    controllers: path.join('internal', 'controllers'),
    factories: path.join('internal', 'factories'),
    mocks: path.join('internal', 'mocks'),
};

// Ensure directories exist (they should, but good to be safe)
for (const dir of Object.values(dirs)) {
    if (!fs.existsSync(dir)) {
        console.error(`Directory not found: ${dir}. Are you in the project root?`);
        process.exit(1);
    }
}

// Define Templates

const domainTemplate = `package domain

type ${Resource} struct {
	UUID      string \`json:"uuid"\`
	CreatedAt int64  \`json:"created_at"\`
	UpdatedAt int64  \`json:"updated_at"\`
    // Add your fields here
}

type Create${Resource}DTO struct {
    // Add your fields here
}

type ${Resource}UpdateDTO struct {
    // Add your fields here
}

type ${Resources}Service interface {
	GetByUUID(string) (*${Resource}, error)
	Create(Create${Resource}DTO) (*${Resource}, error)
	Update(string, ${Resource}UpdateDTO) error
	Delete(string) error
}

type ${Resources}Repository interface {
	FindByUUID(string) (*${Resource}, error)
	Create(${Resource}) (*${Resource}, error)
	Update(${Resource}) error
	Delete(string) error
}
`;

const repositoryTemplate = `package repositories

import (
	"context"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type ${Resources}PostgresRepository struct {
	q *postgres.Queries
}

var _ domain.${Resources}Repository = (*${Resources}PostgresRepository)(nil)

func New${Resources}PostgresRepository(db postgres.DBTX) domain.${Resources}Repository {
	return &${Resources}PostgresRepository{
		q: postgres.New(db),
	}
}

func (r *${Resources}PostgresRepository) FindByUUID(uuidStr string) (*domain.${Resource}, error) {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, err
	}

    // TODO: Implement Get${Resource}ByUUID in postgres/queries
    // user, err := r.q.Get${Resource}ByUUID(context.Background(), pgtype.UUID{Bytes: [16]byte(uuid), Valid: true})
	// if err != nil {
	// 	return nil, err
	// }

	return &domain.${Resource}{UUID: uuidStr}, nil // Placeholder
}

func (r *${Resources}PostgresRepository) Create(entity domain.${Resource}) (*domain.${Resource}, error) {
    // TODO: Implement Create${Resource} in postgres/queries
	return &entity, nil // Placeholder
}

func (r *${Resources}PostgresRepository) Update(entity domain.${Resource}) error {
    // TODO: Implement Update${Resource} in postgres/queries
	return nil // Placeholder
}

func (r *${Resources}PostgresRepository) Delete(uuidStr string) error {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return err
	}
    // TODO: Implement Delete${Resource} in postgres/queries
    _ = uuid
	return nil // Placeholder
}
`;

const serviceTemplate = `package services

import (
	"go-net-http-auth-base/internal/domain"
)

type ${resources}Service struct {
	repo domain.${Resources}Repository
}

func New${Resources}Service(repo domain.${Resources}Repository) domain.${Resources}Service {
	return &${resources}Service{repo: repo}
}

func (s *${resources}Service) GetByUUID(uuid string) (*domain.${Resource}, error) {
	return s.repo.FindByUUID(uuid)
}

func (s *${resources}Service) Create(dto domain.Create${Resource}DTO) (*domain.${Resource}, error) {
	entity := domain.${Resource}{
        // Map DTO to entity
	}

	created, err := s.repo.Create(entity)
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *${resources}Service) Update(uuid string, dto domain.${Resource}UpdateDTO) error {
	entity, err := s.repo.FindByUUID(uuid)
	if err != nil {
		return err
	}

    // Update fields
    _ = dto
    _ = entity

	if err = s.repo.Update(*entity); err != nil {
		return err
	}
	return nil
}

func (s *${resources}Service) Delete(uuid string) error {
	return s.repo.Delete(uuid)
}
`;

const controllerTemplate = `package controllers

import (
	"encoding/json"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
)

type ${Resources}Controller struct {
	service    domain.${Resources}Service
	middleware middlewares.HandlerMiddleware
}

var _ Controller = (*${Resources}Controller)(nil)

func New${Resources}Controller(service domain.${Resources}Service, middleware middlewares.HandlerMiddleware) *${Resources}Controller {
	return &${Resources}Controller{
		service:    service,
		middleware: middleware,
	}
}

func (c *${Resources}Controller) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /${resources}", c.middleware.Use(c.Create))
	router.HandleFunc("GET /${resources}/{uuid}", c.middleware.Use(c.GetByUUID))
	router.HandleFunc("PUT /${resources}/{uuid}", c.middleware.Use(c.Update))
	router.HandleFunc("DELETE /${resources}/{uuid}", c.middleware.Use(c.Delete))
}

func (c *${Resources}Controller) Create(w http.ResponseWriter, r *http.Request) {
	var dto domain.Create${Resource}DTO
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "${resource}.create.bad_request",
			Error:   err.Error(),
		})
		return
	}

	created, err := c.service.Create(dto)
	if err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "${resource}.create.failed",
			Error:   err.Error(),
		})
		return
	}

	api.WriteJSONResponse(w, http.StatusCreated, api.ResponseBody[domain.${Resource}]{
		Data:    *created,
		Message: "${resource}.create.success",
	})
}

func (c *${Resources}Controller) GetByUUID(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	entity, err := c.service.GetByUUID(uuid)
	if err != nil {
		api.WriteJSONResponse(w, http.StatusNotFound, api.ResponseBody[any]{
			Message: "${resource}.get.not_found",
			Error:   err.Error(),
		})
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.${Resource}]{
		Data:    *entity,
		Message: "${resource}.get.success",
	})
}

func (c *${Resources}Controller) Update(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	var dto domain.${Resource}UpdateDTO

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest,
			api.ResponseBody[any]{
				Message: "${resource}.update.bad_request",
				Error:   err.Error(),
			},
		)
		return
	}

	if err := c.service.Update(uuid, dto); err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError,
			api.ResponseBody[any]{
				Message: "${resource}.update.failed",
				Error:   err.Error(),
			},
		)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK,
		api.ResponseBody[domain.${Resource}]{
			Message: "${resource}.update.success",
		},
	)
}

func (c *${Resources}Controller) Delete(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if err := c.service.Delete(uuid); err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "${resource}.delete.failed",
			Error:   err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
`;

const factoryTemplate = `package factories

import (
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"
    "go-net-http-auth-base/internal/middlewares"

	"github.com/jackc/pgx/v5"
)

func ${Resources}Factory(conn *pgx.Conn) *controllers.${Resources}Controller {
	repo := repositories.New${Resources}PostgresRepository(conn)
	service := services.New${Resources}Service(repo)

	// TODO: Add middleware here if needed (e.g. AuthMiddleware)
	// You can see internal/factories/users_factory.go for an example of how to inject AuthMiddleware.
	// For now, we are passing nil which might cause a panic if the controller expects middleware.
	// You should either:
	// 1. Inject a real middleware (requires constructing AuthService etc.)
	// 2. Or update the controller to not need middleware if this resource is public.
	
	// Example of constructing a simple middleware or passing nil if handled inside:
	// middleware := middlewares.NewRateLimitMiddleware(...) 

	return controllers.New${Resources}Controller(service, nil) 
}
`;

const repositoryMockTemplate = \`package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type ${Resources}RepositoryMock struct {
	mock.Mock
}

var _ domain.${Resources}Repository = (*${Resources}RepositoryMock)(nil)

func (m *${Resources}RepositoryMock) FindByUUID(uuid string) (*domain.${Resource}, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.${Resource}), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *${Resources}RepositoryMock) Create(entity domain.${Resource}) (*domain.${Resource}, error) {
	args := m.Called(entity)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.${Resource}), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *${Resources}RepositoryMock) Update(entity domain.${Resource}) error {
	args := m.Called(entity)
	return args.Error(0)
}

func (m *${Resources}RepositoryMock) Delete(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}
\`;

const serviceMockTemplate = \`package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type ${Resources}ServiceMock struct {
	mock.Mock
}

var _ domain.${Resources}Service = (*${Resources}ServiceMock)(nil)

func (m *${Resources}ServiceMock) GetByUUID(uuid string) (*domain.${Resource}, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.${Resource}), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *${Resources}ServiceMock) Create(dto domain.Create${Resource}DTO) (*domain.${Resource}, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.${Resource}), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *${Resources}ServiceMock) Update(uuid string, dto domain.${Resource}UpdateDTO) error {
	args := m.Called(uuid, dto)
	return args.Error(0)
}

func (m *${Resources}ServiceMock) Delete(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}
\`;

const serviceTestTemplate = \`package services_test

import (
	"errors"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNew${Resources}Service(t *testing.T) {
	repo := new(mocks.${Resources}RepositoryMock)
	service := services.New${Resources}Service(repo)
	assert.NotNil(t, service)
}

func Test${Resources}Service_GetByUUID(t *testing.T) {
	repo := new(mocks.${Resources}RepositoryMock)
	service := services.New${Resources}Service(repo)

	t.Run("success", func(t *testing.T) {
		entity := &domain.${Resource}{UUID: "some-uuid"}
		repo.On("FindByUUID", "some-uuid").Return(entity, nil).Once()

		result, err := service.GetByUUID("some-uuid")

		assert.NoError(t, err)
		assert.Equal(t, entity, result)
		repo.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		repo.On("FindByUUID", "not-found-uuid").Return(nil, errors.New("not found")).Once()

		result, err := service.GetByUUID("not-found-uuid")

		assert.Error(t, err)
		assert.Nil(t, result)
		repo.AssertExpectations(t)
	})
}

func Test${Resources}Service_Create(t *testing.T) {
	repo := new(mocks.${Resources}RepositoryMock)
	service := services.New${Resources}Service(repo)

	t.Run("success", func(t *testing.T) {
		dto := domain.Create${Resource}DTO{}

		repo.On("Create", mock.AnythingOfType("domain.${Resource}")).Return(&domain.${Resource}{
			UUID:         "generated-uuid",
		}, nil).Once()

		entity, err := service.Create(dto)

		assert.NoError(t, err)
		assert.NotNil(t, entity)
		assert.Equal(t, "generated-uuid", entity.UUID)
		repo.AssertExpectations(t)
	})

	t.Run("repository create error", func(t *testing.T) {
		dto := domain.Create${Resource}DTO{}

		repo.On("Create", mock.AnythingOfType("domain.${Resource}")).Return(nil, errors.New("db error")).Once()

		entity, err := service.Create(dto)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.Nil(t, entity)
		repo.AssertExpectations(t)
	})
}

func Test${Resources}Service_Update(t *testing.T) {
	repo := new(mocks.${Resources}RepositoryMock)
	service := services.New${Resources}Service(repo)
	uuid := "some-uuid"
	originalEntity := &domain.${Resource}{
		UUID:  uuid,
	}

	t.Run("success", func(t *testing.T) {
		dto := domain.${Resource}UpdateDTO{}

		repo.On("FindByUUID", uuid).Return(originalEntity, nil).Once()
		repo.On("Update", mock.AnythingOfType("domain.${Resource}")).Return(nil).Once()

		err := service.Update(uuid, dto)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		dto := domain.${Resource}UpdateDTO{}
		repo.On("FindByUUID", "not-found").Return(nil, errors.New("not found")).Once()

		err := service.Update("not-found", dto)

		assert.Error(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("update fails", func(t *testing.T) {
		dto := domain.${Resource}UpdateDTO{}

		repo.On("FindByUUID", uuid).Return(originalEntity, nil).Once()
		repo.On("Update", mock.AnythingOfType("domain.${Resource}")).Return(errors.New("db error")).Once()

		err := service.Update(uuid, dto)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		repo.AssertExpectations(t)
	})
}

func Test${Resources}Service_Delete(t *testing.T) {
	repo := new(mocks.${Resources}RepositoryMock)
	service := services.New${Resources}Service(repo)
	uuid := "some-uuid"

	t.Run("success", func(t *testing.T) {
		repo.On("Delete", uuid).Return(nil).Once()

		err := service.Delete(uuid)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("delete fails", func(t *testing.T) {
		repo.On("Delete", uuid).Return(errors.New("db error")).Once()

		err := service.Delete(uuid)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		repo.AssertExpectations(t)
	})
}
\`;

const repositoryTestTemplate = \`package repositories_test

import (
	"context"
	"fmt"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup${Resources}RepoTest(t *testing.T) domain.${Resources}Repository {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	ctx := context.Background()
	repo := repositories.New${Resources}PostgresRepository(testDB)
	require.NotNil(t, repo)

	// Clean up table before tests
	// TODO: Ensure this table name matches your migration
	_, err := testDB.Exec(ctx, "TRUNCATE TABLE ${resources} RESTART IDENTITY CASCADE")
	if err != nil {
		t.Logf("Warning: Failed to truncate table ${resources}: %v", err)
	}

	return repo
}

func Test${Resources}PostgresRepository_Create(t *testing.T) {
	repo := setup${Resources}RepoTest(t)

	t.Run("success", func(t *testing.T) {
		entity := domain.${Resource}{
			// TODO: Add required fields
			UUID: uuid.New().String(),
		}

		created, err := repo.Create(entity)
		require.NoError(t, err)
		assert.NotEmpty(t, created.UUID)
	})
}

func Test${Resources}PostgresRepository_FindByUUID(t *testing.T) {
	repo := setup${Resources}RepoTest(t)

	t.Run("success", func(t *testing.T) {
		entity := domain.${Resource}{
			UUID: uuid.New().String(),
		}
		created, err := repo.Create(entity)
		require.NoError(t, err)

		found, err := repo.FindByUUID(created.UUID)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, found.UUID)
	})

	t.Run("not found", func(t *testing.T) {
		found, err := repo.FindByUUID(uuid.New().String())
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}

func Test${Resources}PostgresRepository_Update(t *testing.T) {
	repo := setup${Resources}RepoTest(t)

	t.Run("success", func(t *testing.T) {
		entity := domain.${Resource}{
			UUID: uuid.New().String(),
		}
		created, err := repo.Create(entity)
		require.NoError(t, err)

		// TODO: Change fields
		err = repo.Update(*created)
		require.NoError(t, err)
	})
}

func Test${Resources}PostgresRepository_Delete(t *testing.T) {
	repo := setup${Resources}RepoTest(t)

	t.Run("success", func(t *testing.T) {
		entity := domain.${Resource}{
			UUID: uuid.New().String(),
		}
		created, err := repo.Create(entity)
		require.NoError(t, err)

		err = repo.Delete(created.UUID)
		require.NoError(t, err)

		found, err := repo.FindByUUID(created.UUID)
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}
\`;

const controllerTestTemplate = \`package controllers_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTest${Resources}Controller() (*controllers.${Resources}Controller, *mocks.${Resources}ServiceMock, *mocks.AuthMiddlewareMock) {
	serviceMock := new(mocks.${Resources}ServiceMock)
	middlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.New${Resources}Controller(serviceMock, middlewareMock)

	return controller, serviceMock, middlewareMock
}

func Test${Resources}Controller_RegisterRoutes(t *testing.T) {
	t.Run("should register routes with auth middleware", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, authMiddleware := newTest${Resources}Controller()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(4)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 4)
	})
}

func Test${Resources}Controller_Create(t *testing.T) {
	entity := &domain.${Resource}{
		UUID:  "test-uuid",
	}
	dto := domain.Create${Resource}DTO{}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("Create", dto).Return(entity, nil)
		w, req := getControllerArgs(
			"POST",
			"/${resources}/",
			dto,
		)

		controller.Create(w, req)

		var response api.ResponseBody[domain.${Resource}]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, response.Data, *entity)
		serviceMock.AssertCalled(t, "Create", dto)
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("Create", dto).Return(nil, assert.AnError)

		w, req := getControllerArgs(
			"POST",
			"/${resources}/",
			dto,
		)

		controller.Create(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Create", dto)
	})

}

func Test${Resources}Controller_GetByUUID(t *testing.T) {
	uuid := "test-uuid"
	entity := &domain.${Resource}{
		UUID:  "test-uuid",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("GetByUUID", mock.Anything).Return(entity, nil)

		w, req := getControllerArgs("GET", "/${resources}/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetByUUID(w, req)

		var response api.ResponseBody[domain.${Resource}]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *entity, response.Data)
		serviceMock.AssertCalled(t, "GetByUUID", uuid)
	})

	t.Run("not found", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("GetByUUID", mock.Anything).Return(nil, assert.AnError)

		w, req := getControllerArgs("GET", "/${resources}/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetByUUID(w, req)

		var response api.ResponseBody[domain.${Resource}]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
		serviceMock.AssertCalled(t, "GetByUUID", uuid)

	})
}

func Test${Resources}Controller_Update(t *testing.T) {
	uuid := "test-uuid"
	dto := domain.${Resource}UpdateDTO{}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("Update", uuid, dto).Return(nil)

		w, req := getControllerArgs("PUT", "/${resources}/", dto)
		req.SetPathValue("uuid", uuid)

		controller.Update(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, dto)
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("Update", uuid, dto).Return(assert.AnError)

		w, req := getControllerArgs("PUT", "/${resources}/", dto)
		req.SetPathValue("uuid", uuid)

		controller.Update(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, dto)
	})

}

func Test${Resources}Controller_Delete(t *testing.T) {
	uuid := "test-uuid"

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("Delete", "test-uuid").Return(nil)

		w, req := getControllerArgs("DELETE", "/${resources}/", nil)
		req.SetPathValue("uuid", uuid)

		controller.Delete(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, _ := newTest${Resources}Controller()

		serviceMock.On("Delete", "test-uuid").Return(assert.AnError)

		w, req := getControllerArgs("DELETE", "/${resources}/", nil)
		req.SetPathValue("uuid", uuid)

		controller.Delete(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")

	})
}
\`;

// Files to create
const files = [
    {
        path: path.join(dirs.domain, `${resource}.go`),
        content: domainTemplate,
    },
    {
        path: path.join(dirs.repositories, `${resource}_repository.go`),
        content: repositoryTemplate,
    },
    {
        path: path.join(dirs.services, `${resource}_service.go`),
        content: serviceTemplate,
    },
    {
        path: path.join(dirs.controllers, `${resource}_controller.go`),
        content: controllerTemplate,
    },
    {
        path: path.join(dirs.factories, `${resource}_factory.go`),
        content: factoryTemplate,
    },
    {
        path: path.join(dirs.mocks, `${resource}_repository_mock.go`),
        content: repositoryMockTemplate,
    },
    {
        path: path.join(dirs.mocks, `${resource}_service_mock.go`),
        content: serviceMockTemplate,
    },
    {
        path: path.join(dirs.services, `${resource}_service_test.go`),
        content: serviceTestTemplate,
    },
    {
        path: path.join(dirs.controllers, `${resource}_controller_test.go`),
        content: controllerTestTemplate,
    },
    {
        path: path.join(dirs.repositories, `${resource}_repository_test.go`),
        content: repositoryTestTemplate,
    },
];

// Write files
files.forEach(file => {
    if (fs.existsSync(file.path)) {
        console.warn(`Skipping ${file.path}: File already exists.`);
    } else {
        fs.writeFileSync(file.path, file.content);
        console.log(`Created ${file.path}`);
    }
});

console.log("\nScaffolding complete!");
console.log("Remember to:");
console.log("1. Add the SQL migration.");
console.log("2. Generate SQLC queries.");
console.log(`3. Register the factory in cmd/main.go: factories.${Resources}Factory(conn).RegisterRoutes(mux)`);
