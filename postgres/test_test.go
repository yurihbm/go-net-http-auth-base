package postgres_test

import (
	"context"
	"net/url"
	"os"
	"testing"

	"go-net-http-auth-base/postgres"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestNewTestPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("error - port conflict leaves no container behind", func(t *testing.T) {
		ctx := context.Background()
		t.Setenv("DATABASE_URL", "")

		_, cleanup, err := postgres.NewTestPool(ctx)
		require.NoError(t, err)
		defer cleanup()

		dbURL, err := url.Parse(os.Getenv("DATABASE_URL"))
		require.NoError(t, err)
		port := dbURL.Port()
		t.Setenv("TEST_DB_PORT_START", port)
		t.Setenv("TEST_DB_PORT_END", port)

		_, _, err = postgres.NewTestPool(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no available postgres test port")

		assert.Len(t, testContainersBoundTo(t, ctx, port), 1)
	})
}

func testContainersBoundTo(t *testing.T, ctx context.Context, hostPort string) []string {
	t.Helper()

	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	defer func() { _ = docker.Close() }()

	list, err := docker.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: client.Filters{}.Add("label", "org.testcontainers=true"),
	})
	require.NoError(t, err)

	var bound []string
	for _, summary := range list.Items {
		inspect, err := docker.ContainerInspect(ctx, summary.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		for _, bindings := range inspect.Container.HostConfig.PortBindings {
			for _, binding := range bindings {
				if binding.HostPort == hostPort {
					bound = append(bound, summary.ID)
				}
			}
		}
	}
	return bound
}
