package main

import (
	"context"
	"log"
	"net/http"

	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/postgres"
)

func main() {
	ctx := context.Background()
	conn := postgres.NewConnection(ctx)

	defer func() {
		if err := conn.Close(ctx); err != nil {
			log.Println("Error closing database connection:", err)
		}
	}()

	mux := http.NewServeMux()
	factories.UsersFactory(conn).RegisterRoutes(mux)

	log.Println("Server listening on port :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
