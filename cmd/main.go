package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	factories.AuthFactory(conn).RegisterRoutes(mux)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		log.Println("Server listening on port :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited gracefully")
}
