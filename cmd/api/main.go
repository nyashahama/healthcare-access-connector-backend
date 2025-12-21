package main

import (
	"log"
	"os"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/app"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"

	"github.com/joho/godotenv"
)

func main() {
	// Load .env file if it exists (for local development)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load and validate configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize and start application
	application, err := app.New(cfg)
	if err != nil {
		log.Fatal("Failed to initialize application:", err)
	}

	// Start server with graceful shutdown
	if err := application.Run(); err != nil {
		log.Fatal("Application failed:", err)
	}

	os.Exit(0)
}
