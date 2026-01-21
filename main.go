package main

import (
	"log"
	"os"

	"github.com/labstack/echo/v4"
)

func main() {
	// Bootstrap: Flags, Config, Validierung
	if err := bootstrap(); err != nil {
		log.Fatalf("%s", err.Error())
		os.Exit(1)
	}

	// Server: Setup and Start
	e := echo.New()
	if err := setupServer(e); err != nil {
		log.Fatalf("%s", err.Error())
		os.Exit(1)
	}
	startServerWithGracefulShutdown(e)
}
