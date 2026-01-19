package main

import (
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func main() {
	// Bootstrap: Flags, Config, Validierung
	if err := bootstrap(); err != nil {
		log.Errorf("%s", err.Error())
		os.Exit(1)
	}

	// Server: Setup and Start
	e := echo.New()
	if err := setupServer(e); err != nil {
		log.Errorf("%s", err.Error())
		os.Exit(1)
	}

	startServerWithGracefulShutdown(e)
	// if err := startServer(e); err != nil {
	// 	log.Errorf("%s", err.Error())
	// 	os.Exit(1)
	// }
}
