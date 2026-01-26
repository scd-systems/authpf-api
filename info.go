package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func info(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{"version": Version, "API": API_VERSION})
}
