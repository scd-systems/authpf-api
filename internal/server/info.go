package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func info(c echo.Context) error {
	return c.JSON(http.StatusOK, GetVersionInfo())
}
