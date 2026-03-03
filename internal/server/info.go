package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/scd-systems/authpf-api/internal/api"
)

func info(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{"version": Version, "API": api.API_VERSION})
}
