package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// parseJwtTokenTimeout parses the JWT token timeout string and returns a time.Duration
// Supported formats: "30m", "1h", "2d" (maximal 30d)
// Returns error if format is invalid or exceeds 30 days
func parseJwtTokenTimeout(timeout string) (time.Duration, error) {
	if timeout == "" {
		return 0, fmt.Errorf("timeout cannot be empty")
	}

	// Regex pattern to match number + unit (m, h, d)
	pattern := `^(\d+)([mhd])$`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(strings.TrimSpace(timeout))

	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid timeout format: %s (expected format: 30m, 1h, or 2d)", timeout)
	}

	value, _ := strconv.Atoi(matches[1])
	unit := matches[2]

	var duration time.Duration
	switch unit {
	case "m":
		duration = time.Duration(value) * time.Minute
	case "h":
		duration = time.Duration(value) * time.Hour
	case "d":
		duration = time.Duration(value) * 24 * time.Hour
	}

	// Check if duration exceeds 30 days
	maxDuration := 30 * 24 * time.Hour
	if duration > maxDuration {
		return 0, fmt.Errorf("timeout exceeds maximum allowed duration of 30 days: %s", timeout)
	}

	return duration, nil
}

// login handles POST /login with username and password
func login(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		c.Set("auth", "invalid request")
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		c.Set("auth", "no username or password")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid credentials"})
	}

	if err := config.checkUserAndPassword(req.Username, req.Password); err != nil {
		c.Set("auth", fmt.Sprintf("Failed login request [user: %s]: %s", req.Username, err))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username or password"})
	}

	// Parse JWT token timeout from config
	timeoutStr := fmt.Sprintf("%s", config.Server.JwtTokenTimeout)
	if config.Server.JwtTokenTimeout == "" {
		timeoutStr = "8h"
	}

	tokenDuration, err := parseJwtTokenTimeout(timeoutStr)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Invalid JWT token timeout configuration: %v", err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "token generation failed"})
	}

	claims := &JWTClaims{
		Username: req.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.Set("auth", fmt.Sprintf("Token generation failed: %v", err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "token generation failed"})
	}
	c.Set("auth", fmt.Sprintf("User %s has been successfully authenticated", req.Username))
	return c.JSON(http.StatusOK, LoginResponse{Token: tokenString})
}

// jwtMiddleware validates JWT tokens
func jwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get("Authorization")
		if auth == "" {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "missing authorization header"})
		}

		if len(auth) < 7 || auth[:7] != "Bearer " {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid authorization format"})
		}

		tokenString := auth[7:]
		claims := &JWTClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token"})
		}

		c.Set("username", claims.Username)
		return next(c)
	}
}
