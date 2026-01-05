package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// login handles POST /login with username and password
func login(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid credentials"})
	}

	if err := config.checkUserAndPassword(req.Username, req.Password); err != nil {
		c.Logger().Errorf(err.Error())
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username or password"})
	}

	claims := &JWTClaims{
		Username: req.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 8)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "token generation failed"})
	}

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
