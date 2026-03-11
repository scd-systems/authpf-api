package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/pkg/config"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	config    *config.ConfigFile
	jwtSecret []byte
	logger    zerolog.Logger
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the login response with token
type LoginResponse struct {
	Token string `json:"token"`
}

func New(config *config.ConfigFile, logger zerolog.Logger, jwtSecret []byte) *Auth {
	return &Auth{config: config, logger: logger, jwtSecret: jwtSecret}
}

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
func (a *Auth) Login(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		c.Set("auth", "invalid request")
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		c.Set("auth", "no username or password")
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid credentials"})
	}

	if err := a.checkUserAndPassword(req.Username, req.Password); err != nil {
		c.Set("auth", fmt.Sprintf("Failed login request [user: %s]: %s", req.Username, err))
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username or password"})
	}

	// Parse JWT token timeout from config
	timeoutStr := a.config.Server.JwtTokenTimeout
	if a.config.Server.JwtTokenTimeout == "" {
		timeoutStr = "8h"
	}

	tokenDuration, err := parseJwtTokenTimeout(timeoutStr)
	if err != nil {
		a.logger.Error().Err(err).Msg(fmt.Sprintln("Invalid JWT token timeout configuration"))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "token generation failed"})
	}

	claims := &JWTClaims{
		Username: req.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "authpf-api",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(a.jwtSecret)
	if err != nil {
		a.logger.Error().Err(err).Str("user", req.Username).Msg("failed to generate JWT token")
		c.Set("auth", fmt.Sprintf("Token generation failed: %v", err))
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "token generation failed"})
	}
	c.Set("auth", fmt.Sprintf("User %s has been successfully authenticated", req.Username))
	return c.JSON(http.StatusOK, LoginResponse{Token: tokenString})
}

// JwtMiddleware validates JWT tokens
func (a *Auth) JwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get("Authorization")
		if auth == "" {
			a.logger.Debug().Str("ip", c.RealIP()).Msg("missing authorization header")
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "missing authorization header"})
		}

		if len(auth) < 7 || auth[:7] != "Bearer " {
			a.logger.Debug().Str("ip", c.RealIP()).Msg("invalid authorization format")
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid authorization format"})
		}

		tokenString := auth[7:]
		if len(tokenString) > 4096 {
			a.logger.Debug().Str("ip", c.RealIP()).Msg("token too long")
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token"})
		}

		claims := &JWTClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				msg := fmt.Sprintf("invalid signing algorithm: %v", token.Header["alg"])
				return nil, fmt.Errorf("%s", msg)
			}

			if token.Method.Alg() != "HS256" {
				msg := fmt.Sprintf("unsupported algorithm: %s", token.Method.Alg())
				return nil, fmt.Errorf("%s", msg)
			}

			return a.jwtSecret, nil
		})
		if err != nil {
			a.logger.Debug().Str("ip", c.RealIP()).Msgf("token parsing failed: %s", err)
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token"})
		}

		if !token.Valid {
			a.logger.Debug().Str("ip", c.RealIP()).Msg("token is not valid")
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid token"})
		}

		if err := a.validateJWTClaims(claims, c.RealIP()); err != nil {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": err.Error()})
		}

		c.Set("username", claims.Username)
		a.logger.Debug().Str("user", claims.Username).Str("ip", c.RealIP()).Msg("JWT token validated successfully")

		return next(c)
	}
}

// validateJWTClaims performs comprehensive validation of JWT claims
func (a *Auth) validateJWTClaims(claims *JWTClaims, clientIP string) error {
	if claims.Username == "" {
		a.logger.Debug().Str("ip", clientIP).Msg("empty username in JWT claims")
		return fmt.Errorf("invalid username in token")
	}

	if len(claims.Username) > 255 {
		a.logger.Debug().Str("ip", clientIP).Msg("username too long in JWT claims")
		return fmt.Errorf("invalid username in token")
	}

	if claims.ExpiresAt != nil {
		if claims.ExpiresAt.Before(time.Now()) {
			a.logger.Debug().Str("user", claims.Username).Str("ip", clientIP).Msg("token expired")
			return fmt.Errorf("token expired")
		}
	} else {
		a.logger.Debug().Str("ip", clientIP).Msg("missing expiration in JWT claims")
		return fmt.Errorf("invalid token: missing expiration")
	}

	if claims.IssuedAt != nil {
		if claims.IssuedAt.After(time.Now().Add(60 * time.Second)) {
			a.logger.Debug().Str("user", claims.Username).Str("ip", clientIP).Msg("token issued in the future")
			return fmt.Errorf("invalid token: issued in future")
		}
	}

	if claims.NotBefore != nil {
		if claims.NotBefore.After(time.Now().Add(60 * time.Second)) {
			a.logger.Debug().Str("user", claims.Username).Str("ip", clientIP).Msg("token not yet valid")
			return fmt.Errorf("token not yet valid")
		}
	}
	if claims.Issuer != "authpf-api" {
		a.logger.Debug().Str("user", claims.Username).Str("ip", clientIP).Msgf("wrong issuer claim: %s", claims.Issuer)
		return fmt.Errorf("invalid issuer claim")
	}

	if _, ok := a.config.Rbac.Users[claims.Username]; !ok {
		a.logger.Debug().Str("user", claims.Username).Str("ip", clientIP).Msg("user not found in configuration")
		return fmt.Errorf("user not found")
	}

	return nil
}

func (a *Auth) checkUserAndPassword(username string, clearTextPassword string) error {
	user, ok := a.config.Rbac.Users[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}

	// Use bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(clearTextPassword))
	if err == nil {
		return nil
	}

	// SHA256 fallback
	if len(user.Password) == 64 {
		userPassword, err := hex.DecodeString(user.Password)
		if err == nil {
			requestPassword := sha256.Sum256([]byte(clearTextPassword))
			if ret := subtle.ConstantTimeCompare(requestPassword[:], userPassword); ret == 1 {
				a.logger.Info().Msgf("User %q using legacy SHA256 password - please update to bcrypt", username)
				return nil
			}
		}
	}

	return fmt.Errorf("password not correct")
}
