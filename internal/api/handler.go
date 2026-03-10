package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/exec"
	"github.com/scd-systems/authpf-api/pkg/config"
)

const API_VERSION = "1.2"

type Handler struct {
	db     *authpf.AnchorsDB
	lock   *sync.Mutex
	logger zerolog.Logger
	config *config.ConfigFile
	exec   *exec.Exec
}

// AuthPFAnchorResponse represents all rules with server time for client-side calculations
type AuthPFAnchorResponse struct {
	Anchors    authpf.AnchorsDB `json:"anchors"`
	ServerTime time.Time        `json:"server_time"`
}

func New(db *authpf.AnchorsDB, lock *sync.Mutex, logger zerolog.Logger, config *config.ConfigFile) (*Handler, error) {
	e, err := exec.New(logger, config, db)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to initialize exec")
		return nil, fmt.Errorf("failed to initialize exec: %v", err.Error())
	}

	return &Handler{db: db, lock: lock, logger: logger, config: config, exec: e}, nil
}

func (h *Handler) AddToDB(r *authpf.AuthPFAnchor) error {
	if h.db.IsActivated(r.Username) {
		return fmt.Errorf("anchor for user: %s already activated", r.Username)
	}
	h.db.Add(r)
	return nil
}

func (h *Handler) HandleGetLogin(c echo.Context) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	return c.JSON(http.StatusOK, "valid")
}

// HandlerFunc for activate Anchors (POST /api/v1/authpf/activate)
func (h *Handler) HandlePostActivate(c echo.Context) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	anchor := &authpf.AuthPFAnchor{}

	// Check Username & JSON Payload
	if err := h.CheckSessionUsername(c); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	if err := h.CheckJSONPayload(c, anchor); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Check Permissions
	if err := h.CheckSessionUserPermission(c, config.SESSION_REGISTER); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Check UserIP from Requester
	if err := h.CheckSessionUserIP(c); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Check if user/anchor already activated
	check, err := h.CheckAnchorIsActivated(c)
	if check {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	anchor, err = h.GetAnchorFromContext(c)
	if err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Exec
	if err := h.CallExecActivateAnchor(c, anchor); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Store status into DB
	if err := h.AddToDB(anchor); err != nil {
		msg := "Unable to store user into Session DB, rollback anchor activation"
		c.Set("authpf", msg)
		h.logger.Info().Msg(msg)

		if err := h.CallExecDeactivateAnchor(anchor); err != nil {
			c.Set("authpf", err.Message)
			h.logger.Info().Msgf("failed to rollback anchor deactivation: %s", err.Message)
			h.logger.Debug().Msgf("error in anchor deactivation: %s", err.Details)
			return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
		}

		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	c.Set("authpf", fmt.Sprintf("Activated authpf anchor: user=%s, user_ip=%s, user_id=%d, timeout=%s, expire_at=%s", anchor.Username, anchor.UserIP, anchor.UserID, anchor.Timeout, anchor.ExpiresAt))
	return c.JSON(http.StatusCreated, echo.Map{"status": "activated", "user": anchor.Username, "message": "authpf anchor is being loaded"})
}

func (h *Handler) HandleGetActivate(c echo.Context) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Check Username & JSON Payload
	if err := h.CheckSessionUsername(c); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Check Permissions
	if err := h.CheckSessionUserPermission(c, config.SESSION_VIEW); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "rejected", "message": err.Details})
	}

	reqUser, err := h.resolveAnchorUsername(c)
	if err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	response := &AuthPFAnchorResponse{
		Anchors:    map[string]*authpf.AuthPFAnchor{reqUser: (*h.db)[reqUser]},
		ServerTime: time.Now().UTC(),
	}
	return c.JSON(http.StatusOK, response)
}

func (h *Handler) HandleGetAllActivePFAnchors(c echo.Context) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Check Username & JSON Payload
	if err := h.CheckSessionUsername(c); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Set Flag to define required permission in CheckSessionUserPermission()
	c.Set("Flag", "view-all")

	// Check Permissions
	if err := h.CheckSessionUserPermission(c, config.SESSION_VIEW); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "rejected", "message": err.Details})
	}

	response := &AuthPFAnchorResponse{
		Anchors:    *h.db,
		ServerTime: time.Now().UTC(),
	}
	return c.JSON(http.StatusOK, response)

}

func (h *Handler) HandleDeleteDeactivate(c echo.Context) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	anchor := &authpf.AuthPFAnchor{}

	// Check Username & JSON Payload
	if err := h.CheckSessionUsername(c); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	if err := h.CheckJSONPayload(c, anchor); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Check Permissions
	if err := h.CheckSessionUserPermission(c, config.SESSION_UNREGISTER); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	anchor, err := h.GetAnchorFromContext(c)
	if err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Check if user/anchor already activated
	check, _ := h.CheckAnchorIsActivated(c)
	if !check {
		msg := "User anchor not active"
		c.Set("authpf", fmt.Sprintf("Deactivated authpf anchor: user=%s, user_ip=%s, user_id=%d", anchor.Username, anchor.UserIP, anchor.UserID))
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "user": anchor.Username, "message": msg})
	}

	// Exec
	if err := h.CallExecDeactivateAnchor(anchor); err != nil {
		c.Set("authpf", err.Details)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Message})
	}

	// Store status into DB
	if err := h.db.Remove(anchor.Username); err != nil {
		msg := "Unable to store user into Session DB"
		c.Set("authpf", msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}
	msg := "authpf anchor is being unloaded"
	c.Set("authpf", fmt.Sprintf("Deactivated authpf anchor: user=%s, user_ip=%s, user_id=%d", anchor.Username, anchor.UserIP, anchor.UserID))
	return c.JSON(http.StatusAccepted, echo.Map{"status": "queued", "user": anchor.Username, "message": msg})
}

func (h *Handler) HandleDeleteAllDeactivate(c echo.Context) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Check Username
	if err := h.CheckSessionUsername(c); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	c.Set("Flag", "delete-all")
	// Check Permissions
	if err := h.CheckSessionUserPermission(c, config.SESSION_UNREGISTER); err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	anchor, err := h.GetAnchorFromContext(c)
	if err != nil {
		c.Set("authpf", err.Message)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Details})
	}

	// Exec
	if err := h.CallExecDeactivateAllAnchors(anchor); err != nil {
		c.Set("authpf", err.Details)
		return c.JSON(err.HttpStatusCode, echo.Map{"status": "failed", "message": err.Message})
	}
	h.flushDB()
	return c.JSON(http.StatusOK, echo.Map{"status": "cleared"})
}

func (h *Handler) flushDB() {
	h.db.Flush()
	h.logger.Debug().Msg("Flushing anchors succeed")
}
