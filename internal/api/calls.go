package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/errors"
)

// Call Exec activate anchor
func (h *Handler) CallExecActivateAnchor(c *echo.Context, r *authpf.AuthPFAnchor) *errors.APIError {
	result := h.exec.LoadAuthPFAnchor(r)
	msg := fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	h.logger.Trace().Str("user", c.Get("username").(string)).Msg(msg)

	if result.ExitCode != 0 {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     result.ExitCode,
			Message:        "failed to load anchor rules",
			Details:        result.Stderr,
		}
	}

	// Add user_ip to pf table
	result = h.exec.AddIPToPfTable(r)

	msg = fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	h.logger.Trace().Str("user", c.Get("username").(string)).Msg(msg)

	if result.ExitCode != 0 {
		// Roll back the anchor from step 1: it is loaded in pf but not yet
		// in the session DB, so no cleanup path would ever find it. The IP
		// was never added to the table, so there is nothing to remove there.
		if err := h.exec.UnloadAnchor(r); err != nil {
			h.logger.Error().Err(err).Str("user", r.Username).Msgf(
				"rollback failed, anchor is still loaded and untracked, remove it with: pfctl -a %s/%s(%d) -F all",
				h.config.AuthPF.AnchorName, r.Username, r.UserID)
		}
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     result.ExitCode,
			Message:        "failed to add IP to pf table",
			Details:        result.Stderr,
		}
	}
	return nil
}

func (h *Handler) CallExecDeactivateAnchor(r *authpf.AuthPFAnchor) *errors.APIError {
	// Remove user_ip from pf table
	if err := h.exec.FlushPFTable(r); err != nil {
		h.logger.Error().Err(err).Str("user", r.Username).Msgf("failed to remove IP from pf table")
	}

	// remove anchor
	if err := h.exec.FlushAnchor(r); err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "failed to unload anchor rules",
			Details:        "check server logs",
		}
	}

	return nil
}

func (h *Handler) CallExecDeactivateAllAnchors(r *authpf.AuthPFAnchor) *errors.APIError {

	// Remove all user_ip's from pf tables
	result := h.exec.FlushAllPFTables()
	if result != nil {
		if result.ExitCode != 0 {
			h.logger.Warn().Str("user", r.Username).Msgf("failed to remove all IP's from pf table: %s", result.Stderr)
		}
	}

	if err := h.exec.FlushAllAnchors(r.Username); err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "failed to unload anchor rules",
			Details:        "check server logs",
		}
	}

	h.db.Flush()
	return nil
}
