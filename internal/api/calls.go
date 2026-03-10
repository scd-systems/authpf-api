package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/errors"
	"github.com/scd-systems/authpf-api/internal/exec"
)

// Call Exec activate anchor
func (h *Handler) CallExecActivateAnchor(c echo.Context, r *authpf.AuthPFAnchor) *errors.APIError {
	e, err := exec.New(h.logger, h.config, h.db)
	if err != nil {
		h.logger.Debug().Str("user", c.Get("username").(string)).Msgf("Unable to create new Exec: %v", err.Error())
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        err.Error(),
			Details:        "unable to create an Exec",
		}
	}

	result := e.LoadAuthPFAnchor(r)
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
	result = e.AddIPToPfTable(r)
	msg = fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	h.logger.Trace().Str("user", c.Get("username").(string)).Msg(msg)

	if result.ExitCode != 0 {
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
	e, err := exec.New(h.logger, h.config, h.db)
	if err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        err.Error(),
			Details:        "unable to create an Exec",
		}
	}

	// Remove user_ip from pf table
	result := e.RemoveIPFromPfTable(r)

	if result != nil {
		// Log only possible of pf table is defined (pf table required in RemoveIPFromPfTable)
		msg := fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
		h.logger.Trace().Str("user", r.Username).Msg(msg)

		if result.ExitCode != 0 {
			h.logger.Warn().Str("user", r.Username).Msgf("failed to remove IP from pf table: %s", result.Stderr)
		}
	}

	// Remove anchor
	multiResult := e.UnloadAuthPFAnchor(r)
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		h.logger.Debug().Str("user", r.Username).Msg(msg)
	}
	if multiResult.Error != nil {
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
	e, err := exec.New(h.logger, h.config, h.db)
	if err != nil {
		h.logger.Debug().Str("user", r.Username).Msgf("Unable to create new Exec: %v", err.Error())
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        err.Error(),
			Details:        "unable to create an Exec",
		}
	}

	// Remove all user_ip's from pf tables
	e.RemoveAllIPsFromPfTable()

	multiResult := e.UnloadAllAuthPFAnchors()

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		h.logger.Debug().Str("user", r.Username).Msg(msg)
	}
	if multiResult.Error != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "failed to unload anchor rules",
			Details:        "check server logs",
		}
	}
	return nil
}
