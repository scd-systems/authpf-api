package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
)

// A failed pf table add must unload the anchor that step 1 loaded. The stub
// pfctl succeeds for every command except table ops (-t), reproducing the
// half-activated state, and records every invocation for assertions.
func TestCallExecActivateAnchor_RollsBackAnchorOnTableAddFailure(t *testing.T) {
	tmpDir := t.TempDir()
	argLog := filepath.Join(tmpDir, "args.log")
	stub := filepath.Join(tmpDir, "pfctl-stub")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> " + argLog + "\n" +
		"case \" $* \" in *\" -t \"*) exit 1;; esac\n" +
		"exit 0\n"
	assert.NoError(t, os.WriteFile(stub, []byte(script), 0755))

	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: stub},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"rules", "nat"},
			PfTable:             "authpf_users",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {Role: "user", UserID: 1000},
			},
		},
	}

	db := authpf.New()
	logger := zerolog.New(os.Stderr)
	h, err := New(db, &sync.Mutex{}, logger, cfg)
	assert.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	c := e.NewContext(req, httptest.NewRecorder())
	c.Set("username", "testuser")

	anchor := &authpf.AuthPFAnchor{Username: "testuser", UserID: 1000, UserIP: "192.0.2.10"}
	apiErr := h.CallExecActivateAnchor(c, anchor)

	assert.NotNil(t, apiErr, "table add failure must surface as an APIError")
	assert.Equal(t, http.StatusInternalServerError, apiErr.HttpStatusCode)

	out, err := os.ReadFile(argLog)
	assert.NoError(t, err)
	calls := strings.TrimSpace(string(out))

	// Step 1 loaded the anchor, step 2 failed on -t. Without the rollback the
	// log ends there and the anchor stays loaded with no DB entry to find it.
	assert.Contains(t, calls, "-f", "step 1 must have loaded the anchor")
	assert.Contains(t, calls, "-t authpf_users -T add 192.0.2.10", "step 2 must have been attempted")
	assert.Contains(t, calls, "-a authpf/testuser(1000) -F rules", "anchor must be unloaded after the failure")
	assert.Contains(t, calls, "-a authpf/testuser(1000) -F nat", "anchor must be unloaded after the failure")
}
