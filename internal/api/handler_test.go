package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
)

func TestConcurrentActivateIsAtomic(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "pfctl")
	script := "#!/bin/sh\necho call >> \"" + stub + ".calls\"\nsleep 0.02\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := activationTestConfig(t.TempDir(), stub)

	db := authpf.New()
	h, err := New(db, &sync.Mutex{}, zerolog.New(io.Discard), cfg)
	if err != nil {
		t.Fatal(err)
	}

	statuses := make(chan int, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			c.Set("username", "alice")
			_ = h.HandlePostActivate(c)
			statuses <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)

	created, duplicate := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusAlreadyReported:
			duplicate++
		default:
			t.Errorf("activation returned HTTP %d", status)
		}
	}
	if created != 1 || duplicate != 1 || db.Len() != 1 {
		t.Fatalf("got %d created, %d duplicate, DB size %d; want 1, 1, 1", created, duplicate, db.Len())
	}

	calls, err := os.ReadFile(stub + ".calls")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(string(calls))); got != 1 {
		t.Fatalf("pfctl called %d times, want once for the successful activation", got)
	}
}

func TestReadOnlyDBAccessDoesNotWaitForPfctl(t *testing.T) {
	tmpDir := t.TempDir()
	stub := filepath.Join(tmpDir, "pfctl")
	started := filepath.Join(tmpDir, "pfctl-started")
	script := "#!/bin/sh\ntouch \"" + started + "\"\nsleep 0.5\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := activationTestConfig(tmpDir, stub)
	db := authpf.New()
	outerLock := &sync.Mutex{}
	h, err := New(db, outerLock, zerolog.New(io.Discard), cfg)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		outerLock.Lock()
		defer outerLock.Unlock()
		_ = h.exec.LoadAuthPFAnchor(&authpf.AuthPFAnchor{Username: "alice", UserID: 1000})
	}()

	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pfctl stub did not start")
		}
		time.Sleep(time.Millisecond)
	}

	readDone := make(chan struct{})
	go func() {
		_ = db.Len()
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("DB read waited behind delayed pfctl; it must not take the outer transaction lock")
	}
	<-done
}

func activationTestConfig(tmpDir, pfctl string) *config.ConfigFile {
	return &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: pfctl},
		AuthPF: config.ConfigFileAuthPF{
			Timeout:             "1h",
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"rules", "nat"},
		},
		Rbac: config.ConfigFileRbac{
			Roles: map[string]config.ConfigFileRbacRoles{
				"user": {Permissions: []string{config.RBAC_ACTIVATE_OWN_RULE}},
			},
			Users: map[string]config.ConfigFileRbacUsers{
				"alice": {Role: "user", UserID: 1000},
			},
		},
	}
}

func TestAuthPFGetEndpointsKeepJSONShape(t *testing.T) {
	db := authpf.New()
	db.Add(&authpf.AuthPFAnchor{
		Username:  "alice",
		Timeout:   "1h",
		UserIP:    "192.0.2.10",
		UserID:    1000,
		ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Roles: map[string]config.ConfigFileRbacRoles{
				"user": {Permissions: []string{
					config.RBAC_GET_STATUS_OWN_RULE,
					config.RBAC_GET_STATUS_OTHER_RULE,
				}},
			},
			Users: map[string]config.ConfigFileRbacUsers{"alice": {Role: "user"}},
		},
	}
	h, err := New(db, &sync.Mutex{}, zerolog.New(io.Discard), cfg)
	if err != nil {
		t.Fatal(err)
	}

	responses := make([]map[string]json.RawMessage, 0, 2)
	for _, endpoint := range []struct {
		name string
		h    func(*echo.Context) error
	}{
		{name: "single", h: h.HandleGetActivate},
		{name: "all", h: h.HandleGetAllActivePFAnchors},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			c.Set("username", "alice")
			if err := endpoint.h(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}

			var body map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 2 || body["anchors"] == nil || body["server_time"] == nil {
				t.Fatalf("response keys = %v, want anchors and server_time", body)
			}
			var anchors map[string]json.RawMessage
			if err := json.Unmarshal(body["anchors"], &anchors); err != nil {
				t.Fatal(err)
			}
			if len(anchors) != 1 || anchors["alice"] == nil {
				t.Fatalf("anchors = %s, want alice entry", body["anchors"])
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(anchors["alice"], &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"username", "timeout", "user_ip", "user_id", "expire_at"} {
				if fields[key] == nil {
					t.Errorf("anchor JSON missing %q: %s", key, anchors["alice"])
				}
			}
			responses = append(responses, anchors)
		})
	}

	if string(responses[0]["alice"]) != string(responses[1]["alice"]) {
		t.Fatalf("single and all endpoints returned different anchor JSON: %s != %s", responses[0]["alice"], responses[1]["alice"])
	}
}
