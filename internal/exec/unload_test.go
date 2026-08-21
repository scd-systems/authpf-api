package exec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/stretchr/testify/assert"
)

// writeRecordingStub creates a fake pfctl that appends its arguments to a
// log file, so tests can assert which commands were executed.
func writeRecordingStub(t *testing.T, dir string) (stub string, argLog string) {
	t.Helper()
	stub = filepath.Join(dir, "pfctl-stub")
	argLog = filepath.Join(dir, "args.log")
	script := "#!/bin/sh\necho \"$@\" >> " + argLog + "\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return stub, argLog
}

// UnloadAnchor must execute the flush commands even when the session DB is
// empty. A failed activation can be exactly that state, and is in the
// single-session case this test constructs: the anchor is loaded in pf but was
// never added to the DB. See TestFlushAnchor_GuardIsGlobalNotPerUser for why
// that is a case rather than the rule.
func TestUnloadAnchor_RunsWithEmptyDB(t *testing.T) {
	tmpDir := t.TempDir()
	stub, argLog := writeRecordingStub(t, tmpDir)

	cfg := createTestConfig(t, tmpDir)
	cfg.Defaults.PfctlBinary = stub
	cfg.AuthPF.FlushFilter = []string{"rules", "nat"}

	db := authpf.New() // empty DB, the half-activated state
	logger := zerolog.New(os.Stderr)
	e, err := New(logger, cfg, db)
	assert.NoError(t, err)

	anchor := &authpf.AuthPFAnchor{Username: "testuser", UserID: 1000, UserIP: "192.0.2.10"}
	assert.NoError(t, e.UnloadAnchor(anchor))

	out, err := os.ReadFile(argLog)
	assert.NoError(t, err, "pfctl stub must have been executed despite the empty DB")
	assert.Contains(t, string(out), "-a authpf/testuser(1000) -F rules")
	assert.Contains(t, string(out), "-a authpf/testuser(1000) -F nat")
}

// FlushAnchor keeps its existing behavior: with an empty DB it is a no-op.
func TestFlushAnchor_SkipsWithEmptyDB(t *testing.T) {
	tmpDir := t.TempDir()
	stub, argLog := writeRecordingStub(t, tmpDir)

	cfg := createTestConfig(t, tmpDir)
	cfg.Defaults.PfctlBinary = stub

	db := authpf.New()
	logger := zerolog.New(os.Stderr)
	e, err := New(logger, cfg, db)
	assert.NoError(t, err)

	anchor := &authpf.AuthPFAnchor{Username: "testuser", UserID: 1000, UserIP: "192.0.2.10"}
	assert.NoError(t, e.FlushAnchor(anchor))

	_, err = os.ReadFile(argLog)
	assert.True(t, os.IsNotExist(err), "no pfctl call expected with an empty DB")
}

// The FlushAnchor guard is a global emptiness check, not a per-user lookup, so
// the naive rollback (calling FlushAnchor from the activation failure path)
// misbehaves intermittently: it is a silent no-op only when the failing user is
// the only session. With any other session active it would have worked. That
// intermittency is why the DB-independent UnloadAnchor exists.
func TestFlushAnchor_GuardIsGlobalNotPerUser(t *testing.T) {
	tmpDir := t.TempDir()
	stub, argLog := writeRecordingStub(t, tmpDir)

	cfg := createTestConfig(t, tmpDir)
	cfg.Defaults.PfctlBinary = stub
	cfg.AuthPF.FlushFilter = []string{"rules"}

	// Another user's session is active; the failing user is absent from the DB.
	db := authpf.New()
	db.Add(&authpf.AuthPFAnchor{Username: "otheruser", UserID: 1001, UserIP: "192.0.2.20"})

	logger := zerolog.New(os.Stderr)
	e, err := New(logger, cfg, db)
	assert.NoError(t, err)

	absent := &authpf.AuthPFAnchor{Username: "testuser", UserID: 1000, UserIP: "192.0.2.10"}
	assert.NoError(t, e.FlushAnchor(absent))

	out, err := os.ReadFile(argLog)
	assert.NoError(t, err, "guard passes when any session exists, so pfctl runs")
	assert.Contains(t, string(out), "-a authpf/testuser(1000) -F rules",
		"FlushAnchor flushes a user absent from the DB whenever the DB is non-empty")
}
