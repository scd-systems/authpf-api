package main

// guard_test.go wires the guard into `go test ./...`, which is what makes CI
// enforce it without any pipeline change. The shell script stays the human entry
// point; this is the automatic one.

import (
	"path/filepath"
	"testing"
)

// TestLedgerMatchesRepo is the check that fails a pull request which changed the
// locking discipline. It is the same comparison `go run . -dir .` performs.
func TestLedgerMatchesRepo(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	m, err := scan(root, "internal", "pkg")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	res := m.check(production)

	for _, f := range res.Findings {
		t.Error(f)
	}
	if res.failed() {
		t.Fatalf("anchorsDB locking drifted: %s. If the change was intentional, update "+
			"ledger.go in this commit and explain why.", res.summary())
	}
	t.Logf("%d functions reach the DB map, all documented", len(res.Accessors))
}

// TestGuardDetectsItsFixtures keeps the selftest inside the normal test run. A
// guard that stopped being able to detect a missing lock would otherwise keep
// reporting success forever, unnoticed.
func TestGuardDetectsItsFixtures(t *testing.T) {
	if code := runSelftests(); code != 0 {
		t.Fatalf("guard selftest failed with exit code %d, see output above", code)
	}
}
