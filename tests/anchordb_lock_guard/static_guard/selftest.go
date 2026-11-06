package main

// selftest.go proves the guard can fail. A guard that only ever reports success
// is worth nothing, and this one pattern-matches source shapes, so the shapes
// have to be verified rather than trusted.
//
// Fixtures go to a temp dir, each shaped like the real code: a package with a
// *sync.Mutex, a struct holding a *AnchorsDB, and methods that reach the map.
//
//	good    every accessor covered, one by lock and one through a lock holder
//	bad     goodCode with the lock dropped from an entry point
//	rotten  goodCode with the lock dropped from the holder of a helper
//	empty   no DB at all, which must be reported instead of passed quietly
//
// The two lock-dropping fixtures differ from goodCode in one statement each, so
// the only thing the guard can react to is the mutex it is meant to watch.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// storeCode owns the map and the primitives over it, like internal/authpf does.
// The map lives inside the struct and every method takes the struct's own mutex,
// which is the shape the real AnchorsDB has.
const storeCode = `package store

import "sync"

type AuthPFAnchor struct{ Username string }

type AnchorsDB struct {
	mu   sync.Mutex
	data map[string]*AuthPFAnchor
}

func (d *AnchorsDB) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.data)
}

func (d *AnchorsDB) Sweep() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.data {
		delete(d.data, k)
	}
}
`

// storeNoMutex is storeCode with the mutex field gone: the DB type no longer owns
// any protection, which is the one regression no caller-side ledger entry can see.
const storeNoMutex = `package store

type AuthPFAnchor struct{ Username string }

type AnchorsDB struct {
	data map[string]*AuthPFAnchor
}

func (d *AnchorsDB) Len() int { return len(d.data) }

func (d *AnchorsDB) Sweep() {
	for k := range d.data {
		delete(d.data, k)
	}
}
`

// storeDroppedLock is storeCode with the lock removed from Len only, which is the
// regression checkStore exists for: the method still compiles and still reads the
// map, and the callers cannot compensate for it.
const storeDroppedLock = `package store

import "sync"

type AuthPFAnchor struct{ Username string }

type AnchorsDB struct {
	mu   sync.Mutex
	data map[string]*AuthPFAnchor
}

func (d *AnchorsDB) Len() int { return len(d.data) }

func (d *AnchorsDB) Sweep() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.data {
		delete(d.data, k)
	}
}
`

// appCode is the correct miniature: an entry point holding the mutex, and a
// second one reaching the map through a helper that never locks itself.
const appCode = `package app

import (
	"sync"

	"fixture/internal/store"
)

var lock = &sync.Mutex{}

type App struct {
	db *store.AnchorsDB
}

func (a *App) RunSweep() {
	lock.Lock()
	defer lock.Unlock()
	a.sweepAll()
}

func (a *App) HandleRead() {
	lock.Lock()
	defer lock.Unlock()
	a.db.Len()
}
`

// helpersCode is the unlocked helper. Legal only while a lock holder calls it.
const helpersCode = `package app

func (a *App) sweepAll() {
	a.db.Sweep()
}
`

// noLockInHandleRead is appCode with the two lock lines removed from
// HandleRead. Everything else, including RunSweep, is untouched.
const noLockInHandleRead = `package app

import (
	"sync"

	"fixture/internal/store"
)

var lock = &sync.Mutex{}

type App struct {
	db *store.AnchorsDB
}

func (a *App) RunSweep() {
	lock.Lock()
	defer lock.Unlock()
	a.sweepAll()
}

func (a *App) HandleRead() {
	a.db.Len()
}
`

// noLockInRunSweep drops the lock from the helper's holder instead. This is the
// one a reader misses in a diff: sweepAll still compiles, still runs, only
// nobody holds the mutex while it deletes from the map.
const noLockInRunSweep = `package app

import (
	"sync"

	"fixture/internal/store"
)

var lock = &sync.Mutex{}

type App struct {
	db *store.AnchorsDB
}

func (a *App) RunSweep() {
	a.sweepAll()
}

func (a *App) HandleRead() {
	lock.Lock()
	defer lock.Unlock()
	a.db.Len()
}
`

// emptyCode parses fine and has no DB anywhere.
const emptyCode = `package app

func Nothing() int { return 1 }
`

// fixtureLedger describes the good fixture. It mirrors the shape of production
// without depending on it.
func fixtureLedger() ledgerSet {
	return ledgerSet{
		"internal/app/app.go::App.RunSweep": {
			Kind: locked, Why: "entry point, holds the mutex",
		},
		"internal/app/app.go::App.HandleRead": {
			Kind: locked, Why: "entry point, holds the mutex",
		},
		"internal/app/helpers.go::App.sweepAll": {
			Kind: helper, HeldBy: "internal/app/app.go::App.RunSweep",
			Why: "reaches the map while RunSweep holds the mutex",
		},
	}
}

func fixtureFiles(app string) map[string]string {
	return map[string]string{
		"internal/app/app.go":     app,
		"internal/app/helpers.go": helpersCode,
		"internal/store/store.go": storeCode,
	}
}

// storeFixture pairs good app code with a broken DB type, so the only thing these
// cases differ in is the protection inside AnchorsDB itself.
func storeFixture(store string) map[string]string {
	f := fixtureFiles(appCode)
	f["internal/store/store.go"] = store
	return f
}

type fixtureCase struct {
	name        string
	files       map[string]string
	led         ledgerSet
	wantFailed  bool
	wantContain string
}

// runSelftests returns a process exit code.
func runSelftests() int {
	root, err := os.MkdirTemp("", "anchordb-guard")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer func() { _ = os.RemoveAll(root) }()

	cases := []fixtureCase{
		{
			name:       "covered accessors pass",
			files:      fixtureFiles(appCode),
			led:        fixtureLedger(),
			wantFailed: false,
		},
		{
			name:        "an entry point that dropped its lock is a regression",
			files:       fixtureFiles(noLockInHandleRead),
			led:         fixtureLedger(),
			wantFailed:  true,
			wantContain: "App.HandleRead",
		},
		{
			name:        "a lock holder that dropped its lock is a regression",
			files:       fixtureFiles(noLockInRunSweep),
			led:         fixtureLedger(),
			wantFailed:  true,
			wantContain: "App.RunSweep",
		},
		{
			name:       "an accessor with no ledger entry is reported",
			files:      fixtureFiles(appCode),
			led:        ledgerSet{"internal/app/app.go::App.HandleRead": {Kind: locked, Why: "entry point"}},
			wantFailed: true,
			// RunSweep and sweepAll are undocumented here.
			wantContain: "no ledger entry",
		},
		{
			name:        "a code root with no DB at all is reported, not passed",
			files:       map[string]string{"internal/app/app.go": emptyCode},
			led:         fixtureLedger(),
			wantFailed:  true,
			wantContain: "no function reaches the DB map",
		},
		{
			// These two are the reason the guard reads the DB type and not only its
			// callers: a store that lost its mutex kills the daemon through an
			// extension, and no ledger entry is ever touched by that change.
			name:        "a DB type with no mutex of its own is a regression",
			files:       storeFixture(storeNoMutex),
			led:         fixtureLedger(),
			wantFailed:  true,
			wantContain: "declares no sync.Mutex",
		},
		{
			name:        "a DB method that dropped its lock is a regression",
			files:       storeFixture(storeDroppedLock),
			led:         fixtureLedger(),
			wantFailed:  true,
			wantContain: "AnchorsDB.Len",
		},
	}

	exit := 0
	for i, tc := range cases {
		dir := filepath.Join(root, fmt.Sprintf("case%d", i))
		if err := writeFixture(dir, tc.files); err != nil {
			fmt.Printf("  FAIL  %s: %v\n", tc.name, err)
			exit = 1
			continue
		}
		m, err := scan(dir, "internal")
		if err != nil {
			fmt.Printf("  FAIL  %s: %v\n", tc.name, err)
			exit = 1
			continue
		}
		res := m.check(tc.led)

		ok := res.failed() == tc.wantFailed
		if ok && tc.wantContain != "" {
			ok = findingsMention(res, tc.wantContain)
		}
		// A passing case must have validated something, or it passed by matching
		// nothing. RunSweep reaches the map only through sweepAll and has no DB
		// expression of its own, so two checked accessors is the correct count.
		if ok && !tc.wantFailed && res.Checked < 2 {
			ok = false
		}
		if ok {
			fmt.Printf("  pass  %s\n", tc.name)
			continue
		}
		fmt.Printf("  --- FAIL: %s\n", tc.name)
		fmt.Printf("        failed=%v want=%v accessors=%d\n", res.failed(), tc.wantFailed, len(res.Accessors))
		for _, f := range res.Findings {
			fmt.Printf("        finding: %s\n", f)
		}
		exit = 1
	}
	return exit
}

func writeFixture(dir string, files map[string]string) error {
	for rel, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func findingsMention(r *Result, want string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f.String(), want) {
			return true
		}
	}
	return false
}
