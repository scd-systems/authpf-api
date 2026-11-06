package main

// main.go runs the static half of the anchorsDB locking guard.
//
//	go run ./tests/anchordb_lock_guard/static_guard -dir .        # check the repo
//	go run ./tests/anchordb_lock_guard/static_guard -selftest     # prove it bites
//	go run ./tests/anchordb_lock_guard/static_guard -dir . -v     # full inventory
//
// It is a main package rather than a test so that it can also run with plain
// `go run` outside the module, and so CI can call it before any test binary has
// to be built. It stays in tests/ inside the module, so go vet and the linter
// still cover it.
//
// Exit codes: 0 clean, 1 findings, 2 the guard could not do its job.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	dir := flag.String("dir", ".", "code root to check, usually the repository root")
	runSelftest := flag.Bool("selftest", false, "run the guard against generated fixtures")
	verbose := flag.Bool("v", false, "list every DB accessor, not only the findings")
	flag.Parse()

	if *runSelftest {
		os.Exit(runSelftests())
	}

	root, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anchordb lock guard: %v\n", err)
		os.Exit(2)
	}

	m, err := scan(root, "internal", "pkg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "anchordb lock guard: %v\n", err)
		os.Exit(2)
	}
	res := m.check(production)

	fmt.Printf("anchorsDB locking: %d functions reach the map, %d documented in the ledger\n",
		len(res.Accessors), res.Checked)
	if *verbose {
		for _, fn := range res.Accessors {
			state := "unlocked"
			if fn.HasLock {
				state = "locks   "
			}
			fmt.Printf("  [%s] %-58s %s\n", state, fn.Key(), strings.Join(fn.Accesses, "; "))
			if len(fn.Path) > 1 {
				fmt.Printf("          reached via %s\n", strings.Join(fn.Path, " -> "))
			}
		}
	}
	if !res.failed() {
		fmt.Println("  every accessor matches its ledger entry")
		return
	}
	for _, f := range res.Findings {
		fmt.Printf("  %s\n", f)
	}
	regressions := len(res.regressions())
	fmt.Printf("anchordb lock guard: %d regression(s), %d drift(s)\n",
		regressions, len(res.Findings)-regressions)
	os.Exit(1)
}
