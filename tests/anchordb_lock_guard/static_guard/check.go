package main

// check.go compares what the scan found against the ledger and turns every
// mismatch into one sentence a stranger can act on.
//
// The interesting case is the one this guard exists for: a function that touched
// the DB under the mutex and no longer does. That is reported as a regression,
// not as a diff. Everything else is drift - the code moved, a helper appeared,
// the ledger got stale - and is reported as such, because a guard that screams
// about both teaches people to ignore it.

import (
	"fmt"
	"sort"
	"strings"
)

// Finding is one mismatch between the scan and the ledger.
type Finding struct {
	Severity string // "regression" is unsafe code, "drift" needs a ledger update
	Subject  string
	Message  string
}

func (f Finding) String() string { return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Subject, f.Message) }

// Result is the outcome of one guarded scan.
type Result struct {
	Accessors []*Func
	Checked   int
	Findings  []Finding
}

// failed reports whether anything needs attention. Every finding does.
func (r *Result) failed() bool { return len(r.Findings) > 0 }

// summary is the one-line verdict used by both the CLI and the test.
func (r *Result) summary() string {
	n := len(r.regressions())
	return fmt.Sprintf("%d regression(s), %d drift(s)", n, len(r.Findings)-n)
}

func (r *Result) regressions() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == "regression" {
			out = append(out, f)
		}
	}
	return out
}

// check is the whole comparison.
func (m *Model) check(led ledgerSet) *Result {
	res := &Result{}

	res.Accessors = m.funcs
	if len(m.funcs) == 0 {
		res.Findings = append(res.Findings, Finding{
			Severity: "regression",
			Subject:  "scan",
			Message: "no function reaches the DB map at all, so this guard would pass by " +
				"accident: the scan found no *sync.Mutex and no *authpf.AnchorsDB field, " +
				"which means the code stopped matching the pattern the guard understands",
		})
		return res
	}

	seen := map[string]bool{}
	for _, fn := range m.funcs {
		seen[fn.Key()] = true
		// Methods over the DB type are covered by checkStore, which requires the
		// mutex and cannot be opted out of, so they are not "undocumented".
		if m.storeType != "" && fn.Recv == m.storeType {
			continue
		}
		e, ok := led[fn.Key()]
		if !ok {
			res.Findings = append(res.Findings, Finding{
				Severity: "drift",
				Subject:  fn.String(),
				Message: fmt.Sprintf("touches the DB map (%s) but is in no ledger entry, so nobody has "+
					"decided how it is protected. Add it to ledger.go as locked, helper with a "+
					"HeldBy, or startup with a reason.", strings.Join(fn.Accesses, ", ")),
			})
			continue
		}
		res.Checked++
		res.Findings = append(res.Findings, m.checkEntry(fn, e, led)...)
	}

	// A ledger entry whose function vanished is as much a finding as a new one:
	// the guarantee it documented is gone with it.
	for key, e := range led {
		if e.Kind == owned || seen[key] {
			continue
		}
		fn, exists := m.byKey[key]
		if !exists {
			res.Findings = append(res.Findings, Finding{
				Severity: "drift",
				Subject:  key,
				Message:  fmt.Sprintf("is documented as %s but no longer exists in the scanned code", e.Kind),
			})
			continue
		}
		// A documented holder may have no DB expression of its own and reach the
		// map only through a helper; Scheduler.Run does exactly that. What still
		// has to be true is that it holds the lock.
		if e.Kind == locked && !fn.HasLock {
			res.Findings = append(res.Findings, Finding{
				Severity: "regression",
				Subject:  fn.String(),
				Message:  fmt.Sprintf("is documented as %s but no longer takes and releases the mutex", e),
			})
		}
	}

	res.Findings = append(res.Findings, m.checkOwned()...)
	res.Findings = append(res.Findings, m.checkStore(led)...)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Severity != res.Findings[j].Severity {
			return res.Findings[i].Severity < res.Findings[j].Severity
		}
		return res.Findings[i].Subject < res.Findings[j].Subject
	})
	return res
}

// checkEntry judges one function against its ledger entry.
func (m *Model) checkEntry(fn *Func, e entry, led ledgerSet) []Finding {
	switch e.Kind {
	case locked:
		if !fn.HasLock {
			return []Finding{{
				Severity: "regression",
				Subject:  fn.String(),
				Message: fmt.Sprintf("LOST ITS LOCK. Documented as %s, but the body no longer takes "+
					"the shared mutex and releases it. Reads and writes of the anchorsDB map can now "+
					"collide with the scheduler tick, and the Go runtime answers with a fatal error "+
					"that takes the whole process down, not a failed request.", e),
			}}
		}
		return nil

	case helper:
		var out []Finding
		if fn.HasLock {
			out = append(out, Finding{
				Severity: "drift",
				Subject:  fn.String(),
				Message:  "now takes the mutex itself, so the ledger should say locked instead of helper",
			})
			return out
		}
		path, reachable := m.callPath(e.HeldBy, fn)
		if !reachable {
			holder := e.HeldBy
			if h, ok := led[holder]; ok {
				holder = fmt.Sprintf("%s (%s)", holder, h.Kind)
			}
			out = append(out, Finding{
				Severity: "regression",
				Subject:  fn.String(),
				Message: fmt.Sprintf("has no lock of its own and is no longer reachable from the documented "+
					"lock holder %s, so nothing is known to hold the mutex while it reads or writes the "+
					"DB map. Either restore the call path or record who protects it now.", holder),
			})
			return out
		}
		// path is the chain the ledger promised; -v shows it.
		fn.Path = path
		return out

	case startup:
		return nil
	}
	return nil
}

// callPath answers the one question the helper entries depend on: can this lock
// holder still get to this function? Names are matched, not types, because the
// guard runs with `go run` outside the module and has no type information. That
// is a deliberate trade: one name may belong to several types, which weakens the
// proof slightly, and in this codebase no DB helper name is shared between types.
func (m *Model) callPath(startKey string, target *Func) ([]string, bool) {
	start, ok := m.byKey[startKey]
	if !ok {
		return nil, false
	}
	if start.Key() == target.Key() {
		return []string{target.Name}, true
	}

	type node struct {
		fn   *Func
		path []string
	}
	visited := map[string]bool{start.Key(): true}
	queue := []node{{fn: start, path: []string{start.Name}}}

	for depth := 0; len(queue) > 0 && depth < 200; depth++ {
		next := make([]node, 0, len(queue))
		for _, cur := range queue {
			for _, callee := range cur.fn.Callees {
				if callee == shortName(target.Name) {
					return append(cur.path, target.Name), true
				}
				for _, cand := range m.byName[callee] {
					if visited[cand.Key()] {
						continue
					}
					visited[cand.Key()] = true
					next = append(next, node{fn: cand, path: append(append([]string{}, cur.path...), cand.Name)})
				}
			}
		}
		queue = next
	}
	return nil, false
}

// checkOwned verifies the two things the whole design rests on still exist:
// the one shared mutex, and the map it is supposed to guard.
func (m *Model) checkOwned() []Finding {
	var out []Finding
	if len(m.lockNames) == 0 {
		out = append(out, Finding{
			Severity: "regression",
			Subject:  "internal/server/types.go::lock",
			Message:  "no *sync.Mutex is declared anywhere in the scanned code, so the external lock this design is built on is gone",
		})
	}
	if len(m.dbNames) == 0 {
		out = append(out, Finding{
			Severity: "regression",
			Subject:  "internal/authpf/anchordb.go::AnchorsDB",
			Message:  "no *authpf.AnchorsDB field or variable is declared anywhere, so the guard can no longer see the DB at all",
		})
	}
	return out
}

// checkStore owns the rule for the map primitives inside AnchorsDB. They are not
// listed in the ledger one by one: a new method over the map has to lock, and that
// cannot be opted out of by forgetting a ledger line. The ledger only records why.
func (m *Model) checkStore(led ledgerSet) []Finding {
	var out []Finding
	if m.storeType == "" {
		return []Finding{{
			Severity: "regression",
			Subject:  "internal/authpf/anchordb.go::AnchorsDB",
			Message: "no AnchorsDB struct was found, so the guard cannot tell whether the map is " +
				"still the one that AnchorsDB owns. If the DB type moved, update scan.go: " +
				"indexAnchorsDB is what makes anchordb.go scannable at all",
		}}
	}
	if !m.storeLock {
		return []Finding{{
			Severity: "regression",
			Subject:  "internal/authpf/anchordb.go::" + m.storeType,
			Message: "declares no sync.Mutex or sync.RWMutex field. The map moved inside this struct, " +
				"so the mutex inside it is the only thing an extension cannot bypass. Without it " +
				"Range/Snapshot/Get from an extension goroutine is a fatal error again, and no " +
				"other entry in this ledger would notice",
		}}
	}
	for _, fn := range m.funcs {
		if fn.Recv != m.storeType {
			continue
		}
		// A ledger entry saying otherwise is an explicit decision, and it stays visible.
		if e, ok := led[fn.Key()]; ok && e.Kind != locked {
			continue
		}
		if !fn.HasLock {
			out = append(out, Finding{
				Severity: "regression",
				Subject:  fn.String(),
				Message: fmt.Sprintf("touches the map inside %s without taking its mutex. Callers cannot "+
					"compensate: an extension reaches this through ReadOnlyAnchorsDB and has no way to "+
					"take the server lock. Concurrent access is a fatal error that ends the daemon", m.storeType),
			})
		}
	}
	return out
}

func shortName(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}
