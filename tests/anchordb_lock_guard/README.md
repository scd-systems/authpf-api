# anchorsDB locking guard

Keeps the locking discipline around the anchorsDB map intact. Run it with:

```sh
./tests/e2e_anchordb_lock_guard_test.sh              # static + runtime
./tests/e2e_anchordb_lock_guard_test.sh --selftest   # also prove the guard can fail
./tests/e2e_anchordb_lock_guard_test.sh --verbose    # full accessor inventory
```

## What is being protected

Two locks protect this data and the guard watches both.

- `authpf.AnchorsDB` (`internal/authpf/anchordb.go`) is a struct that owns the map
  and a mutex of its own. Every one of its methods takes that mutex, which is what
  makes the DB safe for an extension: `ReadOnlyAnchorsDB` cannot reach the server
  lock, so the type has to protect itself.
- The server mutex (`internal/server/types.go`) is taken by the API handler and the
  scheduler around a whole section, so a check and the write that follows cannot
  interleave with another activation. The mutex inside the type cannot do that, it
  is released when the method returns.

Lock order is server mutex first, `AnchorsDB.mu` second, never the reverse.

Two ways to break this, and neither shows up in review:

```
fatal error: concurrent map read and map write   // a method lost its mu
```

Unrecoverable, and it takes the whole daemon down rather than one request. Or the
reverse: a method that locks *too much* for its own good, `Range` calling back into
the DB with the mutex held, which wedges the daemon silently instead of failing.

## How it works

Two independent halves, both reached through the script.

**Static** (`static_guard/`, a `go run` program, stdlib only) scans `internal/`
and `pkg/` with `go/ast` and answers, per function: does it reach the map, and
does it take the shared mutex? Names are found by declared type, not by string, so
renaming `lock` to `dbMu` keeps working.

Reaching the map means `range *db`, `*db`, `(*db)[k]`, `len(*db)`, `clear(db)`, or a
method call such as `db.Add(...)`. Holding the lock means taking that mutex and
releasing it, `defer` or ordered `Unlock`.

`AnchorsDB` is a struct now, so the scan reads the type as well: the mutex field and
the map field inside it are what it looks for, and every method with that receiver is
checked by rule rather than by ledger entry. A new method over the map that does not
lock is a regression with no ledger line to forget.

Each accessor is then compared against `static_guard/ledger.go`, which states what
the code is supposed to look like:

| kind      | meaning                                                       | verified                              |
| --------- | ------------------------------------------------------------- | ------------------------------------- |
| `locked`  | takes the mutex in its own body                               | lock and release present              |
| `helper`  | unlocked, called while `HeldBy` holds the mutex               | call path from `HeldBy` still exists  |
| `startup` | runs before the listener accepts requests                     | by declaration, with a reason         |
| `owned`   | the mutex itself, and the map                                 | both still declared                   |

A new accessor with no entry is a finding. So is an existing accessor that stopped
locking, a helper whose lock holder no longer holds the lock, and a ledger entry
whose function disappeared. `-v` prints the call chain each helper relies on.

**Runtime** (`runtime/`) proves the pattern is worth enforcing, which no static
check can. Four things, all against the production type:

- a reader that takes no lock at all, as an extension sees it, survives load
- `Range`'s callback may reach back into the DB while writers are running
- the handler shape (server mutex around a whole section) survives the same load
- two concurrent activations of one user do not both decide the user is new

They run with `CGO_ENABLED=0`: this repository has no C toolchain, so `-race` is
unavailable, and the guard has to work without it.

## Proving the guard bites

A guard that can only say "fine" is decoration, so each failure mode is exercised:

```sh
go run ./tests/anchordb_lock_guard/static_guard -selftest
```

Fixtures are generated into a temp dir: correct code that must pass, a dropped
lock on an entry point, a dropped lock on a helper's holder, an undocumented
accessor, and a code root with no DB at all (which must be reported rather than
pass quietly, because a scan that matches nothing passes by accident).

To check the real thing end to end, delete a `lock.Lock()` from a handler, run the
script, watch it name the function, and put it back.

## Changing the ledger

Change it in the same commit as the code that makes it true, and put the reason in
`Why`. The ledger is the design record: `internal/exec` has no lock of its own
because every caller takes the mutex first, and that claim lives here as four
entries rather than in someone's memory.

## Out of scope

The gap `ReadOnlyAnchorsDB` used to open is closed: the mutex moved into the type,
so an extension reads a guarded map whether or not it knows about locking. Its probe
script stays as the independent check of that claim:

```sh
./tests/e2e_anchordb_lock_test.sh --expect-clean
```

Extension routes are still unauthenticated, and the server mutex is still held
across `pfctl` I/O. Both are deliberate and tracked elsewhere.
