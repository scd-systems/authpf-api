package main

// ledger.go is the declared state of anchorsDB locking: what the code is
// supposed to look like, written down per function.
//
// The anchorsDB is a plain map guarded by one mutex that lives outside it
// (internal/server/types.go). Safety therefore depends on individual functions,
// and a change that drops one lock.Lock() turns the server into a process that
// kills itself with "fatal error: concurrent map read and map write" at some
// point under load. This ledger is the expectation the scan is compared against,
// so such a change fails the guard instead of the customer's uptime.
//
// Four kinds of entry:
//
//	locked  takes the mutex in its own body; verified against the scan
//	helper  reaches the DB with no lock of its own and is only ever called while
//	        HeldBy holds it; the call path from HeldBy is verified
//	startup runs before the HTTP listener starts, so nothing can race it
//	owned   the mutex itself, or the map
//
// Keys are "relative/file.go::Name", so the file is part of the identity: moving
// a function elsewhere is a change worth a look, and the guard asks for one
// rather than following it silently.
//
// Change the ledger only together with the code change it explains.

// ledgerSet is keyed by Func.Key().
type ledgerSet map[string]entry

// production is the ledger for the real repository.
var production = ledgerSet{
	// The API handler. Every entry point that touches the map holds the mutex for
	// its whole body, the pfctl calls included, so a rule can never be half
	// written while another request reads the DB.
	"internal/api/handler.go::Handler.HandleGetLogin": {
		Kind: locked, Why: "entry point, holds the shared mutex",
	},
	"internal/api/handler.go::Handler.HandlePostActivate": {
		Kind: locked, Why: "entry point, the lock covers the checks, the pfctl load and AddToDB",
	},
	"internal/api/handler.go::Handler.HandleGetActivate": {
		Kind: locked, Why: "entry point, reads (*h.db)[user] under the mutex",
	},
	"internal/api/handler.go::Handler.HandleGetAllActivePFAnchors": {
		Kind: locked, Why: "entry point, hands out *h.db by value under the mutex",
	},
	"internal/api/handler.go::Handler.HandleDeleteDeactivate": {
		Kind: locked, Why: "entry point, the lock covers the pfctl unload and db.Remove",
	},
	"internal/api/handler.go::Handler.HandleDeleteAllDeactivate": {
		Kind: locked, Why: "entry point, the lock covers the pfctl flush and db.Flush",
	},

	// Handler helpers: reached through the handler's own mutex, held by the entry
	// point named in HeldBy. The call path is verified, not taken on trust.
	"internal/api/checks.go::Handler.CheckAnchorIsActivated": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandlePostActivate",
		Why: "reads db.IsActivated while the caller holds the mutex",
	},
	"internal/api/handler.go::Handler.AddToDB": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandlePostActivate",
		Why: "the duplicate check and db.Add run while the caller holds the mutex",
	},
	"internal/api/calls.go::Handler.CallExecDeactivateAllAnchors": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandleDeleteAllDeactivate",
		Why: "db.Flush runs while the caller holds the mutex",
	},

	// The scheduler. The ticker goroutine takes the same mutex around a whole
	// cleanup pass, so it waits behind handlers instead of cutting between them.
	"internal/scheduler/scheduler.go::Scheduler.Run": {
		Kind: locked, Why: "locks around cleanupExpiredRules on every tick",
	},
	"internal/scheduler/scheduler.go::Scheduler.cleanupExpiredRules": {
		Kind: helper, HeldBy: "internal/scheduler/scheduler.go::Scheduler.Run",
		Why: "iterates *s.db and removes entries under the tick's lock",
	},

	// Shutdown flushes every anchor before the process exits.
	"internal/server/shutdown.go::Server.deactivateAllActiveUsers": {
		Kind: locked, Why: "entry point, holds the package mutex for the whole flush",
	},

	// Exec reaches the map through its own db field and never locks. That is only
	// right because each caller takes the mutex first, so every helper is pinned
	// to the caller that provides it. exec.New only rejects a nil db, so a new
	// caller is a review question, and this list is where the answer has to show
	// up: an Exec method nobody can reach from a lock holder is a finding.
	"internal/exec/exec.go::Exec.FlushAnchor": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandleDeleteDeactivate",
		Why: "called from CallExecDeactivateAnchor under the handler's mutex",
	},
	"internal/exec/exec.go::Exec.FlushAllAnchors": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandleDeleteAllDeactivate",
		Why: "ranges *e.db through buildPfctlDeactivateAllCmdParameters under the handler's mutex",
	},
	"internal/exec/exec.go::Exec.FlushAllPFTables": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandleDeleteAllDeactivate",
		Why: "ranges *e.db under the handler's mutex",
	},
	"internal/exec/exec.go::Exec.buildPfctlDeactivateAllCmdParameters": {
		Kind: helper, HeldBy: "internal/api/handler.go::Handler.HandleDeleteAllDeactivate",
		Why: "ranges *e.db while FlushAllAnchors holds the caller's mutex",
	},

	// Startup and import. Both finish before the server accepts a single request,
	// which is why they need no mutex. If a call ever moves behind a running
	// server, it needs the lock and this entry has to become locked.
	"internal/exec/importer.go::Exec.ImportAuthPF": {
		Kind: startup, Why: "onStartup import runs before the listener starts",
	},
	"internal/exec/importer.go::Exec.parsePfctlOutput": {
		Kind: helper, HeldBy: "internal/exec/importer.go::Exec.ImportAuthPF",
		Why: "writes the map while the startup import has it to itself",
	},
	"internal/server/bootstrap.go::Server.Bootstrap": {
		Kind: startup, Why: "s.db.Flush on onStartup=importflush runs before any request can arrive",
	},

	// The map primitives live in AnchorsDB itself now. They are not listed one by
	// one: checkStore owns the rule, and the entries below only carry the reason.
	"owned::internal/server/types.go.lock":         {Kind: owned, Why: "the single shared mutex"},
	"owned::internal/authpf/anchordb.go.AnchorsDB": {Kind: owned, Why: "the struct that owns the map and its mutex"},
}

type entryKind int

const (
	locked entryKind = iota
	helper
	startup
	owned
)

func (k entryKind) String() string {
	switch k {
	case locked:
		return "locked"
	case helper:
		return "helper"
	case startup:
		return "startup"
	}
	return "owned"
}

type entry struct {
	Kind   entryKind
	HeldBy string // ledger key of the lock holder, helpers only
	Why    string
}

func (e entry) String() string {
	switch e.Kind {
	case locked:
		return "locked: " + e.Why
	case helper:
		return "helper, lock held by " + e.HeldBy + ": " + e.Why
	case startup:
		return "startup, no lock needed: " + e.Why
	}
	return e.Why
}
