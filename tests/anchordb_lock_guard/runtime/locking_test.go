package runtime_test

// locking_test.go is the runtime half of the anchorsDB locking guard.
//
// The static half proves the locking pattern is still in the source. This half
// proves the pattern is worth enforcing, which static analysis cannot:
//
//  1. AnchorsDB is safe on its own. A reader that knows nothing about the server
//     mutex is what an extension looks like, and it must survive load. The map used
//     to live outside the type, and the same load killed the process with a runtime
//     fatal error; the mutex inside AnchorsDB is what changed that.
//  2. Range must let its callback reach back into the DB. The callback runs with no
//     lock held, and if that ever regresses, the call blocks forever instead of
//     failing - no error, no panic, a wedged daemon.
//  3. The map primitives and the server mutex compose: the handler shape takes the
//     server mutex around a whole section and still calls the locking methods, so
//     "is it activated?" and the write that follows cannot interleave. This is the
//     part no lock inside the type can do, because a method lock is released the
//     moment the method returns.
//
// All of them use the production type, no mock.

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scd-systems/authpf-api/internal/authpf"
)

// load mirrors the shape of the real workload: readers and writers hammering the
// same DB while entries come and go, which is what concurrent API handlers, a
// scheduler tick and an extension scrape do to it at the same time.
const (
	loadWorkers = 8
	loadTime    = 500 * time.Millisecond
)

// TestUnlockedReaderSurvivesLoad is the premise the type now has to hold. The
// reader never takes a lock, because the code that reads the DB from an extension
// cannot reach one: ReadOnlyAnchorsDB is all it is handed.
func TestUnlockedReaderSurvivesLoad(t *testing.T) {
	db := authpf.New()
	var ro authpf.ReadOnlyAnchorsDB = db

	stop := time.Now().Add(loadTime)
	var wg sync.WaitGroup
	var reads atomic.Int64

	for w := 0; w < loadWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; time.Now().Before(stop); i++ {
				switch (w + i) % 3 {
				case 0:
					db.Add(anchor("user"))
				case 1:
					_ = db.Remove("user")
				default:
					// The read an extension performs, with no lock of its own.
					_ = ro.Len()
					_ = ro.IsActivated("user")
					_ = ro.Get("user")
					for range ro.Snapshot() {
					}
					reads.Add(1)
				}
			}
		}(w)
	}

	if !waitTimeout(&wg, 30*time.Second) {
		t.Fatal("unlocked reader load deadlocked, the DB does not protect itself")
	}
	if reads.Load() == 0 {
		t.Fatal("no unlocked read ran, so this test observed nothing")
	}
	t.Logf("%d unsynchronized extension reads survived %d workers for %v", reads.Load(), loadWorkers, loadTime)
}

// TestRangeCallbackMayReachBackIntoTheDB pins the shape of the mutex use inside
// Range. Calling the callback while the mutex is held deadlocks the moment the
// callback reads the DB, and a deadlock is worse than the fatal error it replaced:
// it is silent.
//
// The writers matter. A callback taking RLock again while the outer RLock is held
// succeeds as long as nobody wants to write; one waiting writer blocks every
// reader after it, and that is the case that hangs a daemon under real load.
func TestRangeCallbackMayReachBackIntoTheDB(t *testing.T) {
	db := authpf.New()
	for _, u := range []string{"a", "b", "c"} {
		db.Add(anchor(u))
	}

	stop := time.Now().Add(200 * time.Millisecond)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; time.Now().Before(stop); i++ {
				name := fmt.Sprintf("user%d", i%5)
				if (w+i)%2 == 0 {
					db.Add(anchor(name))
				} else {
					_ = db.Remove(name)
				}
			}
		}(w)
	}

	// Range from a reader goroutine, continuously, while the map is written around
	// it. One call would usually finish before a writer ever queues, which is what
	// makes a single probe useless for proving the absence of a deadlock.
	visits := make(chan int, 1)
	go func() {
		n := 0
		for time.Now().Before(stop) {
			db.Range(func(a *authpf.AuthPFAnchor) bool {
				// Every one of these takes the DB mutex again if Range holds it.
				n += db.Len()
				_ = db.IsActivated(a.Username)
				_ = db.Get(a.Username)
				n += len(db.Snapshot())
				return true
			})
		}
		visits <- n
	}()

	select {
	case n := <-visits:
		if n == 0 {
			t.Fatal("Range never visited an anchor, so this test observed nothing")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Range deadlocked with a writer waiting: it calls its callback while holding " +
			"the mutex. Copy the anchors first, release, then call fn.")
	}
	wg.Wait()
}

// TestLockedAccessSurvivesSameLoad proves the external pattern still works. The
// handler shape holds one mutex across a whole section and calls the DB methods
// inside it; the methods take their own lock a moment later. Lock order is server
// mutex first, DB mutex second, and never the reverse.
func TestLockedAccessSurvivesSameLoad(t *testing.T) {
	var (
		mu       sync.Mutex
		db       = authpf.New()
		stop     = time.Now().Add(loadTime)
		wg       sync.WaitGroup
		sections atomic.Int64
	)

	for w := 0; w < loadWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; time.Now().Before(stop); i++ {
				// The handler shape: lock once, then do everything the section does,
				// including the parts that only read the map.
				mu.Lock()
				switch (w + i) % 3 {
				case 0:
					if !db.IsActivated("user") {
						db.Add(anchor("user"))
					}
				case 1:
					_ = db.Remove("user")
				default:
					for k := range db.GetAll() {
						_ = k
					}
				}
				sections.Add(1)
				mu.Unlock()
			}
		}(w)
	}

	if !waitTimeout(&wg, 30*time.Second) {
		t.Fatal("locked load deadlocked, the lock discipline does not compose")
	}
	// A guard that proves nothing because it observed nothing is worse than none.
	if got := sections.Load(); got == 0 {
		t.Fatal("no locked section ran, so this test observed nothing")
	} else {
		t.Logf("%d locked sections survived %d workers for %v", got, loadWorkers, loadTime)
	}
}

// TestActivationSectionIsAtomic is why the server mutex stays even though the type
// now guards itself. A method lock cannot span the check and the write: two
// activations for the same user must not both decide the user is new, or both load
// the pf anchor and only one of them ever gets removed again. The lock is taken
// here, by the caller, around the whole section.
func TestActivationSectionIsAtomic(t *testing.T) {
	const rounds = 400

	var mu sync.Mutex
	db := authpf.New()

	duplicates := 0
	for round := 0; round < rounds; round++ {
		var activated atomic.Int32
		var wg sync.WaitGroup

		// Two requests racing to activate the same user, as the handler does it.
		for r := 0; r < 2; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mu.Lock()
				fresh := !db.IsActivated("user")
				// A real section runs pfctl between the check and the write, which is
				// what makes the window wide enough to hit. Without the yield the two
				// goroutines still overlap, only less dependably.
				runtime.Gosched()
				if fresh {
					db.Add(anchor("user"))
				}
				mu.Unlock()
				if fresh {
					activated.Add(1)
				}
			}()
		}
		wg.Wait()

		if got := activated.Load(); got > 1 {
			duplicates++
		}
		if err := db.Remove("user"); err != nil {
			t.Fatalf("User remove test error: %s", err.Error())
		}

	}

	if duplicates > 0 {
		t.Fatalf("%d of %d rounds activated the same user twice: the check and the write are "+
			"not one section. Both callers load the pf anchor and only one unload runs, so an "+
			"anchor is left behind with nothing tracking it.", duplicates, rounds)
	}
	t.Logf("%d concurrent activation rounds, no double activation", rounds)
}

// anchor builds an activation the way the API handler does before inserting it.
func anchor(username string) *authpf.AuthPFAnchor {
	return &authpf.AuthPFAnchor{
		Username:  username,
		Timeout:   "1h",
		UserIP:    "203.0.113.7",
		UserID:    1,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}
