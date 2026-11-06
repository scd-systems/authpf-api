package runtime_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scd-systems/authpf-api/internal/authpf"
)

func TestPollingExtensionSurvivesConcurrentWrites(t *testing.T) {
	db := authpf.New()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var writes, reads atomic.Int64

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				db.Add(anchor("polled-user"))
				_ = db.Remove("polled-user")
				writes.Add(1)
			}
		}
	}()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = db.Snapshot()
				reads.Add(1)
			}
		}
	}()

	time.Sleep(loadTime)
	close(stop)
	wg.Wait()
	if writes.Load() == 0 || reads.Load() == 0 {
		t.Fatalf("observed %d writes and %d polling reads; want both", writes.Load(), reads.Load())
	}
}
