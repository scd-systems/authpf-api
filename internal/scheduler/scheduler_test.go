package scheduler

import (
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
)

// TestRunSurvivesUnusableInterval is the regression guard for the reported
// panic: time.NewTicker aborts the process with "non-positive interval" for
// negative, zero and sub-second intervals, and Run() runs in its own goroutine,
// so the crash arrived long after startup looked healthy. Run() must fall back
// to the default interval instead.
func TestRunSurvivesUnusableInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
	}{
		{name: "negative", interval: "-5s"},
		{name: "zero", interval: "0s"},
		{name: "sub-second truncates to zero seconds", interval: "500ms"},
		{name: "not a duration at all", interval: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(authpf.New(), &sync.Mutex{}, zerolog.Nop(), &config.ConfigFile{
				AuthPF: config.ConfigFileAuthPF{SchedulerInterval: tt.interval},
			})

			panicked := make(chan any, 1)
			go func() {
				// A panic in a goroutine only escapes the process if nothing
				// recovers in that same goroutine.
				defer func() {
					if r := recover(); r != nil {
						panicked <- r
					}
				}()
				s.Run()
			}()

			select {
			case r := <-panicked:
				t.Fatalf("Run() panicked for schedulerInterval %q: %v", tt.interval, r)
			case <-time.After(200 * time.Millisecond):
				// No panic; the fallback interval is 60s, so no tick fired and
				// no pfctl call is attempted.
			}
		})
	}
}
