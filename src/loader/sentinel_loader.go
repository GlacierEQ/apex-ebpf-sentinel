//go:build !linux
// +build !linux

package loader

import (
	"context"
	"time"

	"github.com/GlacierEQ/apex-ebpf-sentinel/src/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type SentinelEvent struct {
	PID       int32
	PPID      int32
	UID       uint32
	Comm      string
	Syscall   string
	Args      []string
	Timestamp time.Time
	Action    string
}

type SentinelLoader struct {
	policy  *policy.PolicyEngine
	eventCh chan SentinelEvent
	done    chan struct{}
}

var (
	eventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apex_sentinel_events_total",
			Help: "Total number of sentinel events",
		},
		[]string{"syscall", "action"},
	)
)

func NewSentinelLoader(pe *policy.PolicyEngine) *SentinelLoader {
	return &SentinelLoader{
		policy:  pe,
		eventCh: make(chan SentinelEvent, 100),
		done:    make(chan struct{}),
	}
}

func (s *SentinelLoader) Start(ctx context.Context) error {
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Synthetic events for macOS fallback
				event := SentinelEvent{
					PID:       1001,
					PPID:      1,
					UID:       501,
					Comm:      "synthetic",
					Syscall:   "execve",
					Args:      []string{"/bin/ls"},
					Timestamp: time.Now(),
				}
				action := s.policy.Evaluate(event)
				event.Action = string(action)
				
				eventsTotal.WithLabelValues(event.Syscall, event.Action).Inc()
				
				select {
				case s.eventCh <- event:
				default:
				}
			}
		}
	}()
	return nil
}

func (s *SentinelLoader) Events() <-chan SentinelEvent {
	return s.eventCh
}
