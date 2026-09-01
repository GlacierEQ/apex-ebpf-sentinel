package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GlacierEQ/apex-ebpf-sentinel/src/loader"
	"github.com/GlacierEQ/apex-ebpf-sentinel/src/policy"
	"github.com/GlacierEQ/apex-ebpf-sentinel/src/probes"
)

func TestPolicyEngineEvaluate(t *testing.T) {
	yamlContent := `
default_action: audit
rules:
  - name: block_xmrig
    process_pattern: "xmrig"
    syscall_types: ["*"]
    action: deny
    priority: 100
`
	tmpPath := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(tmpPath, []byte(yamlContent), 0644)

	pe, err := policy.LoadFromFile(tmpPath)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	action := pe.EvaluateData("xmrig", "execve")
	if action != policy.ActionDeny {
		t.Errorf("expected deny, got %v", action)
	}

	action = pe.EvaluateData("curl", "execve")
	if action != policy.ActionAudit {
		t.Errorf("expected audit, got %v", action)
	}
}

func TestSentinelLoaderStartStop(t *testing.T) {
	pe := &policy.PolicyEngine{}
	l := loader.NewSentinelLoader(pe)
	
	ctx, cancel := context.WithCancel(context.Background())
	err := l.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	
	time.Sleep(200 * time.Millisecond)
	cancel()
	
	// just a brief sleep to allow shutdown
	time.Sleep(50 * time.Millisecond)
}

func TestProbeRegistryPlatformProbes(t *testing.T) {
	r := probes.NewProbeRegistry()
	p := r.PlatformProbes()
	if len(p) == 0 {
		t.Errorf("expected at least 1 platform probe")
	}
}

func TestEventMetrics(t *testing.T) {
	pe := &policy.PolicyEngine{}
	l := loader.NewSentinelLoader(pe)
	ctx, cancel := context.WithCancel(context.Background())
	l.Start(ctx)
	
	count := 0
	for count < 5 {
		select {
		case <-l.Events():
			count++
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for events")
		}
	}
	cancel()
}
