package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GlacierEQ/apex-ebpf-sentinel/src/loader"
	"github.com/GlacierEQ/apex-ebpf-sentinel/src/policy"
	"github.com/GlacierEQ/apex-ebpf-sentinel/src/probes"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	policyPath := flag.String("policy", "config/policy.yaml", "Path to policy YAML")
	metricsPort := flag.String("metrics-port", "9090", "Metrics port")
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	level, err := zerolog.ParseLevel(*logLevel)
	if err == nil {
		zerolog.SetGlobalLevel(level)
	}

	pe, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		log.Warn().Err(err).Msg("failed to load policy, using default")
		pe = &policy.PolicyEngine{}
	}

	pr := probes.NewProbeRegistry()
	for _, p := range pr.PlatformProbes() {
		pr.Register(p)
	}

	sl := loader.NewSentinelLoader(pe)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to start loader")
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":"+*metricsPort, nil)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Info().Msg("Sentinel running...")

	for {
		select {
		case event := <-sl.Events():
			log.Info().
				Str("comm", event.Comm).
				Str("syscall", event.Syscall).
				Str("action", event.Action).
				Int32("pid", event.PID).
				Msg("event")
		case <-sigCh:
			log.Info().Msg("Shutting down...")
			cancel()
			time.Sleep(100 * time.Millisecond) // wait for shutdown
			return
		}
	}
}
