package probes

import (
	"errors"
	"runtime"
)

type ProbeType string

const (
	KProbe     ProbeType = "KProbe"
	UProbe     ProbeType = "UProbe"
	Tracepoint ProbeType = "Tracepoint"
	DTrace     ProbeType = "DTrace"
)

type ProbeSpec struct {
	Name   string
	Type   ProbeType
	Target string
	Symbol string
}

type ProbeRegistry struct {
	probes map[string]ProbeSpec
}

func NewProbeRegistry() *ProbeRegistry {
	return &ProbeRegistry{
		probes: make(map[string]ProbeSpec),
	}
}

func (r *ProbeRegistry) Register(spec ProbeSpec) error {
	if _, exists := r.probes[spec.Name]; exists {
		return errors.New("probe already registered")
	}
	r.probes[spec.Name] = spec
	return nil
}

func (r *ProbeRegistry) ListActive() []ProbeSpec {
	var list []ProbeSpec
	for _, p := range r.probes {
		list = append(list, p)
	}
	return list
}

func (r *ProbeRegistry) Deregister(name string) error {
	if _, exists := r.probes[name]; !exists {
		return errors.New("probe not found")
	}
	delete(r.probes, name)
	return nil
}

func (r *ProbeRegistry) PlatformProbes() []ProbeSpec {
	if runtime.GOOS == "darwin" {
		return []ProbeSpec{
			{Name: "exec_dtrace", Type: DTrace, Target: "syscall::execve:entry", Symbol: "execve"},
		}
	}
	return []ProbeSpec{
		{Name: "exec_tracepoint", Type: Tracepoint, Target: "syscalls/sys_enter_execve", Symbol: "sys_enter_execve"},
	}
}
