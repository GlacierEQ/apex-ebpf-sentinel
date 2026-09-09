package policy

import (
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAlert Action = "alert"
	ActionAudit Action = "audit"
)

type Rule struct {
	Name           string   `yaml:"name"`
	ProcessPattern string   `yaml:"process_pattern"`
	SyscallTypes   []string `yaml:"syscall_types"`
	Action         Action   `yaml:"action"`
	Priority       int      `yaml:"priority"`
}

type Policy struct {
	Rules         []Rule `yaml:"rules"`
	DefaultAction Action `yaml:"default_action"`
}

type PolicyEngine struct {
	policy Policy
}

func LoadFromFile(path string) (*PolicyEngine, error) {
	pe := &PolicyEngine{}
	if err := pe.Reload(path); err != nil {
		return nil, err
	}
	return pe, nil
}

func (p *PolicyEngine) Reload(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return err
	}

	sort.Slice(pol.Rules, func(i, j int) bool {
		return pol.Rules[i].Priority > pol.Rules[j].Priority
	})

	p.policy = pol
	return nil
}

func (p *PolicyEngine) AddRule(rule Rule) {
	p.policy.Rules = append(p.policy.Rules, rule)
	sort.Slice(p.policy.Rules, func(i, j int) bool {
		return p.policy.Rules[i].Priority > p.policy.Rules[j].Priority
	})
}

// Event is the cycle-free view of a syscall the loader already saw.
type Event struct {
	Comm    string
	Syscall string
}

// Evaluate is fail-closed: any matching deny beats allow/alert/audit.
func (p *PolicyEngine) Evaluate(event Event) Action {
	return p.evaluate(event.Comm, event.Syscall)
}

func (p *PolicyEngine) EvaluateData(comm string, syscall string) Action {
	return p.evaluate(comm, syscall)
}

func matchProcess(comm, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if comm == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(comm, strings.TrimPrefix(pattern, "*")) {
		return true
	}
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(comm, strings.TrimSuffix(pattern, "*")) {
		return true
	}
	return false
}

func matchSyscall(syscall string, types []string) bool {
	if len(types) == 0 {
		return false
	}
	for _, st := range types {
		if st == "*" || st == syscall {
			return true
		}
	}
	return false
}

func (p *PolicyEngine) evaluate(comm, syscall string) Action {
	matched := false
	best := p.policy.DefaultAction
	if best == "" {
		best = ActionDeny
	}
	for _, rule := range p.policy.Rules {
		if !matchProcess(comm, rule.ProcessPattern) {
			continue
		}
		if !matchSyscall(syscall, rule.SyscallTypes) {
			continue
		}
		matched = true
		if rule.Action == ActionDeny {
			return ActionDeny
		}
		best = rule.Action
	}
	if !matched && p.policy.DefaultAction == "" {
		return ActionDeny
	}
	return best
}
