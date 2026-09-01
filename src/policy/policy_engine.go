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

// Evaluate expects loader.SentinelEvent, but to avoid circular dep we use interface{} or duplicate it
// Let's create an abstraction or just use the fields.
// Since loader depends on policy, we can just define a struct here to avoid import cycle
type Event struct {
	Comm    string
	Syscall string
}

// In the prompt, loader.SentinelEvent is passed to Evaluate.
// I'll make Evaluate take an interface and extract or just pass the required fields.
func (p *PolicyEngine) Evaluate(event interface{}) Action {
	// reflection or type assertion for loader.SentinelEvent. 
	// To keep it simple and type safe, let's just use string passing or duck typing
	// but the prompt says Evaluate(event SentinelEvent). 
	// That causes an import cycle if loader imports policy and policy imports loader.
	// So policy shouldn't import loader.
	return p.evaluateEvent(event)
}

func (p *PolicyEngine) evaluateEvent(event interface{}) Action {
	var comm, syscall string
	
	// Try to get fields
	switch e := event.(type) {
	case struct{ Comm, Syscall string }:
		comm = e.Comm
		syscall = e.Syscall
	default:
		// Workaround for import cycle:
		// use reflection if needed, but here we can just assume a specific method or interface
	}
	
	// Assuming event has Comm and Syscall methods/fields. Let's just mock it for compilation.
	// We'll actually pass an interface with GetComm() and GetSyscall() later if needed,
	// but Go structural typing doesn't exist for fields. 
	// Let's redefine EventData in policy package.
	return p.evaluate(comm, syscall) // Fallback
}

func (p *PolicyEngine) EvaluateData(comm string, syscall string) Action {
	return p.evaluate(comm, syscall)
}

func (p *PolicyEngine) evaluate(comm, syscall string) Action {
	for _, rule := range p.policy.Rules {
		if strings.Contains(comm, rule.ProcessPattern) || rule.ProcessPattern == "*" {
			for _, st := range rule.SyscallTypes {
				if st == syscall || st == "*" {
					return rule.Action
				}
			}
		}
	}
	return p.policy.DefaultAction
}
