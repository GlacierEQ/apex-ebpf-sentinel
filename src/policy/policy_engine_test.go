package policy

import "testing"

func TestDenyOverridesAllow(t *testing.T) {
	eng := &PolicyEngine{policy: Policy{
		DefaultAction: ActionAllow,
		Rules: []Rule{
			{Name: "allow-ssh", ProcessPattern: "sshd", SyscallTypes: []string{"connect"}, Action: ActionAllow, Priority: 10},
			{Name: "deny-ssh-exec", ProcessPattern: "sshd", SyscallTypes: []string{"execve"}, Action: ActionDeny, Priority: 1},
		},
	}}
	if got := eng.Evaluate(Event{Comm: "sshd", Syscall: "execve"}); got != ActionDeny {
		t.Fatalf("execve want deny got %s", got)
	}
	if got := eng.Evaluate(Event{Comm: "sshd", Syscall: "connect"}); got != ActionAllow {
		t.Fatalf("connect want allow got %s", got)
	}
}

func TestSubstringDoesNotImpersonateProcess(t *testing.T) {
	eng := &PolicyEngine{policy: Policy{
		DefaultAction: ActionAllow,
		Rules: []Rule{
			{Name: "deny-cat", ProcessPattern: "cat", SyscallTypes: []string{"*"}, Action: ActionDeny, Priority: 50},
		},
	}}
	if got := eng.Evaluate(Event{Comm: "concatenate", Syscall: "open"}); got != ActionAllow {
		t.Fatalf("concatenate must not match cat, got %s", got)
	}
	if got := eng.Evaluate(Event{Comm: "cat", Syscall: "open"}); got != ActionDeny {
		t.Fatalf("cat must deny, got %s", got)
	}
}

func TestEmptyDefaultIsDeny(t *testing.T) {
	eng := &PolicyEngine{}
	if got := eng.Evaluate(Event{Comm: "unknown", Syscall: "ptrace"}); got != ActionDeny {
		t.Fatalf("fail closed, got %s", got)
	}
}

func TestGlobStarSuffix(t *testing.T) {
	eng := &PolicyEngine{policy: Policy{
		DefaultAction: ActionAudit,
		Rules: []Rule{
			{Name: "python", ProcessPattern: "python*", SyscallTypes: []string{"connect"}, Action: ActionAlert, Priority: 5},
		},
	}}
	if got := eng.Evaluate(Event{Comm: "python3.12", Syscall: "connect"}); got != ActionAlert {
		t.Fatalf("python3.12 want alert got %s", got)
	}
}
