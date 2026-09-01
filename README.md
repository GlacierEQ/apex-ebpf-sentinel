# apex-ebpf-sentinel

Cross-platform process observability and policy enforcement daemon.

## Architecture

```
[ eBPF / DTrace ] ---> [ Sentinel Loader ] ---> [ Policy Engine ] ---> Action (Allow/Deny/Audit/Alert)
```

## eBPF vs DTrace

- **eBPF (Linux)**: Uses kprobes/tracepoints. High performance, native process control.
- **DTrace (macOS)**: Used as a fallback for tracing execve on macOS.

## Policy DSL

Define rules in `config/policy.yaml`:
```yaml
rules:
  - name: block_crypto_miners
    process_pattern: "xmrig"
    syscall_types: ["*"]
    action: deny
    priority: 100
```
