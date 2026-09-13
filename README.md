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

### Machine–Mesh Protocol Manifest

<!-- glacier-eq-protocol:start -->
```yaml
{
  "schema": "glacier-eq.readme.machine-mesh/v1",
  "repository": {
    "id": "GlacierEQ/apex-ebpf-sentinel",
    "url": "https://github.com/GlacierEQ/apex-ebpf-sentinel",
    "readme_contract": "estate-machine-v1",
    "default_branch": "main"
  },
  "machine": {
    "repository_kind": "migration-residue",
    "public_api": "inspect-declared-entrypoints",
    "protocol_files": [],
    "entrypoints": [
      {
        "kind": "package-contract",
        "path": "go.mod",
        "policy": "inspect-before-use"
      },
      {
        "kind": "source-area",
        "path": "src",
        "policy": "inspect-before-use"
      },
      {
        "kind": "test-area",
        "path": "tests",
        "policy": "run-before-reliance"
      },
      {
        "kind": "capability-contract",
        "path": "GENIUS.yaml",
        "policy": "read-first"
      },
      {
        "kind": "role-contract",
        "path": "ROLE.yaml",
        "policy": "read-first"
      }
    ]
  },
  "presentation": {
    "architecture": [
      "recruiter",
      "master",
      "machine",
      "mesh"
    ],
    "authority": {
      "capability": "stone-psysoc-x",
      "repository": "GlacierEQ/AKOS",
      "manifest": "stones/psysoc-x/stone.json",
      "engine": "infinity_stones/psysoc_x.py"
    },
    "truth_invariant": "presentation-may-change-sequence-density-tone-and-style; facts-evidence-uncertainty-provenance-dignity-and-reader-agency-may-not"
  },
  "license": {
    "class": "NO_ROOT_LICENSE_DETECTED",
    "status": "ORIGINALITY_AND_PROVENANCE_REVIEW_REQUIRED",
    "controlling_path": null,
    "policy": "GlacierEQ/job-app-helix/LICENSE_POLICY.json",
    "may_relicense_automatically": false,
    "upstream_rights_must_be_preserved": false
  },
  "mesh": {
    "primary_home": null,
    "branch": "migration-residue",
    "subcategory": "unresolved-primary-home",
    "routing": [
      {
        "relation": "estate-map",
        "target": "GlacierEQ/monolith",
        "url": "https://github.com/GlacierEQ/monolith"
      }
    ],
    "boundaries": [
      "routing-does-not-transfer-source-code-evidence-deployment-or-lifecycle-authority",
      "generated-contract-is-a-source-index-not-a-runtime-or-provider-receipt",
      "implementation-and-provider-state-require-independent-evidence",
      "presentation-calibration-cannot-promote-claim-or-evidence-state",
      "license-automation-cannot-relicense-unresolved-upstream-or-third-party-rights"
    ]
  },
  "provenance": {
    "generated_by": "GlacierEQ/job-app-helix",
    "generator_contract": "estate-machine-v1",
    "classification_source": null,
    "classification_evidence_path": null,
    "classification_evidence_blob_sha": null,
    "classification_status": null,
    "contract_digest": "e545e86a9a21dcaefec7c531fd737e838279230e25cf1b11e5608521549178d4"
  }
}
```
<!-- glacier-eq-protocol:end -->
