# CIS Docker Benchmark v1.6.0 — Automated Compliance Checks

**Benchmark**: CIS Docker Benchmark **v1.6.0** (2023-09-29)
**Source**: https://www.cisecurity.org/benchmark/docker
**Scope**: Section 5 — Container Runtime Configuration
**Target**: [`iac/n8n/docker-compose.yml`](../iac/n8n/docker-compose.yml)
**Policy file**: [`policy/runtime-hardening-policy.yml`](runtime-hardening-policy.yml)
**Enforced by**: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — runs on every push and pull request, **blocks merge on violation**

---

## How the Check Works

The `CIS Docker Benchmark v1.6.0 Compliance Check` job in `ci.yml`:
- Parses `iac/n8n/docker-compose.yml` using shell text matching
- Evaluates each automated control below
- Prints `✅ PASS` or `❌ FAIL` per control ID
- Exits with code 1 (blocking CI) if **any** control fails
- Does **not** auto-fix — the developer must correct the compose file and push again

---

## Automated Controls (14 checks)

| CIS ID | Control | Check Performed | Compose Setting |
|--------|---------|----------------|-----------------|
| **5.1** | AppArmor profile applied | `security_opt` contains `apparmor:docker-default` | `security_opt: [apparmor:docker-default]` |
| **5.2** | All capabilities dropped | `cap_drop` contains `ALL`; no `cap_add` entries | `cap_drop: [ALL]` |
| **5.3** | No privileged mode | `privileged: true` is absent | *(key omitted — default false)* |
| **5.4 / 5.31** | No sensitive host mounts or docker.sock | Volumes do not reference `/etc`, `/proc`, `/sys`, `/dev`, `docker.sock` | Named volume only: `n8n_storage` |
| **5.7** | No privileged ports mapped | No host port < 1024 in `ports:` | Port `5678` only |
| **5.10** | Memory limit set | `mem_limit` is present | `mem_limit: ${MEM_LIMIT:-1g}` |
| **5.11** | CPU limit set | `cpus` is present | `cpus: "${CPU_LIMIT:-1.0}"` |
| **5.12** | Root filesystem is read-only | `read_only: true` is present | `read_only: true` |
| **5.13** | Port bound to specific interface | Port binding does not use `0.0.0.0` | `ports: "${HOST_IP}:5678:5678"` |
| **5.14** | Restart policy uses on-failure | `restart:` value contains `on-failure` | `restart: "on-failure:5"` |
| **5.18** | ulimits configured | `ulimits:` key is present | `ulimits: nofile: soft=1024 hard=4096` |
| **5.21** | Default seccomp not disabled | `seccomp:unconfined` is absent from `security_opt` | *(not set — default profile active)* |
| **5.25** | No new privileges | `security_opt` contains `no-new-privileges:true` | `security_opt: [no-new-privileges:true]` |
| **5.28** | PIDs cgroup limit set | `pids_limit` is present | `pids_limit: ${PIDS_LIMIT:-200}` |
| **5.29** | Custom network (not docker0) | `networks:` key present; `network_mode: host` absent | `networks: [n8n_net]` (custom bridge) |

---

## Not-Applicable Controls

These CIS 5.x controls are documented in [`runtime-hardening-policy.yml`](runtime-hardening-policy.yml) as `NOT_APPLICABLE` — they are not automated checks because the settings they guard against are simply absent from the compose file.

| CIS ID | Control | Reason |
|--------|---------|--------|
| 5.5 / 5.9 | No host network namespace | `network_mode: host` not set |
| 5.15 | No host process namespace | `pid: host` not set |
| 5.16 | No host IPC namespace | `ipc: host` not set |
| 5.17 | No host device exposure | `devices:` key absent |
| 5.20 | No host UTS namespace | `uts: host` not set |
| 5.30 | No host user namespace | `userns_mode` not set |

---

## Fixing a Failure

If the CI job fails, the output will show which CIS control failed and why:

```
❌ CIS 5.12 — read_only: true is missing — root filesystem is writable
```

Add or correct the relevant setting in `iac/n8n/docker-compose.yml`, commit, and push. The CI check will re-run automatically.

---

## Extending the Policy

To add, change, or accept-a-risk on a control:

1. Edit [`policy/runtime-hardening-policy.yml`](runtime-hardening-policy.yml) — update the control's `status` or `enforcement` field
2. If adding a new automated check, add the corresponding shell check to the `CIS Docker Benchmark v1.6.0 Compliance Check` job in `.github/workflows/ci.yml`
3. Open a Pull Request — all policy changes are auditable in git history
