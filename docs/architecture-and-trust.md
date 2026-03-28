# Architecture and Trust Model

## Purpose

This repository is designed to reduce the risk of promoting a third-party image directly from an upstream registry into an environment you operate. It focuses on image trust, approval quality, and blast-radius reduction after deployment.

The example image is `n8nio/n8n`, but the architecture is meant to illustrate a broader vendor-image promotion pattern.

## Threat Model Mapping

| Threat pattern | Why it matters here | Primary control in this repo |
| :--- | :--- | :--- |
| Dependency chain abuse | A trusted vendor image can still introduce risky or newly vulnerable components | digest pinning, Trivy scan, KEV/EPSS/age enrichment |
| Artifact substitution or tag drift | A mutable upstream tag can change without notice | resolve and pin immutable digest before promotion |
| Prohibitive licenses | Vendor images may introduce strict copyleft licenses | Trivy license scanning blocking promotion |
| Runtime misconfigurations | Static scans miss exposed runtime HTTP flaws | OWASP ZAP baseline DAST during smoke run |
| IaC and script weaknesses | Deployment files can undermine otherwise good image controls | Checkov and Shellcheck in CI |
| Insufficient flow control | Higher-risk images should not move through the same path as cleaner ones | manual approval via `trusted-promotion` |
| Weak artifact integrity evidence | Teams need proof, not only a passing scan | provenance and SBOM attestation |
| Weak pipeline identity model | Long-lived publish credentials expand exposure | ephemeral `GITHUB_TOKEN` and OIDC-backed attestation |
| Insufficient day-2 monitoring | Risk changes after promotion | scheduled re-scan of the latest promoted release |
| Runtime over-privilege | A compromised workload can still do damage after deploy | hardened Docker runtime settings |

## Pipeline Architecture

```mermaid
flowchart TD
    subgraph Intake["1. Secure Intake"]
        A["Manual promotion request or weekly version check"] --> B["Allowlist and semver policy"]
        B --> C["Resolve immutable digest"]
    end

    subgraph Analysis["2. Risk Enrichment"]
        C --> D["Trivy vulnerability, secret, license, and malware scan"]
        C --> E["Tracee reachability and ZAP smoke run"]
        D --> F["KEV, EPSS, and age enrichment"]
        E --> F
    end

    subgraph Gate["3. Decision Logic"]
        F --> G{"Approval gate"}
        G -->|Lower-risk path| H["Auto-promote"]
        G -->|Higher-risk path| I["Manual approval required"]
    end

    subgraph Trust["4. Provenance and Release"]
        H --> J["Push trusted image to GHCR"]
        I --> J
        J --> K["Attest provenance and SBOM"]
        K --> L["Create GitHub release with rollback metadata"]
    end

    subgraph Monitor["5. Day-2 Operations"]
        L --> M["Scheduled re-scan"]
        M --> N["Open issue if risk crosses review threshold"]
    end
```

## Identity, Trust, and Attestation

Current trust model:

- GHCR authentication uses the repository-scoped ephemeral `GITHUB_TOKEN`
- attestation flows use GitHub Actions OIDC with `id-token: write`
- build provenance and SBOM attestations are attached to the promoted image
- workflows are pinned to immutable action SHAs

In practical terms, the promotion path avoids a long-lived registry password or PAT for normal publish operations and treats the GitHub Actions workflow as the controlled promotion environment for this repository.

## Framework Alignment

These frameworks are used as design references, not blanket compliance claims.

### OWASP Top 10 CI/CD Security Risks

Useful here for framing the pipeline as an attack surface instead of only a delivery mechanism.

Examples in this repo:

- workflow separation
- manual approval for higher-risk paths
- digest pinning
- artifact evidence and release traceability

### NIST SP 800-53

Useful here for the control vocabulary behind access control, integrity, auditability, and least privilege.

Examples in this repo:

- policy-as-code
- approval gates
- audit-friendly release evidence
- hardened runtime defaults

### NIST SP 800-204D

Useful here for understanding how supply-chain controls fit into a DevSecOps pipeline.

Examples in this repo:

- policy-driven intake
- artifact-centric promotion decisions
- ongoing re-scan of the active promoted release

### SLSA

Useful here for reasoning about provenance, artifact integrity, and promotion trust.

Examples in this repo:

- immutable digest pinning
- provenance attestation
- SBOM attestation
- release evidence tied to the promoted image digest

## Docker Hardening

Supply-chain controls answer "can I trust this artifact?" Runtime hardening answers "if the workload is compromised, how much damage can it do?"

This repository reduces runtime blast radius by:

- dropping capabilities with `cap_drop: ALL`
- enabling `no-new-privileges`
- using a read-only root filesystem where practical
- preferring non-root execution
- constraining CPU, memory, and process counts
- applying AppArmor and related runtime restrictions

Docker hardening complements the promotion pipeline. It does not replace supply-chain integrity evidence.
