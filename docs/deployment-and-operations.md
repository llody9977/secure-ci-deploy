# Deployment and Operations

## Deployment Assets

The deployment stack lives under [iac/n8n](../iac/n8n).

Main files:

- [docker-compose.yml](../iac/n8n/docker-compose.yml)
- [install.sh](../iac/n8n/install.sh)
- [upgrade.sh](../iac/n8n/upgrade.sh)
- [.env.template](../iac/n8n/.env.template)

## What the Deployment Does

The deployment path is for running the promoted `n8n-trusted` image after it has cleared the promotion workflow.

It is responsible for:

- pulling the trusted image from GHCR
- preferring digest-pinned deployment when available
- running the workload with hardened Docker settings
- starting n8n with external task runners
- supporting upgrades and rollback

## Install Flow

```bash
git clone https://github.com/llody9977/secure-ci-deploy.git
cd secure-ci-deploy/iac/n8n
chmod +x install.sh
./install.sh
```

The installer:

- detects the repository and release source
- allows selection of an explicit version or latest release
- fetches the GHCR digest from release metadata when available
- verifies provenance with `gh attestation verify` when GitHub CLI is authenticated
- writes `.env` values for image selection, resource limits, and runner settings
- deploys both `n8n` and `task-runners`

## Runtime Hardening

The compose stack is intentionally restrictive.

Key controls:

- non-root execution
- `cap_drop: ALL`
- `no-new-privileges`
- read-only root filesystem
- bounded CPU, memory, and PID usage
- custom Docker network
- bounded JSON-file log rotation

## External Task Runners

The deployment uses n8n external task runners instead of internal mode.

Why:

- internal mode is not recommended for production
- it can depend on Python runtime behavior inside the main container
- external mode is better aligned with n8n production guidance

The installer generates and stores a shared runner auth token in `.env`, then starts:

- the main `n8n` container
- a `task-runners` sidecar

## Upgrades and Rollback

`upgrade.sh` checks for newer promoted releases, updates `.env`, redeploys, and rolls back automatically if health checks fail.

Typical manual rollback pattern:

1. set `N8N_IMAGE_VERSION` to the known good version
2. set `N8N_IMAGE_IDENTIFIER` to the known good digest or tag
3. run `docker compose up -d`

## Operational Notes

- promotion publishes trusted images to `ghcr.io/llody9977/secure-ci-deploy/n8n-trusted`
- new promotions should preserve upstream multi-arch manifests so ARM hosts can pull native images
- re-scan findings are surfaced as GitHub issues when a previously accepted image crosses the review threshold

## Troubleshooting

### Docker warns about amd64 emulation on ARM

This usually means the published trusted image is single-arch. Re-run the promotion workflow so GHCR republishes the trusted image as a multi-arch manifest.

### Install cannot resolve a digest from GitHub Release

If release metadata is missing or GitHub CLI is unavailable, the installer can fall back to a version tag. This works, but digest pinning is the preferred path.

### Provenance verification cannot run

Install and authenticate GitHub CLI:

```bash
gh auth login
gh auth status
```

Then rerun the installer so `gh attestation verify` can confirm the promoted artifact before deployment.
