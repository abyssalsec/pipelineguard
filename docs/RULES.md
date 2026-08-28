# PipelineGuard Rule Catalog

PipelineGuard v1 includes 17 native security rules across five built-in analyzers.

## Docker

| Rule | Severity | Description |
| --- | --- | --- |
| `docker.root-user` | HIGH | Final container stage executes as root or does not explicitly switch to a non-root user |
| `docker.unpinned-base-image` | MEDIUM | Docker base image is not pinned to an explicit version or immutable digest |

## GitHub Actions

| Rule | Severity | Description |
| --- | --- | --- |
| `github-actions.write-all-permissions` | HIGH | Workflow grants `write-all` permissions instead of using least privilege |
| `github-actions.unpinned-action` | MEDIUM | Third-party GitHub Action is not pinned to a full commit SHA |
| `github-actions.pull-request-target` | MEDIUM | Workflow uses `pull_request_target` and requires additional review for untrusted code execution risks |

## Secrets

| Rule | Severity | Description |
| --- | --- | --- |
| `secrets.aws-access-key` | CRITICAL | Potential AWS access key detected |
| `secrets.github-token` | CRITICAL | Potential GitHub token detected |
| `secrets.private-key` | CRITICAL | Private key material detected |

PipelineGuard redacts secret values before adding them to findings.

Detected credentials should still be considered compromised if they were committed to source control and should be rotated if they are real.

## Terraform

| Rule | Severity | Description |
| --- | --- | --- |
| `terraform.world-open-ipv4` | HIGH | Terraform configuration contains unrestricted IPv4 exposure through `0.0.0.0/0` |
| `terraform.world-open-ipv6` | HIGH | Terraform configuration contains unrestricted IPv6 exposure through `::/0` |
| `terraform.public-ip` | MEDIUM | Terraform configuration explicitly enables public IP association |
| `terraform.public-read-acl` | CRITICAL | Object storage is configured with a public-read ACL |

## Kubernetes

| Rule | Severity | Description |
| --- | --- | --- |
| `kubernetes.privileged-container` | CRITICAL | Container runs with `privileged: true` |
| `kubernetes.host-network` | HIGH | Workload uses the host network namespace |
| `kubernetes.host-pid` | HIGH | Workload uses the host PID namespace |
| `kubernetes.run-as-non-root` | MEDIUM | Non-root execution is not enforced at pod or container level |
| `kubernetes.unpinned-image` | MEDIUM | Container image is not pinned to an explicit version or immutable digest |

## External Provider Findings

Trivy vulnerability results are normalized into PipelineGuard rule IDs:

```text
dependencies.vulnerability.critical
dependencies.vulnerability.high
dependencies.vulnerability.medium
dependencies.vulnerability.low
dependencies.vulnerability.unknown
```

These findings pass through the same policy engine as native PipelineGuard findings.

Default recommended treatment:

| Rule | Recommended Action |
| --- | --- |
| `dependencies.vulnerability.critical` | BLOCK |
| `dependencies.vulnerability.high` | BLOCK |
| `dependencies.vulnerability.medium` | WARN |
| `dependencies.vulnerability.low` | ALLOW |
| `dependencies.vulnerability.unknown` | WARN |

## Policy Evaluation

PipelineGuard first checks whether a finding has an explicit rule override.

Example:

```yaml
version: 1

gate:
  block_severities:
    - critical
    - high

  warn_severities:
    - medium

rules:
  docker.root-user: block
  docker.unpinned-base-image: warn

  github-actions.write-all-permissions: block
  github-actions.unpinned-action: warn

  terraform.world-open-ipv4: block

  kubernetes.privileged-container: block

  dependencies.vulnerability.critical: block
  dependencies.vulnerability.high: block
  dependencies.vulnerability.medium: warn
```

Supported actions:

```text
allow
warn
block
```

An explicit rule action overrides the default severity-based gate.

For example:

```yaml
rules:
  docker.root-user: warn
```

will downgrade `docker.root-user` from the default HIGH-severity `BLOCK` behavior to `WARN`.

Likewise:

```yaml
rules:
  dependencies.vulnerability.medium: block
```

can make MEDIUM dependency vulnerabilities block a pipeline even though the default MEDIUM policy is `WARN`.

## Default Severity Policy

Without an explicit rule override, PipelineGuard evaluates findings by severity.

Default configuration:

```yaml
gate:
  block_severities:
    - critical
    - high

  warn_severities:
    - medium
```

This produces:

| Severity | Default Action |
| --- | --- |
| CRITICAL | BLOCK |
| HIGH | BLOCK |
| MEDIUM | WARN |
| LOW | ALLOW |
| INFO | ALLOW |

## Decision Model

A scan produces one final policy decision:

```text
ALLOW
WARN
BLOCK
```

Decision precedence is:

```text
BLOCK > WARN > ALLOW
```

Therefore:

- if at least one finding evaluates to `BLOCK`, the final result is `BLOCK`
- otherwise, if at least one finding evaluates to `WARN`, the final result is `WARN`
- otherwise the final result is `ALLOW`

## Exit Codes

PipelineGuard maps the final execution state to deterministic exit codes:

| Exit Code | Meaning |
| ---: | --- |
| `0` | scan completed and final decision is ALLOW or WARN |
| `1` | PipelineGuard execution or provider error |
| `2` | scan completed and final decision is BLOCK |

This behavior allows PipelineGuard to be used directly as a CI/CD security gate.
