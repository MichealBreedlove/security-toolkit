# Security Toolkit

Security utilities for infrastructure defense: secret scanning, credential hygiene, log analysis, and network audit scripts.

Built for use across a 4-node homelab cluster. Part of the infrastructure documented at [michealbreedlove.com](https://michealbreedlove.com).

---

## Overview

A collection of security-focused scripts and tools used to maintain security posture across homelab infrastructure. These tools enforce credential hygiene, detect configuration drift, and provide visibility into network and service state.

---

## Tools

### Secret Scanning

CI-integrated secret detection scanning for 11 credential patterns across all repository commits.

- Regex-based pattern matching (AWS keys, GitHub PATs, private keys, API tokens, etc.)
- Runs as a GitHub Actions gate on every push
- Zero false positives since deployment

### Credential Sanitization

Pre-commit sanitization scripts that strip sensitive values from infrastructure state before it enters version control.

- Platform-specific: Bash (Linux) and PowerShell (Windows)
- Handles: API keys, tokens, private keys, database URIs, file paths
- Integrated into the daily backup pipeline

### Network Audit

Scripts for verifying network segmentation, firewall rules, and service exposure.

- VLAN boundary verification
- Port scan validation against expected service map
- OPNsense rule export and diff

### Log Analysis

Lightweight log parsing utilities for identifying anomalies in system and service logs.

- Pattern matching for auth failures, privilege escalation, unusual connections
- Structured output for review

---

## Security Practices Applied

| Practice | Implementation |
|---|---|
| Least privilege | SSH key-only auth, no shared credentials |
| Secret hygiene | 11-pattern CI scanning, pre-commit sanitization |
| Network segmentation | VLANs isolate IoT, infrastructure, personal devices |
| Monitoring | Service health checks, SLO-driven alerting |
| Incident response | Automated detection, tracking, postmortems |
| Access control | Per-node credential policies, no plaintext storage |

---

## Usage

```bash
# Run secret scan against a directory
./scan-secrets.sh /path/to/repo

# Sanitize a config file
./sanitize.sh --input config.yaml --output config.sanitized.yaml

# Audit network ports against expected services
./network-audit.sh --inventory services.yaml
```

---

## Links

- [Security Segmentation Details](https://michealbreedlove.com/proof.html)
- [AI Cluster Architecture](https://michealbreedlove.com/ai-cluster.html)
- [Portfolio](https://michealbreedlove.com)
- [Lab Repository](https://github.com/MichealBreedlove/Lab)
