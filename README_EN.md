# KubeGuard-Lite

**Language:** [简体中文](README.md) | **English**

**KubeGuard-Lite** is a Python-based static security scanner for Kubernetes YAML manifests. It identifies common configuration risks before deployment and provides structured findings for both developers and other security tools.

Version **0.2.0** introduces a versioned JSON scanning interface while retaining the existing human-readable CLI, Markdown/HTML reports, and limited YAML auto-fix capabilities.

> **Scope:** KubeGuard-Lite is a static configuration analysis component—not a Kubernetes admission controller, a live-cluster security platform, or a complete Kubernetes Schema / Pod Security Standards (PSS) compliance checker.

## Features

| Area | What it checks |
| --- | --- |
| **Workloads** | Pod and Deployment configurations, including regular containers and `initContainers`; host namespaces, `hostPath` volumes, service account token settings, image references, and resource limits. |
| **Container security** | Privileged mode, privilege escalation, root-user settings, read-only root filesystem, seccomp, and selected Linux capabilities. Findings distinguish explicitly risky settings from hardening gaps. |
| **RBAC** | Risky Role/ClusterRole permissions and bindings, wildcard permissions, sensitive resource access, and privilege-related verbs in supplied manifests. |
| **Service & Ingress** | Exposure-related Service types, sensitive ports, TLS/host configuration, and selected risky annotations. |
| **Reports & remediation** | Human-readable CLI output, Markdown/HTML reports, and limited Safe/Strict YAML fixes with safeguards for non-fixable findings. |
| **Machine integration** | JSON Contract v1 with normalized findings, resource coverage, skipped resources, and diagnostic information. |

See [Rule Reference](docs/rule-description.md) for the rules and their actual coverage.

## Quick Start

The lightweight scanning dependencies were verified with **Python 3.13.11 on Windows x64**. The scanner does not need a Kubernetes cluster, administrator privileges, Streamlit, or PySide6. The dependency lock has **not** been independently validated on Linux/macOS.

Clone the repository:

```bash
git clone https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner.git
cd kubeguard-lite-k8s-yaml-security-scanner
```

### Windows PowerShell

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-scan.txt
.venv\Scripts\python.exe cli.py scan examples/insecure
```

### Linux / macOS (source mode; dependency lock not yet platform-validated)

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-scan.txt
.venv/bin/python cli.py scan examples/insecure
```

The full Web/Desktop development dependencies are maintained separately in `requirements.txt`.

## Usage

### Human-readable scan

```bash
python cli.py scan examples/insecure
```

### Export reports

```bash
python cli.py report examples/insecure --format md --output reports/scan-report.md
python cli.py report examples/insecure --format html --output reports/scan-report.html
```

### Limited YAML auto-fix

```bash
python cli.py fix examples/insecure --mode safe --output fixed
```

Fixing is **a separate operation**; scanning does not modify input YAML. Review all modified manifests and the fix report before using them. Safe/Strict modes support only specific rules, and `auto_fixable` is not an authorization mechanism.

## JSON API for Tool Integration

Use the read-only machine interface to integrate KubeGuard-Lite with other tools:

```bash
python cli.py scan-json examples/insecure
```

The command writes **JSON to stdout**. Diagnostic text may be written to stderr; consumers should use the structured `diagnostics` field in JSON instead of parsing localized stderr text. It neither modifies the input nor connects to a Kubernetes cluster.

A **selection of fields** from a real sample result (not a complete response):

```json
{
  "schema_version": "1.0",
  "scanner_version": "0.2.0",
  "status": "COMPLETED",
  "resource_counts": {
    "total": 12,
    "scanned": 11,
    "skipped": 1
  },
  "finding_counts": {
    "HIGH": 16,
    "MEDIUM": 13,
    "LOW": 12,
    "UNKNOWN": 0,
    "total": 41
  }
}
```

The actual response also contains `findings`, `skipped_resources`, and `diagnostics`. Each normalized finding includes a rule ID, severity, resource identity, configuration path when available, and optional container identity and auto-fix metadata. Unreliable values remain `null` rather than being guessed.

### Scan status matters

| Status | Meaning | Exit code |
| --- | --- | --- |
| `COMPLETED` | All applicable targets within the supported scope were analyzed; findings may be present or absent. | `0` |
| `PARTIAL` | At least one target was analyzed, but some applicable resources were not covered. **Zero findings does not mean safe.** | `0` |
| `FAILED` | No usable analysis was completed, or the scan failed. | `1` |

Skipped resources carry explicit reasons, including `UNSUPPORTED_KIND`, `WINDOWS_LINUX_RULES_UNSUPPORTED`, and `OUT_OF_SCOPE`. An out-of-scope manifest (for example, a ConfigMap) does not by itself downgrade a completed scan to `PARTIAL`.

**Integration requirements:** validate `schema_version`, check both process exit code and `status`, respect partial coverage, and never treat an absent finding as proof of security.

For complete field definitions, compatibility rules, and error semantics, see **[JSON Contract v1](docs/json-contract-v1.md)**.

## Architecture and Integration

```text
Kubernetes YAML files / directory
              |
              v
      Manifest parsing
              |
              v
      Static rule scanners
     /         |         \
Workload     RBAC     Service/Ingress
     \         |         /
              v
       Scan findings
         /        \
        v          v
 Human CLI /      Versioned JSON
 reports/fixer       (scan-json)
                         |
                         v
              External integrations
```

KubeGuard-Lite is intended to remain an independent static scanning engine. **KubeGuard Fusion** is a separate project planned to consume its JSON output through a Go adapter; that adapter is not part of KubeGuard-Lite v0.2.0.

## Testing

The project includes regression and JSON contract tests using real scanning logic:

```bash
python -m unittest discover -s tests -v
```

For reproducible scans, keep the scanner revision and Python environment fixed. The `requirements-scan.txt` lock was verified on Python 3.13.11 / Windows x64; other environments require their own validation.

## Limitations

- **Static analysis only:** no image CVE scanning, live-cluster effective RBAC analysis, admission enforcement, or runtime threat detection.
- **Supported Workload kinds:** Pod and Deployment (including regular and init containers). Other workload controllers may be recorded as unsupported instead of scanned.
- **Primarily Linux-oriented:** the JSON interface skips explicitly Windows-targeted Pod/Deployment workload checks rather than presenting Linux-specific findings as valid Windows assessments. The legacy human-readable `scan` command does not offer equivalent complete OS filtering.
- **Not complete PSS / schema validation:** checks are targeted security heuristics, not exhaustive Kubernetes API validation or compliance certification.
- **Coverage-aware results:** `PARTIAL` or `FAILED` is not a clean security assessment. Even `COMPLETED` refers only to the scanner's documented checks.
- **Limited auto-fix:** not every finding can be fixed automatically. Manual review and authorization remain necessary.

## Releases

- **[v0.2.0 — Source / JSON API integration release](https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner/releases/tag/v0.2.0):** security-rule reliability improvements, init-container coverage, capabilities/seccomp checks, regression tests, and JSON Contract v1. No new v0.2.0 desktop binaries are included.
- **[v0.1.0 — Historical desktop release (Git tag `v.0.1.0`)](https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner/releases/tag/v.0.1.0):** Windows executable and Linux AppImage. These binaries belong to the older release and must not be treated as v0.2.0 builds.

See the [Changelog](CHANGELOG.md) and [all GitHub Releases](https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner/releases).

## License

Distributed under the [MIT License](LICENSE).
