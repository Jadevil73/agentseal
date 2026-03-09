# agentseal/mcp_checker.py
"""
MCP Config Checker — static analysis of MCP server configurations.

Reads JSON config files and flags dangerous permissions, exposed credentials,
and unsigned binaries. Does NOT connect to MCP servers (that's Phase 2).
Fast and safe: no network, no process spawning (except macOS codesign check).
"""

import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional

from agentseal.guard_models import GuardVerdict, MCPFinding, MCPServerResult


# ═══════════════════════════════════════════════════════════════════════
# SENSITIVE PATH DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════

_SENSITIVE_PATHS: list[tuple[str, str]] = [
    (".ssh", "SSH private keys"),
    (".aws", "AWS credentials"),
    (".gnupg", "GPG private keys"),
    (".config/gh", "GitHub CLI credentials"),
    (".npmrc", "NPM auth tokens"),
    (".pypirc", "PyPI credentials"),
    (".docker", "Docker credentials"),
    (".kube", "Kubernetes credentials"),
    (".netrc", "Network login credentials"),
    (".bitcoin", "Bitcoin wallet"),
    (".ethereum", "Ethereum wallet"),
    ("Library/Keychains", "macOS Keychain"),
    (".gitconfig", "Git credentials"),
    (".clawdbot/.env", "OpenClaw credentials"),
    (".openclaw/.env", "OpenClaw credentials"),
]

_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-(?:proj-)?[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"sk_live_[a-zA-Z0-9]+"), "Stripe live key"),
    (re.compile(r"sk_test_[a-zA-Z0-9]+"), "Stripe test key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"xoxb-[a-zA-Z0-9-]+"), "Slack bot token"),
    (re.compile(r"xoxp-[a-zA-Z0-9-]+"), "Slack user token"),
    (re.compile(r"glpat-[a-zA-Z0-9_-]{20,}"), "GitLab personal token"),
    (re.compile(r"SG\.[a-zA-Z0-9_-]{22,}"), "SendGrid API key"),
]


class MCPConfigChecker:
    """Static analysis of MCP server configurations."""

    def check(self, server: dict) -> MCPServerResult:
        """Check a single MCP server config dict for security issues."""
        name = server.get("name", "unknown")
        command = server.get("command", "")
        args = server.get("args", [])
        env = server.get("env", {})
        source = server.get("source_file", "")

        findings: list[MCPFinding] = []

        findings.extend(self._check_sensitive_paths(name, args))
        findings.extend(self._check_env_credentials(name, env))
        findings.extend(self._check_broad_access(name, args))
        findings.extend(self._check_binary_signing(name, command))
        findings.extend(self._check_insecure_urls(name, args, env))

        verdict = _verdict_from_findings(findings)

        return MCPServerResult(
            name=name,
            command=command,
            source_file=source,
            verdict=verdict,
            findings=findings,
        )

    def check_all(self, servers: list[dict]) -> list[MCPServerResult]:
        """Check multiple MCP server configs."""
        return [self.check(s) for s in servers]

    # ── Individual checks ──────────────────────────────────────────────

    def _check_sensitive_paths(self, name: str, args: list) -> list[MCPFinding]:
        """MCP-001: Check if server has access to sensitive directories."""
        findings = []
        home = str(Path.home())

        for arg in args:
            if not isinstance(arg, str):
                continue
            # Expand leading ~ only (not ~ in middle of path)
            expanded = arg if not arg.startswith("~") else home + arg[1:]
            for sensitive_suffix, description in _SENSITIVE_PATHS:
                sensitive_full = os.path.join(home, sensitive_suffix)
                if sensitive_full in expanded or sensitive_suffix in arg:
                    findings.append(MCPFinding(
                        code="MCP-001",
                        title=f"Access to {description}",
                        description=f"MCP server '{name}' has filesystem access to "
                                    f"{sensitive_suffix} ({description}). "
                                    f"This is a critical security risk.",
                        severity="critical",
                        remediation=f"Restrict '{name}' MCP server: remove {sensitive_suffix} "
                                    f"from allowed paths. It does not need access to {description}.",
                    ))
                    break  # One finding per sensitive path per server

        return findings

    def _check_env_credentials(self, name: str, env: dict) -> list[MCPFinding]:
        """MCP-002: Check for hardcoded credentials in environment variables."""
        findings = []

        for env_key, env_value in env.items():
            if not isinstance(env_value, str):
                continue
            # Skip env var references like ${VAR} or $VAR
            if env_value.startswith("${") or env_value.startswith("$"):
                continue

            for pattern, cred_type in _CREDENTIAL_PATTERNS:
                if pattern.search(env_value):
                    # Redact the value for display
                    redacted = env_value[:6] + "..." + env_value[-4:] if len(env_value) > 14 else "***"
                    findings.append(MCPFinding(
                        code="MCP-002",
                        title=f"Hardcoded {cred_type}",
                        description=f"MCP server '{name}' has a hardcoded {cred_type} "
                                    f"in env var {env_key} ({redacted}). "
                                    f"Credentials should not be stored in config files.",
                        severity="high",
                        remediation=f"Move {env_key} for '{name}' to a secrets manager "
                                    f"or environment variable. Do not store API keys in MCP config files.",
                    ))
                    break  # One finding per env var

        return findings

    def _check_broad_access(self, name: str, args: list) -> list[MCPFinding]:
        """MCP-003: Check for overly broad filesystem access."""
        findings = []
        home = str(Path.home())

        for arg in args:
            if not isinstance(arg, str):
                continue
            expanded = arg.replace("~", home)
            # Root-level access
            if expanded == "/" or expanded == home or arg == "~" or arg == "/":
                findings.append(MCPFinding(
                    code="MCP-003",
                    title="Overly broad filesystem access",
                    description=f"MCP server '{name}' has access to the entire "
                                f"{'home directory' if expanded == home else 'filesystem'}. "
                                f"This grants access to all files including credentials.",
                    severity="high",
                    remediation=f"Restrict '{name}' to specific project directories only. "
                                f"Example: /Users/you/projects/my-app instead of ~ or /",
                ))
                break

        return findings

    def _check_binary_signing(self, name: str, command: str) -> list[MCPFinding]:
        """MCP-004: Check if MCP server binary is code-signed (macOS only)."""
        if platform.system() != "Darwin":
            return []

        if not command:
            return []

        # Only check absolute paths to binaries (not npx, uvx, etc.)
        binary_path = Path(command)
        if not binary_path.is_absolute() or not binary_path.is_file():
            return []

        try:
            result = subprocess.run(
                ["codesign", "-v", str(binary_path)],
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                return [MCPFinding(
                    code="MCP-004",
                    title="Unsigned binary",
                    description=f"MCP server '{name}' binary at {command} "
                                f"is not code-signed. This could indicate a "
                                f"tampered or untrusted binary.",
                    severity="medium",
                    remediation=f"Verify the source of '{name}' binary. "
                                f"Consider using an npm/pip package instead.",
                )]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return []

    def _check_insecure_urls(self, name: str, args: list, env: dict) -> list[MCPFinding]:
        """MCP-005: Check for HTTP (not HTTPS) endpoints."""
        findings = []
        http_pattern = re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])")

        all_values = [a for a in args if isinstance(a, str)]
        all_values.extend(v for v in env.values() if isinstance(v, str))

        for value in all_values:
            if http_pattern.search(value):
                findings.append(MCPFinding(
                    code="MCP-005",
                    title="Insecure HTTP connection",
                    description=f"MCP server '{name}' uses an unencrypted HTTP connection. "
                                f"Data sent to this server could be intercepted.",
                    severity="medium",
                    remediation=f"Use HTTPS for '{name}' MCP server connections.",
                ))
                break  # One finding is enough

        return findings


def _verdict_from_findings(findings: list[MCPFinding]) -> GuardVerdict:
    """Determine verdict from findings."""
    if not findings:
        return GuardVerdict.SAFE
    if any(f.severity == "critical" for f in findings):
        return GuardVerdict.DANGER
    if any(f.severity in ("high", "medium") for f in findings):
        return GuardVerdict.WARNING
    return GuardVerdict.SAFE
