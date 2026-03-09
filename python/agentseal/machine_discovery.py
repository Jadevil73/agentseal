# agentseal/machine_discovery.py
"""
Machine-level agent discovery — finds ALL AI agents, MCP servers, and skills
installed on the user's machine by checking well-known config paths.

This is different from discovery.py which scans a project directory.
machine_discovery.py scans the entire machine's well-known locations.
"""

import json
import os
import platform
import re
from pathlib import Path
from typing import Optional

from agentseal.guard_models import AgentConfigResult


def _home() -> Path:
    return Path.home()


def _get_well_known_configs() -> list[dict]:
    """Return all known agent config locations for the current platform."""
    home = _home()
    system = platform.system()

    # Windows APPDATA (may not exist on other platforms)
    appdata = Path(os.environ.get("APPDATA", "")) if system == "Windows" else None

    configs = [
        {
            "name": "Claude Desktop",
            "agent_type": "claude-desktop",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
                "Windows": appdata / "Claude" / "claude_desktop_config.json" if appdata else None,
                "Linux": home / ".config" / "claude" / "claude_desktop_config.json",
            },
            "mcp_key": "mcpServers",
        },
        {
            "name": "Claude Code",
            "agent_type": "claude-code",
            "paths": {"all": home / ".claude" / "settings.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Cursor",
            "agent_type": "cursor",
            "paths": {"all": home / ".cursor" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Windsurf",
            "agent_type": "windsurf",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Windsurf" / "User" / "globalStorage" / "mcp.json",
                "Windows": appdata / "Windsurf" / "User" / "globalStorage" / "mcp.json" if appdata else None,
                "Linux": home / ".config" / "Windsurf" / "User" / "globalStorage" / "mcp.json",
            },
            "mcp_key": "servers",
        },
        {
            "name": "VS Code",
            "agent_type": "vscode",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "mcp.json",
                "Windows": appdata / "Code" / "User" / "globalStorage" / "mcp.json" if appdata else None,
                "Linux": home / ".config" / "Code" / "User" / "globalStorage" / "mcp.json",
            },
            "mcp_key": "servers",
        },
        {
            "name": "Gemini CLI",
            "agent_type": "gemini-cli",
            "paths": {"all": home / ".gemini" / "settings.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Codex CLI",
            "agent_type": "codex",
            "paths": {"all": home / ".codex" / "config.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "OpenClaw",
            "agent_type": "openclaw",
            "paths": {"all": home / ".openclaw" / "config.json"},
            "mcp_key": "mcpServers",
            "skills_dir_key": "skillsPath",
        },
        {
            "name": "Kiro",
            "agent_type": "kiro",
            "paths": {"all": home / ".kiro" / "settings.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "OpenCode",
            "agent_type": "opencode",
            "paths": {"all": home / ".opencode" / "config.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Continue",
            "agent_type": "continue",
            "paths": {"all": home / ".continue" / "config.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Aider",
            "agent_type": "aider",
            "paths": {"all": home / ".aider.conf.yml"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Roo Code",
            "agent_type": "roo-code",
            "paths": {"all": home / ".roo" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        {
            "name": "Cline",
            "agent_type": "cline",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
                "Linux": home / ".config" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            },
            "mcp_key": "mcpServers",
        },
        {
            "name": "Zed",
            "agent_type": "zed",
            "paths": {
                "Darwin": home / ".config" / "zed" / "settings.json",
                "Linux": home / ".config" / "zed" / "settings.json",
            },
            "mcp_key": "context_servers",
        },
        {
            "name": "Amp",
            "agent_type": "amp",
            "paths": {"all": home / ".amp" / "settings.json"},
            "mcp_key": "mcpServers",
        },
    ]

    return configs


# Well-known skill directories to scan
_SKILL_DIRS = [
    ".openclaw/workspace/skills",
    ".openclaw/skills",
    ".clawdbot/skills",
    ".cursor/rules",
    ".roo/rules",
    ".continue/rules",
    ".trae/rules",
]

# Well-known skill files (single files that act as agent instructions)
_SKILL_FILES = [
    ".cursorrules",
    ".claude/CLAUDE.md",
    ".github/copilot-instructions.md",
]

# Max file size for skill scanning (10 MB — anything larger is not a skill file)
_MAX_SKILL_SIZE = 10 * 1024 * 1024


def _strip_json_comments(text: str) -> str:
    """Strip // and /* */ comments from JSON (for VS Code-style configs)."""
    # Remove single-line comments (not inside strings — simplified approach)
    text = re.sub(r'(?<!["\'])//.*?$', '', text, flags=re.MULTILINE)
    # Remove multi-line comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return text


def scan_machine() -> tuple[
    list[AgentConfigResult],  # Which agents are installed
    list[dict],               # All MCP server configs found
    list[Path],               # All skill files found
]:
    """Discover all AI agents, MCP servers, and skills on this machine.

    Returns:
        agents: List of discovered agent configurations
        mcp_servers: List of MCP server config dicts (with source_file and agent_type added)
        skill_paths: List of Path objects pointing to skill files
    """
    system = platform.system()
    home = _home()
    configs = _get_well_known_configs()

    agent_results: list[AgentConfigResult] = []
    all_mcp_servers: list[dict] = []
    all_skill_paths: list[Path] = []

    for cfg in configs:
        # Resolve path for current platform
        path = cfg["paths"].get(system) or cfg["paths"].get("all")
        if path is None:
            continue

        path = Path(path).expanduser()

        if not path.is_file():
            agent_results.append(AgentConfigResult(
                name=cfg["name"],
                config_path=str(path),
                agent_type=cfg["agent_type"],
                mcp_servers=0,
                skills_count=0,
                status="not_installed",
            ))
            continue

        # Parse config file
        try:
            raw_text = path.read_text(encoding="utf-8")
            cleaned = _strip_json_comments(raw_text)
            data = json.loads(cleaned)
        except (json.JSONDecodeError, OSError):
            agent_results.append(AgentConfigResult(
                name=cfg["name"],
                config_path=str(path),
                agent_type=cfg["agent_type"],
                mcp_servers=0,
                skills_count=0,
                status="error",
            ))
            continue

        # Extract MCP servers
        mcp_key = cfg.get("mcp_key", "mcpServers")
        mcp_servers = data.get(mcp_key, {})
        server_count = 0

        if isinstance(mcp_servers, dict):
            for srv_name, srv_cfg in mcp_servers.items():
                if not isinstance(srv_cfg, dict):
                    continue
                all_mcp_servers.append({
                    "name": srv_name,
                    "source_file": str(path),
                    "agent_type": cfg["agent_type"],
                    **srv_cfg,
                })
                server_count += 1

        # Extract skills path if configured (e.g., OpenClaw)
        skills_key = cfg.get("skills_dir_key")
        if skills_key and skills_key in data:
            sp = Path(str(data[skills_key])).expanduser()
            # Only scan if it's a real directory (not a symlink to avoid traversal)
            if sp.is_dir() and not sp.is_symlink():
                try:
                    for f in sp.rglob("SKILL.md"):
                        if f.is_file() and not f.is_symlink():
                            all_skill_paths.append(f)
                except OSError:
                    pass

        agent_results.append(AgentConfigResult(
            name=cfg["name"],
            config_path=str(path),
            agent_type=cfg["agent_type"],
            mcp_servers=server_count,
            skills_count=0,  # Updated later from skill scan
            status="found",
        ))

    # Check well-known skill directories
    seen_skill_paths: set[str] = set()

    for skill_dir_rel in _SKILL_DIRS:
        skill_dir = home / skill_dir_rel
        if skill_dir.is_dir() and not skill_dir.is_symlink():
            for pattern in ["SKILL.md", "*.md"]:
                try:
                    for f in skill_dir.rglob(pattern):
                        # Skip symlinks (prevent loops), oversized files, non-files
                        if f.is_symlink() or not f.is_file():
                            continue
                        try:
                            if f.stat().st_size > _MAX_SKILL_SIZE:
                                continue
                        except OSError:
                            continue
                        resolved = str(f.resolve())
                        if resolved not in seen_skill_paths:
                            seen_skill_paths.add(resolved)
                            all_skill_paths.append(f)
                except OSError:
                    continue  # Permission denied or deleted mid-scan

    # Check well-known single skill files
    for skill_file_rel in _SKILL_FILES:
        skill_file = home / skill_file_rel
        if skill_file.is_file():
            resolved = str(skill_file.resolve())
            if resolved not in seen_skill_paths:
                seen_skill_paths.add(resolved)
                all_skill_paths.append(skill_file)

    # Check cwd for skill files (guard against deleted cwd)
    try:
        cwd = Path.cwd()
    except OSError:
        cwd = None

    if cwd:
        for cwd_file in [".cursorrules", "CLAUDE.md", ".github/copilot-instructions.md"]:
            candidate = cwd / cwd_file
            if candidate.is_file():
                resolved = str(candidate.resolve())
                if resolved not in seen_skill_paths:
                    seen_skill_paths.add(resolved)
                    all_skill_paths.append(candidate)

    # Deduplicate MCP servers by (name, command) tuple
    seen_servers: set[tuple[str, str]] = set()
    unique_servers: list[dict] = []
    for srv in all_mcp_servers:
        key = (srv.get("name", ""), srv.get("command", ""))
        if key not in seen_servers:
            seen_servers.add(key)
            unique_servers.append(srv)

    return agent_results, unique_servers, all_skill_paths
