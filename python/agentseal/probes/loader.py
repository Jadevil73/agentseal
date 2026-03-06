# agentseal/probes/loader.py
"""
Custom probe loader - stub for future YAML/TOML probe definitions,
plus MCP probe loading.

Layer 2: imports from schemas.
"""

from pathlib import Path
from typing import Union

from agentseal.probes.mcp_tools import build_mcp_probes


def load_custom_probes(path: Union[str, Path]) -> list[dict]:
    """Load custom probes from a YAML or TOML file.

    Each probe dict must contain at minimum:
        probe_id: str
        category: str
        technique: str
        severity: Severity value string ("critical", "high", "medium", "low")
        payload: str or list[str] for multi-turn

    Injection probes must also include:
        canary: str

    Args:
        path: Path to a .yaml or .toml probe definition file.

    Returns:
        List of probe dicts ready for execution.

    Raises:
        NotImplementedError: Custom probe loading is not yet implemented.
    """
    raise NotImplementedError(
        "Custom probe loading is planned for a future release. "
        "See https://github.com/agentseal/agentseal for updates."
    )
