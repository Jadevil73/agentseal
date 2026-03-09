# agentseal/skill_scanner.py
"""
Skill Scanner — orchestrates layered threat detection for skill files.

Scans SKILL.md, .cursorrules, CLAUDE.md, and other agent instruction files
for malware, prompt injection, credential theft, and other threats.

Detection layers (applied in order, cheapest first):
  1. Blocklist check (SHA256 hash, instant)
  2. Static pattern matching (compiled regex, ~1ms)
  3. Semantic analysis (MiniLM-L6-v2 embeddings, ~50ms, optional)
"""

import hashlib
import sys
from pathlib import Path

import yaml

from agentseal.blocklist import Blocklist
from agentseal.detection.skill_detector import SkillDetector
from agentseal.guard_models import GuardVerdict, SkillFinding, SkillResult


class SkillScanner:
    """Scan skill files for malware, injection, and suspicious patterns."""

    def __init__(self, semantic: bool = True):
        self._detector = SkillDetector()
        self._blocklist = Blocklist()

        # Check if semantic analysis is available
        self._semantic_available = False
        if semantic:
            try:
                from agentseal.detection.semantic import compute_semantic_similarity  # noqa: F401
                self._semantic_available = True
            except ImportError:
                print(
                    "  \033[90mSemantic detection not available. "
                    "Install with: pip install agentseal[semantic]\033[0m",
                    file=sys.stderr,
                )

    # Max file size to scan (10 MB — anything larger is not a skill file)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def scan_file(self, path: Path) -> SkillResult:
        """Scan a single skill file."""
        path = Path(path)
        name = _extract_skill_name(path)

        try:
            file_size = path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                return SkillResult(
                    name=name,
                    path=str(path),
                    verdict=GuardVerdict.ERROR,
                    findings=[SkillFinding(
                        code="SKILL-ERR",
                        title="File too large",
                        description=f"File is {file_size // 1024 // 1024}MB, max is 10MB.",
                        severity="low",
                        evidence="",
                        remediation="Skill files should be small text files.",
                    )],
                )

            # Read raw bytes for accurate hash, then decode for analysis
            raw_bytes = path.read_bytes()
            sha256 = hashlib.sha256(raw_bytes).hexdigest()
            content = raw_bytes.decode("utf-8", errors="replace")
        except OSError as e:
            return SkillResult(
                name=name,
                path=str(path),
                verdict=GuardVerdict.ERROR,
                findings=[SkillFinding(
                    code="SKILL-ERR",
                    title="Could not read file",
                    description=str(e),
                    severity="low",
                    evidence="",
                    remediation="Check file permissions.",
                )],
            )

        if not content.strip():
            return SkillResult(name=name, path=str(path), verdict=GuardVerdict.SAFE)

        # Layer 1: Blocklist check
        if self._blocklist.is_blocked(sha256):
            return SkillResult(
                name=name,
                path=str(path),
                verdict=GuardVerdict.DANGER,
                findings=[SkillFinding(
                    code="SKILL-000",
                    title="Known malicious skill",
                    description="This skill matches a known malware hash in the AgentSeal threat database.",
                    severity="critical",
                    evidence=f"SHA256: {sha256}",
                    remediation="Remove this skill immediately and rotate all credentials.",
                )],
                blocklist_match=True,
                sha256=sha256,
            )

        # Layer 2: Static pattern matching
        findings = self._detector.scan_patterns(content)

        # Layer 3: Semantic analysis (if available and no critical patterns found)
        if self._semantic_available:
            semantic_findings = self._detector.scan_semantic(content)
            # Only add semantic findings for codes not already covered by patterns
            existing_codes = {f.code for f in findings}
            for sf in semantic_findings:
                if sf.code not in existing_codes:
                    findings.append(sf)

        verdict = _compute_verdict(findings)

        return SkillResult(
            name=name,
            path=str(path),
            verdict=verdict,
            findings=findings,
            sha256=sha256,
        )

    def scan_paths(self, paths: list[Path]) -> list[SkillResult]:
        """Scan a list of skill file paths."""
        results = []
        for path in paths:
            results.append(self.scan_file(path))
        return results


def _extract_skill_name(path: Path) -> str:
    """Extract skill name from YAML frontmatter or filename."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path.stem

    # Try YAML frontmatter (SKILL.md format: ---\nname: foo\n---\n...)
    if content.startswith("---\n") or content.startswith("---\r"):
        try:
            # Find closing --- that starts on its own line
            end = content.index("\n---", 3)
            frontmatter = yaml.safe_load(content[4:end])
            if isinstance(frontmatter, dict) and "name" in frontmatter:
                name_val = str(frontmatter["name"])[:200]  # Limit name length
                return name_val
        except (ValueError, yaml.YAMLError):
            pass

    # If file is named SKILL.md, use parent directory name
    if path.name.lower() == "skill.md":
        return path.parent.name

    # Otherwise use filename without extension
    return path.stem


def _compute_verdict(findings: list[SkillFinding]) -> GuardVerdict:
    """Determine verdict from findings. Worst severity wins."""
    if not findings:
        return GuardVerdict.SAFE
    if any(f.severity == "critical" for f in findings):
        return GuardVerdict.DANGER
    if any(f.severity in ("high", "medium") for f in findings):
        return GuardVerdict.WARNING
    return GuardVerdict.SAFE
