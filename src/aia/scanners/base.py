"""Base scanner interface."""
from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator
from ..models import Agent, Credential, TrustRelationship, Finding, Framework

SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".git", ".tox",
    "dist", "build", ".eggs", ".mypy_cache", ".pytest_cache",
    "site-packages",
    # Large non-project directories commonly found in home dirs
    "Library", "Applications", "Movies", "Music", "Photos", "Pictures",
    "Downloads", ".Trash", ".cache", ".npm", ".cargo", ".rustup",
    ".local", ".docker", ".kube", ".gradle", ".m2", ".gem",
    "go", ".nvm", ".pyenv", ".rbenv", "anaconda3", "miniconda3",
    ".cocoapods", "Pods", ".android", ".flutter",
}

# Paths that are part of AIA itself (scanners/analyzers) should never be scanned
# as agent deployments. Resolved at import time.
_AIA_PACKAGE_DIR = str(Path(__file__).resolve().parent.parent)


def safe_rglob(path: Path, pattern: str, max_depth: int = 6, _depth: int = 0) -> Iterator[Path]:
    """Like Path.rglob but skips node_modules, .venv, .git, and AIA's own source.
    
    Args:
        path: Directory or file to scan.
        pattern: Glob pattern to match files.
        max_depth: Maximum directory recursion depth (default 6).
    """
    if path.is_file():
        if path.match(pattern) and not _is_aia_source(path):
            yield path
        return
    if _depth >= max_depth:
        return
    try:
        entries = list(path.iterdir())
    except PermissionError:
        return
    for item in entries:
        try:
            if item.is_dir():
                if item.name in SKIP_DIRS:
                    continue
                # Skip AIA's own package directory
                if str(item.resolve()).startswith(_AIA_PACKAGE_DIR):
                    continue
                yield from safe_rglob(item, pattern, max_depth, _depth + 1)
            elif item.match(pattern) and not _is_aia_source(item):
                yield item
        except PermissionError:
            continue


def _is_aia_source(path: Path) -> bool:
    """Check if a file is part of AIA's own source code."""
    try:
        return str(path.resolve()).startswith(_AIA_PACKAGE_DIR)
    except (OSError, ValueError):
        return False


def is_broad_scan(path: Path) -> bool:
    """Check if the scan path is a broad directory (home dir or root).
    
    When True, source-code scanners (Python file pattern matching) should
    skip rglob and only check known config paths. Config-based scanners
    (MCP, OpenClaw) use hardcoded paths and are unaffected.
    """
    try:
        resolved = path.resolve()
        return resolved == Path.home() or resolved == Path("/")
    except (OSError, ValueError):
        return False


class BaseScanner(ABC):
    """Base class for framework-specific scanners."""

    framework: Framework
    # If True, this scanner checks known config file paths directly
    # and does not need to rglob. Safe for broad (home dir) scans.
    config_based: bool = False

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """Return True if this framework is detected at the given path."""
        ...

    @abstractmethod
    def scan(self, path: Path) -> tuple[
        list[Agent],
        list[Credential],
        list[TrustRelationship],
        list[Finding],
    ]:
        """Scan the path and return discovered agents, credentials, trust relationships, and findings."""
        ...
