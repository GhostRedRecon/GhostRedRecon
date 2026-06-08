from __future__ import annotations

import os
import sys
from pathlib import Path


def _bootstrap_system_site_packages() -> None:
    candidates = [
        "/usr/lib/python3/dist-packages",
        f"/usr/local/lib/python{sys.version_info.major}.{sys.version_info.minor}/dist-packages",
        f"/usr/lib/python{sys.version_info.major}/dist-packages",
    ]
    extra_paths = []
    try:
        for entry in os.environ.get("PYTHONPATH", "").split(":"):
            entry = entry.strip()
            if entry:
                extra_paths.append(entry)
    except Exception:
        extra_paths = []

    for candidate in [*extra_paths, *candidates]:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.exists():
            continue
        if str(path) in sys.path:
            continue
        sys.path.append(str(path))


_bootstrap_system_site_packages()
