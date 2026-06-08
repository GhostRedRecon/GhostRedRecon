from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import json


ROOT_DIR = Path(__file__).resolve().parents[2]
PROJECT_CONFIG_PATH = ROOT_DIR / "config" / "project.config.json"


@lru_cache(maxsize=1)
def load_project_config() -> dict:
    if not PROJECT_CONFIG_PATH.exists():
        return {}
    return json.loads(PROJECT_CONFIG_PATH.read_text(encoding="utf-8"))


def get_project_config() -> dict:
    return load_project_config()
