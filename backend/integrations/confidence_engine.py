from __future__ import annotations

from typing import Dict, List


def compute_confidence(cluster: List[Dict[str, object]]) -> int:
    if not cluster:
        return 15
    score = 0
    ref = cluster[0]

    if ref.get("company_id") not in {None, "", 0, "0"}:
        score += 20
    if ref.get("service_uuids"):
        score += 20
    if ref.get("manufacturer_prefix"):
        score += 20
    if len(cluster) > 1:
        score += 20
    if ref.get("connectable"):
        score += 10
    name = str(ref.get("name") or "").strip()
    if name and "unknown" not in name.lower():
        score += 10

    return max(15, min(score, 95))
