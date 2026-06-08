from __future__ import annotations

from typing import Any, Dict, List


def cluster_devices(observations: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    clusters: List[List[Dict[str, Any]]] = []

    for obs in observations:
        placed = False

        for cluster in clusters:
            ref = cluster[0]

            if obs.get("manufacturer_prefix") and obs.get("manufacturer_prefix") == ref.get("manufacturer_prefix"):
                cluster.append(obs)
                placed = True
                break

            ref_uuids = set(ref.get("service_uuids") or [])
            obs_uuids = set(obs.get("service_uuids") or [])
            if ref_uuids and obs_uuids and ref_uuids.intersection(obs_uuids):
                cluster.append(obs)
                placed = True
                break

            if str(obs.get("mac_prefix") or "")[:5] and str(obs.get("mac_prefix") or "")[:5] == str(ref.get("mac_prefix") or "")[:5]:
                cluster.append(obs)
                placed = True
                break

        if not placed:
            clusters.append([obs])

    return clusters
