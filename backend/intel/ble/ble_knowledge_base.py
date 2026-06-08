from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class BLEKnowledgeBase:
    def __init__(self, path: Optional[str] = None) -> None:
        default_path = Path(__file__).resolve().parents[2] / "config" / "ble_knowledge_base.yaml"
        self.path = Path(path) if path else default_path
        self.company_ids: Dict[str, str] = {}
        self.service_uuid_names: Dict[str, str] = {}
        self.product_signatures: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        payload = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        self.company_ids = {
            str(key).upper(): str(value)
            for key, value in (payload.get("company_ids") or {}).items()
            if value
        }
        self.service_uuid_names = {
            str(key).upper(): str(value)
            for key, value in (payload.get("service_uuid_names") or {}).items()
            if value
        }
        self.product_signatures = list(payload.get("product_signatures") or [])

    def company_name(self, company_id: Optional[str]) -> Optional[str]:
        if not company_id:
            return None
        return self.company_ids.get(str(company_id).upper())

    def service_name(self, service_uuid: Optional[str]) -> Optional[str]:
        if not service_uuid:
            return None
        return self.service_uuid_names.get(str(service_uuid).upper())

    def match_product(self, parsed: Dict[str, Any], adv_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        manufacturer_id = str(parsed.get("manufacturer_id") or adv_data.get("manufacturer_id") or "").upper()
        service_uuids = {
            str(uuid).upper()
            for uuid in (
                parsed.get("service_uuids")
                or adv_data.get("service_uuids")
                or []
            )
        }
        service_data_keys = {
            str(key).upper()
            for key in (
                parsed.get("service_data")
                or adv_data.get("service_data")
                or {}
            ).keys()
        }
        name = str(parsed.get("device_name") or adv_data.get("device_name") or "").lower()
        appearance = parsed.get("appearance") or adv_data.get("appearance")

        best: Optional[Dict[str, Any]] = None
        for signature in self.product_signatures:
            match = signature.get("match") or {}
            if not self._signature_matches(
                match,
                manufacturer_id=manufacturer_id,
                service_uuids=service_uuids,
                service_data_keys=service_data_keys,
                name=name,
                appearance=appearance,
            ):
                continue
            candidate = {
                "label": signature.get("label"),
                "vendor": signature.get("vendor"),
                "product_category": signature.get("product_category"),
                "rf_device_class": signature.get("rf_device_class"),
                "role": signature.get("role"),
                "confidence": float(signature.get("confidence") or 0.75),
            }
            if best is None or candidate["confidence"] > best["confidence"]:
                best = candidate
        return best

    def _signature_matches(
        self,
        match: Dict[str, Any],
        *,
        manufacturer_id: str,
        service_uuids: set[str],
        service_data_keys: set[str],
        name: str,
        appearance: Any,
    ) -> bool:
        manufacturer_ids = {str(item).upper() for item in (match.get("manufacturer_id") or [])}
        if manufacturer_ids and manufacturer_id not in manufacturer_ids:
            return False

        service_uuid_any = {str(item).upper() for item in (match.get("service_uuid_any") or [])}
        if service_uuid_any and not (service_uuid_any & service_uuids):
            return False

        service_data_uuid_any = {str(item).upper() for item in (match.get("service_data_uuid_any") or [])}
        if service_data_uuid_any and not (service_data_uuid_any & service_data_keys):
            return False

        name_contains = [str(item).lower() for item in (match.get("name_contains") or [])]
        if name_contains and not any(token in name for token in name_contains):
            return False

        appearance_any = set(match.get("appearance_any") or [])
        if appearance_any and appearance not in appearance_any:
            return False

        return True
