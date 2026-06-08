# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/identity/mac_oui_resolver.py
# VERSION:      v1.0.0 (SIGINT VENDOR RESOLUTION ENGINE)
# UPDATED:      2026-03-24
# =============================================================================

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional


class MacOUIResolver:
    """
    MAC / OUI Resolver (SIGINT Layer)

    PURPOSE:
    --------
    Resolve device vendor from MAC address OUI (first 3 bytes)

    INPUT:
    ------
    MAC: AA:BB:CC:XX:XX:XX

    OUTPUT:
    -------
    vendor: Apple / Samsung / Unknown
    """

    VERSION = "1.0.0"

    def __init__(self):
        self.oui_db = self._load_oui_database()
        self.prefix_lengths = sorted({len(prefix) for prefix in self.oui_db.keys()}, reverse=True)

    # =========================================================================
    # PUBLIC API
    # =========================================================================
    COUNTRY_NAMES = {
        "US": "United States",
        "CN": "China",
        "KR": "South Korea",
        "JP": "Japan",
        "TW": "Taiwan",
        "DE": "Germany",
        "FR": "France",
        "CH": "Switzerland",
        "GB": "United Kingdom",
        "NL": "Netherlands",
        "CA": "Canada",
        "SE": "Sweden",
        "FI": "Finland",
        "IL": "Israel",
        "IN": "India",
        "VN": "Vietnam",
        "MY": "Malaysia",
        "SG": "Singapore",
        "PL": "Poland",
        "HU": "Hungary",
        "IE": "Ireland",
        "IT": "Italy",
        "ES": "Spain",
        "PT": "Portugal",
        "AU": "Australia",
        "NZ": "New Zealand",
        "BE": "Belgium",
        "AT": "Austria",
        "DK": "Denmark",
        "NO": "Norway",
        "MX": "Mexico",
        "BR": "Brazil",
        "HK": "Hong Kong",
        "MO": "Macau",
        "RU": "Russia",
        "UA": "Ukraine",
        "CZ": "Czech Republic",
        "RO": "Romania",
        "TR": "Turkey",
        "TH": "Thailand",
        "ID": "Indonesia",
        "PH": "Philippines",
        "ZA": "South Africa",
        "AE": "United Arab Emirates",
        "SA": "Saudi Arabia",
        "AR": "Argentina",
        "CL": "Chile",
        "CO": "Colombia",
        "LU": "Luxembourg",
        "SK": "Slovakia",
        "SI": "Slovenia",
        "LT": "Lithuania",
        "LV": "Latvia",
        "EE": "Estonia",
    }

    def resolve(self, mac: Optional[str]) -> Dict[str, Optional[str]]:

        if not mac:
            return self._empty()

        oui = self._extract_oui(mac)
        mac_prefix = self._normalize_mac(mac)

        if not oui or not mac_prefix:
            return self._empty()

        vendor_record = None
        matched_prefix = None
        for prefix_length in self.prefix_lengths:
            candidate = mac_prefix[:prefix_length]
            if candidate in self.oui_db:
                vendor_record = self.oui_db[candidate]
                matched_prefix = candidate
                break

        if not vendor_record:
            return {
                "vendor": None,
                "oui": oui,
                "country_code": None,
                "country": None,
                "country_source": None,
                "confidence": 0.0,
                "source": "oui_db"
            }

        return {
            "vendor": vendor_record.get("vendor"),
            "oui": self._format_prefix(matched_prefix or oui),
            "country_code": vendor_record.get("country_code"),
            "country": vendor_record.get("country"),
            "country_source": "IEEE OUI registration",
            "confidence": 0.9,
            "source": "oui_db"
        }

    # =========================================================================
    # INTERNAL
    # =========================================================================
    def _extract_oui(self, mac: str) -> Optional[str]:
        """
        Extract first 3 bytes of MAC
        """

        normalized = self._normalize_mac(mac)
        if not normalized or len(normalized) < 6:
            return None
        return self._format_prefix(normalized[:6])

    def _normalize_mac(self, mac: str) -> Optional[str]:
        try:
            normalized = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()
            if len(normalized) < 6:
                return None
            return normalized
        except Exception:
            return None

    @staticmethod
    def _format_prefix(prefix: str) -> str:
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(prefix or "")).upper()
        if not cleaned:
            return ""
        groups = [cleaned[index:index + 2] for index in range(0, len(cleaned), 2)]
        return ":".join(filter(None, groups))

    def _empty(self) -> Dict[str, Optional[str]]:
        return {
            "vendor": None,
            "oui": None,
            "country_code": None,
            "country": None,
            "country_source": None,
            "confidence": 0.0,
            "source": None
        }

    # =========================================================================
    # MINIMAL OUI DATABASE (EXPANDABLE)
    # =========================================================================
    def _country_name(self, country_code: str | None) -> Optional[str]:
        if not country_code:
            return None
        code = str(country_code).strip().upper()
        if not code:
            return None
        return self.COUNTRY_NAMES.get(code, code)

    def _load_oui_database(self) -> Dict[str, Dict[str, Optional[str]]]:
        db: Dict[str, Dict[str, Optional[str]]] = {}
        root = Path(__file__).resolve().parents[2] / "config" / "oui"
        for candidate in (
            root / "oui_full.txt",
            root / "oui.txt",
            root / "mam.txt",
            root / "oui36.txt",
        ):
            if not candidate.exists():
                continue
            try:
                lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
                index = 0
                while index < len(lines):
                    line = lines[index]
                    if "(hex)" not in line:
                        index += 1
                        continue
                    prefix, vendor = line.split("(hex)", 1)
                    normalized = re.sub(r"[^0-9A-Fa-f]", "", prefix).upper()
                    if len(normalized) != 6:
                        index += 1
                        continue
                    country_code = None
                    registration_prefix = normalized
                    lookahead = index + 1
                    while lookahead < len(lines):
                        candidate_line = lines[lookahead]
                        stripped = candidate_line.strip()
                        if not stripped:
                            break
                        if "(hex)" in candidate_line:
                            break
                        if "(base 16)" in candidate_line:
                            base_prefix = candidate_line.split("(base 16)", 1)[0].strip()
                            prefix_range = re.sub(r"[^0-9A-Fa-f-]", "", base_prefix).upper()
                            if "-" in prefix_range:
                                registration_prefix = prefix_range.split("-", 1)[0]
                            elif prefix_range:
                                registration_prefix = prefix_range
                        if len(stripped) == 2 and stripped.isalpha() and stripped.upper() == stripped:
                            country_code = stripped.upper()
                        lookahead += 1
                    db.setdefault(
                        registration_prefix,
                        {
                            "vendor": vendor.strip(),
                            "country_code": country_code,
                            "country": self._country_name(country_code),
                        },
                    )
                    index = lookahead
            except Exception:
                continue
        return db
