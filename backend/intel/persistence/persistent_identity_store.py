# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/persistence/persistent_identity_store.py
# VERSION:      v1.0.0
# =============================================================================

import sqlite3
import json
import time
from typing import Dict, Any, Optional


class PersistentIdentityStore:

    def __init__(self, db_path="ghostrecon_devices.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            global_id TEXT PRIMARY KEY,
            first_seen REAL,
            last_seen REAL,
            mac_history TEXT,
            uuid_history TEXT,
            behavior_history TEXT,
            last_behavior TEXT,
            confidence REAL
        )
        """)

        self.conn.commit()

    # =========================================================================
    def upsert_device(self, global_id: str, data: Dict[str, Any]):

        cur = self.conn.cursor()

        cur.execute("""
        INSERT INTO devices (global_id, first_seen, last_seen, mac_history,
                             uuid_history, behavior_history, last_behavior, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(global_id) DO UPDATE SET
            last_seen=excluded.last_seen,
            mac_history=excluded.mac_history,
            uuid_history=excluded.uuid_history,
            behavior_history=excluded.behavior_history,
            last_behavior=excluded.last_behavior,
            confidence=excluded.confidence
        """, (
            global_id,
            data["first_seen"],
            data["last_seen"],
            json.dumps(data["mac_history"]),
            json.dumps(data["uuid_history"]),
            json.dumps(data["behavior_history"]),
            data["last_behavior"],
            data["confidence"],
        ))

        self.conn.commit()

    # =========================================================================
    def get_all_devices(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM devices")

        rows = cur.fetchall()
        devices = []

        for r in rows:
            devices.append({
                "global_id": r[0],
                "first_seen": r[1],
                "last_seen": r[2],
                "mac_history": json.loads(r[3]),
                "uuid_history": json.loads(r[4]),
                "behavior_history": json.loads(r[5]),
                "last_behavior": r[6],
                "confidence": r[7],
            })

        return devices
