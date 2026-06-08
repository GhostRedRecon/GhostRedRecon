from __future__ import annotations

import os
import queue
import threading
import time
from typing import Any, Callable, Dict, List


class StagedWiFiScanPipeline:
    QUEUE_MAX_SIZE = 4
    DETECTION_REFRESH_INTERVAL_SEC = 1.5
    CAMERA_HUNT_DETECTION_REFRESH_INTERVAL_SEC = 3.5
    CAMERA_HUNT_MIN_SAMPLE_RATE = 3

    def __init__(
        self,
        tracker: Any,
        enricher: Any,
        get_networks: Callable[[], List[Dict[str, Any]]],
        get_clients: Callable[[], List[Dict[str, Any]]],
        error_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.tracker = tracker
        self.enricher = enricher
        self.get_networks = get_networks
        self.get_clients = get_clients
        self.error_callback = error_callback
        self.decode_queue: queue.Queue[Dict[str, Any] | None] = queue.Queue()
        self.flow_queue: queue.Queue[Dict[str, Any] | None] = queue.Queue()
        self.detect_queue: queue.Queue[Dict[str, Any] | None] = queue.Queue()
        self.threads: List[threading.Thread] = []
        self.running = False
        self.started_at: float | None = None
        self.stage_counts: Dict[str, int] = {
            "capture": 0,
            "decode": 0,
            "flow": 0,
            "detect": 0,
        }
        self.last_stage: Dict[str, Any] = {}
        self.latest_summary: Dict[str, Any] = {}
        self.enrichment_enabled = False
        self.camera_hunt = False
        self.lock = threading.Lock()
        self.queue_wait_events = 0
        self.queue_drop_events = 0
        self.last_detection_summary_at = 0.0
        self.enable_zeek = True
        self.enrichment_sample_rate = 1
        self.max_enrichment_pcap_bytes = 0
        self.detection_refresh_interval_sec = self.DETECTION_REFRESH_INTERVAL_SEC

    def start(
        self,
        *,
        enrichment_enabled: bool,
        camera_hunt: bool,
        enable_zeek: bool = True,
        enrichment_sample_rate: int = 1,
        max_enrichment_pcap_bytes: int = 0,
    ) -> None:
        self.stop()
        self.decode_queue = queue.Queue(maxsize=self.QUEUE_MAX_SIZE)
        self.flow_queue = queue.Queue(maxsize=self.QUEUE_MAX_SIZE)
        self.detect_queue = queue.Queue(maxsize=self.QUEUE_MAX_SIZE)
        self.stage_counts = {"capture": 0, "decode": 0, "flow": 0, "detect": 0}
        self.last_stage = {}
        self.latest_summary = {}
        self.enrichment_enabled = bool(enrichment_enabled)
        self.camera_hunt = bool(camera_hunt)
        self.enable_zeek = bool(enable_zeek)
        self.enrichment_sample_rate = max(1, int(enrichment_sample_rate or 1))
        self.max_enrichment_pcap_bytes = max(0, int(max_enrichment_pcap_bytes or 0))
        self.detection_refresh_interval_sec = (
            self.CAMERA_HUNT_DETECTION_REFRESH_INTERVAL_SEC
            if self.camera_hunt
            else self.DETECTION_REFRESH_INTERVAL_SEC
        )
        self.queue_wait_events = 0
        self.queue_drop_events = 0
        self.last_detection_summary_at = 0.0
        self.running = True
        self.started_at = time.time()
        self.threads = [
            threading.Thread(target=self._decode_worker, daemon=True, name="wifi-mk7-decode"),
            threading.Thread(target=self._flow_worker, daemon=True, name="wifi-mk7-flow"),
            threading.Thread(target=self._detect_worker, daemon=True, name="wifi-mk7-detect"),
        ]
        for thread in self.threads:
            thread.start()

    def stop(self) -> None:
        if not self.running and not self.threads:
            return
        self.running = False
        for q in (self.decode_queue, self.flow_queue, self.detect_queue):
            self._signal_stop(q)
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        self.threads = []

    def _signal_stop(self, q: queue.Queue[Dict[str, Any] | None]) -> None:
        for _ in range(20):
            try:
                q.put(None, timeout=0.1)
                return
            except queue.Full:
                continue
            except Exception:
                return

    def submit(self, item: Dict[str, Any]) -> None:
        if not self.running:
            return
        queue_wait_started_at: float | None = None
        with self.lock:
            self.stage_counts["capture"] += 1
            self.last_stage["capture"] = {
                "channel": int((item.get("entry") or {}).get("channel") or 0),
                "interface": item.get("interface") or "",
                "frame_count": len((item.get("result") or {}).get("frames") or []),
                "at": time.time(),
            }
        while self.running:
            try:
                self.decode_queue.put(item, timeout=0.25)
                if queue_wait_started_at is not None:
                    with self.lock:
                        self.last_stage["capture"]["queue_wait_ms"] = round((time.time() - queue_wait_started_at) * 1000.0, 1)
                return
            except queue.Full:
                if queue_wait_started_at is None:
                    queue_wait_started_at = time.time()
                    with self.lock:
                        self.queue_wait_events += 1
                continue
            except Exception:
                break
        with self.lock:
            self.queue_drop_events += 1

    def wait_idle(self, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.decode_queue.unfinished_tasks == 0 and self.flow_queue.unfinished_tasks == 0 and self.detect_queue.unfinished_tasks == 0:
                return
            time.sleep(0.05)

    def _queue_put(self, target_queue: queue.Queue[Dict[str, Any] | None], item: Dict[str, Any] | None) -> bool:
        while self.running:
            try:
                target_queue.put(item, timeout=0.25)
                return True
            except queue.Full:
                continue
            except Exception:
                return False
        return False

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "started_at": self.started_at,
            "topology": "Capture Thread -> Decode Thread -> Flow Engine -> Detection Engine -> UI",
            "queues": {
                "decode": self.decode_queue.qsize(),
                "flow": self.flow_queue.qsize(),
                "detect": self.detect_queue.qsize(),
            },
            "counts": dict(self.stage_counts),
            "last_stage": dict(self.last_stage),
            "summary": dict(self.latest_summary),
            "camera_hunt": self.camera_hunt,
            "enrichment_enabled": self.enrichment_enabled,
            "limits": {
                "queue_max_size": self.QUEUE_MAX_SIZE,
                "detection_refresh_interval_seconds": self.detection_refresh_interval_sec,
                "enrichment_sample_rate": self.enrichment_sample_rate,
                "max_enrichment_pcap_bytes": self.max_enrichment_pcap_bytes,
                "zeek_enabled": self.enable_zeek,
            },
            "pressure": {
                "queue_wait_events": self.queue_wait_events,
                "queue_drop_events": self.queue_drop_events,
            },
        }

    def _decode_worker(self) -> None:
        while True:
            item = self.decode_queue.get()
            try:
                if item is None:
                    return
                result = dict(item.get("result") or {})
                item["decoded_frame_count"] = len(result.get("frames") or [])
                with self.lock:
                    self.stage_counts["decode"] += 1
                    self.last_stage["decode"] = {
                        "channel": int((item.get("entry") or {}).get("channel") or 0),
                        "frame_count": item["decoded_frame_count"],
                        "at": time.time(),
                    }
                if not self._queue_put(self.flow_queue, item):
                    return
            finally:
                self.decode_queue.task_done()

    def _flow_worker(self) -> None:
        while True:
            item = self.flow_queue.get()
            try:
                if item is None:
                    return
                entry = dict(item.get("entry") or {})
                result = dict(item.get("result") or {})
                channel = int(entry.get("channel") or 0)
                band = str(entry.get("band") or "")
                pcap_path = str(result.get("pcap_path") or "")
                frames = list(result.get("frames") or [])
                self.tracker.ingest_capture(channel, band, pcap_path, frames)
                result.pop("frames", None)
                should_enrich = False
                if self.enrichment_enabled or self.camera_hunt:
                    capture_index = int(self.stage_counts.get("flow") or 0) + 1
                    effective_sample_rate = self.enrichment_sample_rate
                    if self.camera_hunt and not self.enrichment_enabled:
                        effective_sample_rate = max(self.CAMERA_HUNT_MIN_SAMPLE_RATE, effective_sample_rate)
                    should_enrich = capture_index % effective_sample_rate == 0
                    if should_enrich and self.max_enrichment_pcap_bytes > 0 and pcap_path:
                        try:
                            should_enrich = pcap_path and os.path.getsize(pcap_path) <= self.max_enrichment_pcap_bytes
                        except Exception:
                            should_enrich = True
                if should_enrich:
                    enrichment = self.enricher.enrich_pcap(pcap_path, enable_zeek=self.enable_zeek)
                    if enrichment.get("ok") and any(
                        (
                            enrichment.get("identities"),
                            enrichment.get("service_inventory"),
                            enrichment.get("protocol_summary"),
                        )
                    ):
                        self.tracker.ingest_enrichment(
                            list(enrichment.get("identities") or []),
                            service_inventory=list(enrichment.get("service_inventory") or []),
                            protocol_summary=dict(enrichment.get("protocol_summary") or {}),
                            pcap_path=pcap_path,
                        )
                    elif enrichment.get("error") and self.error_callback:
                        self.error_callback(str(enrichment.get("error")))
                with self.lock:
                    self.stage_counts["flow"] += 1
                    self.last_stage["flow"] = {
                        "channel": channel,
                        "networks": int(self.latest_summary.get("network_count") or 0),
                        "clients": int(self.latest_summary.get("client_count") or 0),
                        "at": time.time(),
                    }
                if not self._queue_put(self.detect_queue, item):
                    return
            finally:
                self.flow_queue.task_done()

    def _detect_worker(self) -> None:
        while True:
            item = self.detect_queue.get()
            try:
                if item is None:
                    return
                now = time.time()
                refresh_summary = (now - self.last_detection_summary_at) >= self.detection_refresh_interval_sec
                if not refresh_summary:
                    with self.lock:
                        self.stage_counts["detect"] += 1
                        self.last_stage["detect"] = {
                            "channel": int((item.get("entry") or {}).get("channel") or 0),
                            "camera_hits": int(self.latest_summary.get("camera_candidate_count") or 0),
                            "at": now,
                        }
                    continue
                self.last_detection_summary_at = now
                networks = self.get_networks()
                clients = self.get_clients()
                auth_evidence = self.tracker.get_authentication_evidence()
                observation_audit = self.tracker.get_observation_audit()
                camera_hits = [
                    entry for entry in [*networks, *clients]
                    if float(((entry.get("camera_detection") or {}).get("score") or 0.0)) >= 40.0
                ]
                handshake_networks = int(auth_evidence.get("network_count") or 0)
                handshake_clients = int(auth_evidence.get("client_count") or 0)
                handshake_events = int(auth_evidence.get("total_frame_count") or 0)
                high_opportunity = [entry for entry in networks if str((entry.get("observation_opportunity") or {}).get("level")) == "HIGH"]
                association_events = sum(int(entry.get("association_event_count") or 0) for entry in networks) + sum(int(entry.get("association_event_count") or 0) for entry in clients)
                reassociation_events = sum(int(entry.get("reassociation_event_count") or 0) for entry in networks) + sum(int(entry.get("reassociation_event_count") or 0) for entry in clients)
                authentication_events = sum(int(entry.get("authentication_event_count") or 0) for entry in networks) + sum(int(entry.get("authentication_event_count") or 0) for entry in clients)
                probe_requests = sum(int(entry.get("probe_request_count") or 0) for entry in clients)
                with self.lock:
                    self.stage_counts["detect"] += 1
                    self.last_stage["detect"] = {
                        "channel": int((item.get("entry") or {}).get("channel") or 0),
                        "camera_hits": len(camera_hits),
                        "at": now,
                    }
                    self.latest_summary = {
                        "network_count": len(networks),
                        "client_count": len(clients),
                        "camera_candidate_count": len(camera_hits),
                        "handshake_network_count": handshake_networks,
                        "handshake_client_count": handshake_clients,
                        "handshake_session_count": int(auth_evidence.get("session_count") or 0),
                        "handshake_event_count": handshake_events,
                        "confirmed_authentication_evidence_count": int(((auth_evidence.get("quality_counts") or {}).get("CONFIRMED") or 0)),
                        "likely_authentication_evidence_count": int(((auth_evidence.get("quality_counts") or {}).get("LIKELY") or 0)),
                        "partial_authentication_evidence_count": int(((auth_evidence.get("quality_counts") or {}).get("PARTIAL") or 0)),
                        "raw_eapol_frame_count": int(((auth_evidence.get("debug") or {}).get("raw_eapol_frame_count") or 0)),
                        "duplicate_eapol_frame_count": int(((auth_evidence.get("debug") or {}).get("duplicate_eapol_frame_count") or 0)),
                        "unmatched_eapol_frame_count": int(((auth_evidence.get("debug") or {}).get("unmatched_eapol_frame_count") or 0)),
                        "coverage_confidence_level": str(((observation_audit.get("coverage_confidence") or {}).get("level") or "WEAK")),
                        "coverage_confidence_summary": str(((observation_audit.get("coverage_confidence") or {}).get("summary") or "")),
                        "high_observation_opportunity_count": len(high_opportunity),
                        "association_event_count": association_events,
                        "reassociation_event_count": reassociation_events,
                        "authentication_event_count": authentication_events,
                        "probe_request_count": probe_requests,
                    }
            finally:
                self.detect_queue.task_done()
