from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List


@dataclass
class AuditTrace:
    test_id: str
    test_type: str
    target: str
    method: str
    result: str
    evidence: str
    explanation: str
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "test_type": self.test_type,
            "target": self.target,
            "method": self.method,
            "result": self.result,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


class ServiceExposureAuditEngine:
    VERSION = "1.0.0"
    SAFE_TOP_PORTS = [
        80, 81, 443, 8080, 8443, 8000, 8008, 8888, 554, 8554,
        22, 23, 21, 53, 123, 1883, 8883, 5683, 8889, 8081,
    ]

    def __init__(self) -> None:
        self.timeout = 3.0

    @staticmethod
    def _now() -> int:
        return int(time.time())

    @staticmethod
    def _looks_private(ip_value: str) -> bool:
        value = str(ip_value or "").strip()
        return value.startswith("10.") or value.startswith("192.168.") or value.startswith("172.")

    @staticmethod
    def _classify_http_access(status_code: int, headers: Dict[str, str], body_text: str) -> str:
        location = str(headers.get("location") or "").lower()
        www_auth = str(headers.get("www-authenticate") or "").lower()
        body = str(body_text or "").lower()
        if www_auth:
            return "AUTH_REQUIRED"
        if "/login" in location or "signin" in location or "login" in body or "password" in body:
            return "AUTH_REQUIRED"
        if 200 <= status_code < 300:
            return "OPEN_NO_AUTH"
        if status_code in {401, 403}:
            return "AUTH_REQUIRED"
        return "UNKNOWN"

    def _connect_scan(self, ip_value: str, port: int) -> Dict[str, Any]:
        started = self._now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip_value, int(port)))
            if result == 0:
                return {
                    "port": int(port),
                    "state": "open",
                    "method": "tcp_connect",
                    "timestamp": started,
                    "evidence": "TCP connect accepted",
                    "explanation": f"Target accepted a TCP connection on port {port}.",
                }
            if result in {111, 61}:
                return {
                    "port": int(port),
                    "state": "closed",
                    "method": "tcp_connect",
                    "timestamp": started,
                    "evidence": "Connection refused",
                    "explanation": f"Target refused a TCP connection on port {port}.",
                }
            return {
                "port": int(port),
                "state": "filtered",
                "method": "tcp_connect",
                "timestamp": started,
                "evidence": f"connect_ex={result}",
                "explanation": f"Target did not complete a TCP connect on port {port}.",
            }
        except socket.timeout:
            return {
                "port": int(port),
                "state": "filtered",
                "method": "tcp_connect",
                "timestamp": started,
                "evidence": "timeout",
                "explanation": f"Target timed out on port {port}.",
            }
        except OSError as exc:
            return {
                "port": int(port),
                "state": "filtered",
                "method": "tcp_connect",
                "timestamp": started,
                "evidence": str(exc),
                "explanation": f"Socket error while testing port {port}.",
            }
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _http_probe(self, ip_value: str, port: int, secure: bool) -> Dict[str, Any]:
        connection_cls = http.client.HTTPSConnection if secure else http.client.HTTPConnection
        target = f"{'https' if secure else 'http'}://{ip_value}:{port}/"
        started = self._now()
        context = ssl._create_unverified_context() if secure else None
        try:
            conn = connection_cls(ip_value, int(port), timeout=self.timeout, context=context) if secure else connection_cls(ip_value, int(port), timeout=self.timeout)
            conn.request("GET", "/")
            response = conn.getresponse()
            body = response.read(512).decode("utf-8", errors="ignore")
            headers = {str(key).lower(): str(value) for key, value in response.getheaders()}
            posture = self._classify_http_access(int(response.status), headers, body)
            parsed = {
                "status_code": int(response.status),
                "reason": str(response.reason or ""),
                "headers": headers,
                "server_banner": str(headers.get("server") or ""),
                "redirect": str(headers.get("location") or ""),
                "access_posture": posture,
                "body_excerpt": body[:200],
            }
            return {
                "service_type": "https" if secure else "http",
                "response_observed": True,
                "banner_present": bool(parsed["server_banner"]),
                "parsed_result": parsed,
                "timestamp": started,
                "evidence": f"HTTP {response.status}",
                "explanation": f"{target} returned {response.status} {response.reason}.",
            }
        except Exception as exc:
            return {
                "service_type": "https" if secure else "http",
                "response_observed": False,
                "banner_present": False,
                "parsed_result": {"error": str(exc)},
                "timestamp": started,
                "evidence": str(exc),
                "explanation": f"{target} did not return an HTTP response.",
            }
        finally:
            try:
                conn.close()  # type: ignore[name-defined]
            except Exception:
                pass

    def _tls_probe(self, ip_value: str, port: int) -> Dict[str, Any]:
        started = self._now()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            raw.connect((ip_value, int(port)))
            with context.wrap_socket(raw, server_hostname=ip_value) as wrapped:
                cert = wrapped.getpeercert() or {}
                return {
                    "service_type": "tls",
                    "response_observed": True,
                    "banner_present": False,
                    "parsed_result": {
                        "cipher": wrapped.cipher(),
                        "tls_version": wrapped.version(),
                        "certificate_subject": cert.get("subject"),
                        "certificate_issuer": cert.get("issuer"),
                    },
                    "timestamp": started,
                    "evidence": f"TLS {wrapped.version() or 'handshake'}",
                    "explanation": f"TLS handshake succeeded on {ip_value}:{port}.",
                }
        except Exception as exc:
            return {
                "service_type": "tls",
                "response_observed": False,
                "banner_present": False,
                "parsed_result": {"error": str(exc)},
                "timestamp": started,
                "evidence": str(exc),
                "explanation": f"TLS handshake failed on {ip_value}:{port}.",
            }
        finally:
            try:
                raw.close()
            except Exception:
                pass

    def _banner_probe(self, ip_value: str, port: int) -> Dict[str, Any]:
        started = self._now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((ip_value, int(port)))
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
            data = sock.recv(256)
            banner = data.decode("utf-8", errors="ignore").strip()
            return {
                "service_type": "unknown",
                "response_observed": bool(banner),
                "banner_present": bool(banner),
                "parsed_result": {"banner": banner},
                "timestamp": started,
                "evidence": banner or "connected_no_banner",
                "explanation": f"Safe banner probe completed on {ip_value}:{port}.",
            }
        except Exception as exc:
            return {
                "service_type": "unknown",
                "response_observed": False,
                "banner_present": False,
                "parsed_result": {"error": str(exc)},
                "timestamp": started,
                "evidence": str(exc),
                "explanation": f"Safe banner probe failed on {ip_value}:{port}.",
            }
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def run(
        self,
        *,
        target_id: str,
        ip_value: str,
        target_mac: str,
        validation_method: str,
        confidence_score: float,
        allow_infrastructure: bool = False,
        credential_mode: bool = False,
        progress_callback: Callable[[Dict[str, Any]], None] | None = None,
    ) -> Dict[str, Any]:
        traces: List[AuditTrace] = []
        negative_evidence: List[Dict[str, Any]] = []
        tested_ports: Dict[str, Any] = {}
        services: Dict[str, Any] = {}

        def emit(stage_id: str, label: str, status: str, detail: str) -> None:
            if progress_callback is None:
                return
            try:
                progress_callback(
                    {
                        "id": stage_id,
                        "label": label,
                        "status": status,
                        "detail": detail,
                        "target_id": target_id,
                        "target_ip": ip_value,
                    }
                )
            except Exception:
                pass

        target_valid = self._looks_private(ip_value)
        if not allow_infrastructure and ip_value.endswith(".1"):
            target_valid = False
        target_validation = {
            "target_ip_valid": target_valid,
            "validation_method": validation_method,
            "confidence_score": round(float(confidence_score or 0.0), 2),
            "target_ip": ip_value,
            "target_mac": target_mac,
        }
        traces.append(
            AuditTrace(
                test_id="T01",
                test_type="target_validation",
                target=f"{target_mac} -> {ip_value}",
                method=validation_method,
                result="valid" if target_valid else "invalid",
                evidence=f"confidence={target_validation['confidence_score']}",
                explanation="Validated private target IP and MAC-to-IP confidence." if target_valid else "Target IP was not suitable for controlled local audit.",
            )
        )
        emit(
            "target_validation",
            "Target Validate",
            "completed" if target_valid else "blocked",
            (
                f"{validation_method} accepted {ip_value} at confidence {round(float(confidence_score or 0.0), 2)}."
                if target_valid
                else "Target IP invalid or insufficiently validated for controlled local audit."
            ),
        )
        if not target_valid:
            return {
                "ok": False,
                "target_validation": target_validation,
                "test_trace": [trace.as_dict() for trace in traces],
                "negative_evidence": [{"attempted": False, "result": "invalid_target", "explanation": "Target validation failed; port audit did not start."}],
                "port_audit_completeness": {"level": "LOW", "reason": "Target validation failed."},
                "final_verdict": {"classification": "UNKNOWN", "explanation": "Target IP could not be validated."},
                "pipeline": {
                    "status": "blocked",
                    "current_stage": "target_validation",
                    "stages": [
                        {"id": "target_validation", "label": "Target Validate", "status": "blocked", "detail": "Target IP invalid or insufficiently validated."},
                        {"id": "port_discovery", "label": "Port Discovery", "status": "pending", "detail": "Awaiting valid target IP."},
                        {"id": "service_id", "label": "Service ID", "status": "pending", "detail": "Awaiting open ports."},
                        {"id": "access_posture", "label": "Access Posture", "status": "pending", "detail": "Awaiting service responses."},
                        {"id": "trace", "label": "Trace", "status": "pending", "detail": "Awaiting audit execution."},
                    ],
                },
            }

        open_ports: List[int] = []
        emit("port_discovery", "Port Discovery", "active", f"Testing {len(self.SAFE_TOP_PORTS)} safe TCP ports.")
        for index, port in enumerate(self.SAFE_TOP_PORTS, start=2):
            result = self._connect_scan(ip_value, port)
            tested_ports[str(port)] = result
            traces.append(
                AuditTrace(
                    test_id=f"T{index:02d}",
                    test_type="port_scan",
                    target=f"{ip_value}:{port}",
                    method=result["method"],
                    result=result["state"],
                    evidence=result["evidence"],
                    explanation=result["explanation"],
                )
            )
            if result["state"] == "open":
                open_ports.append(int(port))
            else:
                negative_evidence.append({
                    "port": int(port),
                    "attempted": True,
                    "result": result["state"],
                    "evidence": result["evidence"],
                    "explanation": result["explanation"],
                })
        emit(
            "port_discovery",
            "Port Discovery",
            "completed",
            f"{len(open_ports)} open / {len(self.SAFE_TOP_PORTS)} safe ports responded to TCP connect testing.",
        )

        next_id = len(traces) + 1
        auth_surfaces_checked = 0
        services_identified = 0
        emit("service_id", "Service ID", "active", f"Inspecting {len(open_ports)} open ports for protocol identity.")
        for port in open_ports:
            if port in {80, 81, 8080, 8000, 8008, 8081, 8888}:
                response = self._http_probe(ip_value, port, secure=False)
            elif port in {443, 8443}:
                response = self._http_probe(ip_value, port, secure=True)
                if not response["response_observed"]:
                    response = self._tls_probe(ip_value, port)
            elif port in {554, 8554}:
                response = self._banner_probe(ip_value, port)
                response["service_type"] = "rtsp_or_stream"
            else:
                response = self._banner_probe(ip_value, port)
            traces.append(
                AuditTrace(
                    test_id=f"T{next_id:02d}",
                    test_type="service_id",
                    target=f"{ip_value}:{port}",
                    method=response["service_type"],
                    result="response_observed" if response["response_observed"] else "not_observed",
                    evidence=response["evidence"],
                    explanation=response["explanation"],
                )
            )
            next_id += 1
            services[str(port)] = response
            services_identified += 1 if response["response_observed"] else 0
            posture = "UNKNOWN"
            if response["service_type"] in {"http", "https"}:
                posture = str((response.get("parsed_result") or {}).get("access_posture") or "UNKNOWN")
                auth_surfaces_checked += 1
            elif response["service_type"] == "tls":
                posture = "UNKNOWN" if response["response_observed"] else "NO_RESPONSE"
                auth_surfaces_checked += 1
            else:
                posture = "UNKNOWN" if response["response_observed"] else "NO_RESPONSE"
            services[str(port)]["access_posture"] = posture
            if not response["response_observed"]:
                negative_evidence.append({
                    "port": int(port),
                    "attempted": True,
                    "result": "no_response",
                    "evidence": response["evidence"],
                    "explanation": response["explanation"],
                })
        emit(
            "service_id",
            "Service ID",
            "completed" if services else "partial",
            f"{services_identified} service responses observed across {len(open_ports)} open ports.",
        )
        emit(
            "access_posture",
            "Access Posture",
            "completed" if auth_surfaces_checked else "partial",
            f"{auth_surfaces_checked} authentication surfaces checked with safe HTTP/TLS/banner probes.",
        )

        if not open_ports:
            exposure_class = "LOCAL_NO_SERVICE"
            verdict = "LOCAL_NO_SERVICE"
            verdict_explanation = "No open local services were confirmed in the tested safe port range."
        else:
            open_no_auth = any(str((entry or {}).get("access_posture") or "") == "OPEN_NO_AUTH" for entry in services.values())
            auth_required = any(str((entry or {}).get("access_posture") or "") == "AUTH_REQUIRED" for entry in services.values())
            if open_no_auth:
                exposure_class = "LOCAL_OPEN_NO_AUTH"
                verdict = "LOCAL_OPEN_NO_AUTH_CONFIRMED"
                verdict_explanation = "Device exposes at least one local service without authentication."
            elif auth_required:
                exposure_class = "LOCAL_AUTH_REQUIRED"
                verdict = "LOCAL_AUTH_REQUIRED"
                verdict_explanation = "Local services were observed and appear to require authentication."
            else:
                exposure_class = "UNKNOWN"
                verdict = "UNKNOWN"
                verdict_explanation = "Services were observed but access posture was not clear from safe checks."

        completeness_level = "HIGH" if len(self.SAFE_TOP_PORTS) >= 20 and services_identified >= max(1, len(open_ports)) else ("MEDIUM" if open_ports else "LOW")
        pipeline_stages = [
            {"id": "target_validation", "label": "Target Validate", "status": "completed", "detail": f"{validation_method} · confidence {round(confidence_score, 2)}"},
            {"id": "port_discovery", "label": "Port Discovery", "status": "completed", "detail": f"{len(open_ports)} open / {len(self.SAFE_TOP_PORTS)} tested"},
            {"id": "service_id", "label": "Service ID", "status": "completed" if services else "partial", "detail": f"{services_identified} responses observed"},
            {"id": "access_posture", "label": "Access Posture", "status": "completed" if auth_surfaces_checked else "partial", "detail": f"{auth_surfaces_checked} auth surfaces checked"},
            {"id": "trace", "label": "Trace", "status": "completed", "detail": f"{len(traces)} audit events retained"},
        ]
        emit("trace", "Trace", "completed", f"{len(traces)} evidence-backed audit events retained.")
        return {
            "ok": True,
            "target_validation": target_validation,
            "ports": tested_ports,
            "services": services,
            "credential_posture": {
                "credential_tested": credential_mode,
                "credential_source": "not_authorized" if not credential_mode else "authorized_mode",
                "result": "not_authorized" if not credential_mode else "not_tested",
            },
            "negative_evidence": negative_evidence,
            "test_trace": [trace.as_dict() for trace in traces],
            "service_exposure_classification": exposure_class,
            "port_audit_completeness": {
                "level": completeness_level,
                "ports_tested": len(self.SAFE_TOP_PORTS),
                "services_identified": services_identified,
                "auth_surfaces_checked": auth_surfaces_checked,
                "negative_evidence_coverage": len(negative_evidence),
                "reason": (
                    "Sufficient ports were tested and observed services were validated."
                    if completeness_level == "HIGH"
                    else "Audit coverage was partial but evidence-backed."
                ),
            },
            "final_verdict": {
                "classification": verdict,
                "explanation": verdict_explanation,
            },
            "pipeline": {
                "status": "completed",
                "current_stage": "trace",
                "stages": pipeline_stages,
            },
        }
