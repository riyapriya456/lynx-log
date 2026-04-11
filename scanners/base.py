import hashlib
import urllib.parse
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from common import TestingZone, event_manager
from scan_policy import FindingEvidence

SEVERITY_MAP = {
    "SQL Injection": "P1",
    "SQL Injection (POST)": "P1",
    "Time-Based SQLi": "P1",
    "Time-Based SQLi (POST)": "P1",
    "Reflected XSS": "P2",
    "DOM/Reflected XSS (Selenium Verified)": "P1",
    "Local File Inclusion": "P2",
    "CSRF Missing": "P2",
    "CSRF Bypass": "P2",
    "Open Redirect": "P3",
    "Sensitive File Found": "P3",
    "Weak Security Headers": "P3",
    "Cookie Security": "P3",
    "Cookie Attack": "P2",
    "CORS Misconfiguration": "P3",
    "Information Disclosure": "P4",
    "TLS/SSL Issue": "P3",
    "API Endpoint Found": "P4",
    "Potential SSRF": "P2",
    "Potential IDOR": "P2",
    "IDOR": "P2",
    "Secret Leaked": "P1",
    "Auth Issue": "P2",
    "HTML Injection": "P3",
    "Command Injection": "P1",
    "XXE Injection": "P1",
    "Form Security": "P4",
    "Open Port": "P4",
    "CMS Vulnerability": "P3",
    "403 Bypass": "P2",
    "Authentication Bypass": "P1",
    "Rate Limit Bypass": "P3",
    "2FA Bypass": "P1",
    "Mass Assignment": "P1",
    "JSON Injection": "P2",
    "Password Reset Vulnerability": "P1",
    "Default Credentials": "P1",
    "NoSQL Injection": "P1",
    "XPath Injection": "P1",
    "LDAP Injection": "P1",
}


class BaseScanner:
    def __init__(self, context):
        self.context = context
        self.name = self.__class__.__name__
        self.zone = TestingZone.ZONE_E

    def _validate_filepath(self, filepath: str) -> bool:
        """Validate payload path against traversal and absolute-path tricks."""
        if not filepath or not isinstance(filepath, str):
            return False

        if '..' in filepath or filepath.startswith('/') or filepath.startswith('\\'):
            event_manager.emit_sync("log", f"[SECURITY] Blocked path traversal attempt: {filepath}")
            return False

        candidate = Path(filepath)
        return not candidate.is_absolute()

    def load_payloads(self, filepath: str, limit: Optional[int] = None) -> List[str]:
        """Load payloads from a file relative to the payloads directory."""
        if not self._validate_filepath(filepath):
            return []

        payloads_root = Path(self.context.payloads_dir).resolve()
        try:
            payloads_path = (payloads_root / filepath).resolve()
            payloads_path.relative_to(payloads_root)
        except Exception:
            event_manager.emit_sync("log", f"[SECURITY] Blocked invalid payload path: {filepath}")
            return []

        try:
            if payloads_path.is_file():
                with payloads_path.open('r', encoding='utf-8', errors='ignore') as f:
                    payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.strip().startswith('#')
                    ]
                return payloads[:limit] if limit else payloads
        except (IOError, OSError) as e:
            event_manager.emit_sync("log", f"[ERROR] Failed to load payloads from {filepath}: {e}")
        except Exception as e:
            event_manager.emit_sync("log", f"[ERROR] Unexpected error loading payloads: {e}")

        return []

    def _default_reproduction_steps(self, vuln_type: str, target_url: str, payload: Optional[str]) -> List[str]:
        steps = [f"Open {target_url} in a clean session."]
        if payload:
            steps.append(f"Re-run the request with payload `{payload}`.")
        else:
            steps.append("Repeat the same request and compare the response.")

        if vuln_type in {"SQL Injection", "SQL Injection (POST)", "Time-Based SQLi", "Time-Based SQLi (POST)"}:
            steps.append("Compare the response to a clean baseline and verify the SQL behavior or delay.")
        elif "XSS" in vuln_type:
            steps.append("Confirm the payload executes in-browser and produces the expected client-side effect.")
        elif "Redirect" in vuln_type:
            steps.append("Follow the redirect chain and verify the destination is attacker-controlled.")
        elif "Bypass" in vuln_type:
            steps.append("Compare the restricted response with the bypassed response and confirm the access boundary moved.")
        else:
            steps.append("Retest after remediation and confirm the behavior no longer reproduces.")

        return steps

    def _estimate_confidence(self, vuln_type: str, severity: str, details: str, payload: Optional[str]) -> float:
        base = {
            "P1": 0.92,
            "P2": 0.83,
            "P3": 0.72,
            "P4": 0.60,
        }.get(severity, 0.68)

        lowered = (details or "").lower()
        if payload:
            base += 0.03
        if any(token in lowered for token in ("verified", "executed", "timing", "bypass", "sql")):
            base += 0.02
        if vuln_type in {"DOM/Reflected XSS (Selenium Verified)", "Time-Based SQLi", "Time-Based SQLi (POST)"}:
            base += 0.05
        if any(token in lowered for token in ("possible", "may", "might", "could", "appears", "may be", "potential")):
            base -= 0.12
        if "manual verification" in lowered or "heuristic" in lowered:
            base -= 0.08
        if not payload:
            base -= 0.05
        return max(0.1, min(0.99, base))

    def _build_default_evidence(
        self,
        vuln_type: str,
        target_url: str,
        details: str,
        payload: Optional[str],
        method: str,
        response_excerpt: Optional[str],
        confidence: float,
        observed_behavior: Optional[str],
    ) -> FindingEvidence:
        excerpt = response_excerpt or (details[:280] if details else None)
        behavior = observed_behavior or (details.splitlines()[0] if details else None)
        return FindingEvidence(
            request_method=method,
            request_url=target_url,
            payload=payload,
            response_excerpt=excerpt,
            observed_behavior=behavior,
            reproduction_steps=self._default_reproduction_steps(vuln_type, target_url, payload),
            verification="direct" if confidence >= 0.85 else "heuristic",
            confidence_reason="Derived from scanner output and response behavior.",
        )

    async def emit_vulnerability(
        self,
        vuln_type,
        details,
        severity=None,
        remediation=None,
        url=None,
        payload=None,
        *,
        confidence: Optional[float] = None,
        evidence: Optional[Dict[str, Any]] = None,
        reproduction_steps: Optional[List[str]] = None,
        request_method: str = "GET",
        response_excerpt: Optional[str] = None,
        observed_behavior: Optional[str] = None,
        verification: Optional[str] = None,
    ):
        if severity is None:
            severity = SEVERITY_MAP.get(vuln_type, "P4")

        target_url = url if url else self.context.target
        unique_component = payload if payload else details
        unique_key = f"{vuln_type}|{target_url}|{unique_component}"
        vuln_hash = hashlib.md5(unique_key.encode()).hexdigest()
        if vuln_hash in self.context.seen_vulns:
            return
        self.context.seen_vulns.add(vuln_hash)

        if confidence is None:
            confidence = self._estimate_confidence(vuln_type, severity, details or "", payload)

        if confidence < 0.55:
            severity = "P4"
        elif confidence < 0.70 and severity in {"P1", "P2"}:
            severity = "P3"

        evidence_obj = evidence or self._build_default_evidence(
            vuln_type=vuln_type,
            target_url=target_url,
            details=details or "",
            payload=payload,
            method=request_method,
            response_excerpt=response_excerpt,
            confidence=confidence,
            observed_behavior=observed_behavior,
        ).to_dict()

        if reproduction_steps is None:
            reproduction_steps = evidence_obj.get("reproduction_steps", [])

        data = {
            "type": vuln_type,
            "url": target_url,
            "payload": payload,
            "details": details,
            "severity": severity,
            "scanner": self.name,
            "zone": self.zone.value,
            "remediation": remediation or "Apply standard security best practices.",
            "confidence": round(confidence, 2),
            "evidence": evidence_obj,
            "reproduction_steps": reproduction_steps,
            "request_method": request_method,
            "response_excerpt": response_excerpt or evidence_obj.get("response_excerpt"),
            "observed_behavior": observed_behavior or evidence_obj.get("observed_behavior"),
            "verification": verification or evidence_obj.get("verification"),
        }

        try:
            await event_manager.emit("vulnerability", data)
            await event_manager.emit(
                "log",
                f"[red][{severity}] {vuln_type} found in {self.zone.name} (confidence {confidence:.2f})![/red]",
            )
        except Exception as e:
            await event_manager.emit("log", f"[red][Error] Failed to emit vulnerability: {e}[/red]")

    def validate_url(self, url: str) -> bool:
        """Validate URL format to prevent malformed requests."""
        if not url or not isinstance(url, str):
            return False

        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False

            if parsed.scheme not in ["http", "https"]:
                return False

            dangerous_shell = ['`', '$', '(', ')', '<', '>']
            url_without_query = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if any(char in url_without_query for char in dangerous_shell):
                return False

            return True
        except Exception:
            return False

    def generate_injection_points(self, url: str, payload: str):
        """Generate a bounded set of injection points for a payload."""
        if not self.validate_url(url) or not payload or not isinstance(payload, str):
            return

        if len(payload) > 1000:
            payload = payload[:1000]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        emitted = set()

        if params:
            for param in params:
                new_params = params.copy()
                new_params[param] = [payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                new_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                if new_url not in emitted:
                    emitted.add(new_url)
                    yield new_url

        if not params:
            candidates = [
                f"{url}{payload}" if url.endswith('/') else f"{url}/{payload}",
                f"{url}?q={payload}",
                f"{url}?id={payload}",
                f"{url}?search={payload}",
            ]
            for candidate in candidates:
                if candidate not in emitted:
                    emitted.add(candidate)
                    yield candidate

    async def check_generic_payload(self, payload, url, signatures, vuln_type, severity, remediation):
        """Generic GET check against a small signature set."""
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                if any(sig in text for sig in signatures):
                    await self.emit_vulnerability(
                        vuln_type,
                        f"PoC URL: {url}\nPayload: {payload}",
                        severity,
                        remediation,
                        url=url,
                        payload=payload,
                        request_method="GET",
                        response_excerpt=text[:240],
                    )
        except Exception:
            pass

    def cleanup(self):
        pass
