from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import urllib.parse
import hashlib
import re

@dataclass
class Finding:
    type: str
    title: str
    severity: str
    confidence: str # "confirmed", "high", "medium", "low", "informational"
    status: str # "confirmed", "unconfirmed", "informational", "suppressed", "false_positive"
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    baseline_evidence: Optional[Dict[str, Any]] = None
    verification_steps: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: str = ""
    cwe: str = ""
    owasp: str = ""
    scanner: str = ""
    zone: str = ""
    request_count: int = 0
    verification_attempts: int = 0
    first_seen: float = 0.0
    last_verified: float = 0.0
    dedupe_key: str = ""
    reason_for_suppression: str = ""
    raw_http_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "baseline_evidence": self.baseline_evidence,
            "verification_steps": self.verification_steps,
            "reproduction_steps": self.reproduction_steps,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "scanner": self.scanner,
            "zone": self.zone,
            "request_count": self.request_count,
            "verification_attempts": self.verification_attempts,
            "first_seen": self.first_seen,
            "last_verified": self.last_verified,
            "dedupe_key": self.dedupe_key,
            "reason_for_suppression": self.reason_for_suppression,
            "raw_http_summary": self.raw_http_summary
        }

def normalize_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        path = re.sub(r'/+', '/', parsed.path) # collapse duplicate slashes

        # Parse query params, remove tracking/cache busters, sort
        query_params = urllib.parse.parse_qsl(parsed.query)
        ignore_params = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
                         'fbclid', 'gclid', 'msclkid', 'cb', 'cache', '_', 'timestamp', 'ts'}

        filtered_params = sorted([(k, v) for k, v in query_params if k.lower() not in ignore_params])
        new_query = urllib.parse.urlencode(filtered_params)

        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, new_query, ""))
    except Exception:
        return url

def generate_dedupe_key(finding: Finding) -> str:
    norm_url = normalize_url(finding.url)

    # Strip query from norm_url for the dedupe key base, as parameters are tracked separately
    try:
        parsed = urllib.parse.urlparse(norm_url)
        url_path = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    except:
        url_path = norm_url

    param = finding.parameter or ""

    # Simple sink inference for dedupe
    sink = finding.type
    if finding.scanner == "JSAnalyzerScanner":
        sink = finding.payload or finding.type # using payload or type as sink

    evidence_type = "default"
    if finding.evidence and isinstance(finding.evidence, dict):
        evidence_type = finding.evidence.get("verification", "default")

    key_str = f"{finding.type}|{url_path}|{finding.method}|{param}|{sink}|{evidence_type}"
    return hashlib.md5(key_str.encode()).hexdigest()

def quality_gate(finding: Finding) -> Finding:
    """Classifies finding status: confirmed, informational, suppressed, false_positive"""

    # Default assumptions
    finding.status = "informational"

    # High confidence or explicit confirmed check
    if finding.confidence in ["confirmed", "high"]:
        finding.status = "confirmed"

    # Scanner-specific noise suppression
    if finding.scanner == "JSAnalyzerScanner":
        vuln_type = finding.type.lower()
        if "innerhtml" in vuln_type or "dangerouslysetinnerhtml" in vuln_type:
            finding.status = "suppressed"
            finding.reason_for_suppression = "Static innerHTML assignment without proven data-flow."
            finding.confidence = "informational"
        elif "postmessage" in vuln_type or "addeventlistener(\"message\")" in vuln_type:
            finding.status = "suppressed"
            finding.reason_for_suppression = "postMessage detected but no explicit exploit path verified."
            finding.confidence = "informational"
        elif "__proto__" in vuln_type or "prototype" in vuln_type:
            finding.status = "suppressed"
            finding.reason_for_suppression = "Prototype keyword without proven pollution."
            finding.confidence = "informational"
        elif "math.random" in vuln_type:
            finding.status = "suppressed"
            finding.reason_for_suppression = "Math.random exists but usage context (crypto/auth) is unverified."
            finding.confidence = "informational"
        elif "http://" in vuln_type:
            finding.status = "informational"
            finding.reason_for_suppression = "HTTP URL string present; unverified if loaded as active mixed content."
            finding.confidence = "informational"
        elif "react" in vuln_type or "useparams" in vuln_type:
            finding.status = "informational"
            finding.reason_for_suppression = "React pattern detected but impact is unknown."
            finding.confidence = "informational"
        else:
            # Generic JS vulnerabilities without active verification are informational leads
            finding.status = "informational"
            finding.confidence = "informational"
            finding.reason_for_suppression = "Static JavaScript analysis lead requires manual review."

    elif finding.scanner == "SecurityHeadersCheck":
        finding.status = "informational"
        finding.confidence = "informational"
        finding.reason_for_suppression = "Missing headers are informational unless chained with an exploit."

    elif "xss" in finding.type.lower():
        # XSS needs verification
        if finding.confidence not in ["high", "confirmed"]:
            if "selenium verified" in finding.type.lower() or finding.verification_attempts > 0:
                if finding.evidence and finding.evidence.get("observed_behavior") and "alert" in finding.evidence.get("observed_behavior", "").lower():
                     finding.status = "confirmed"
                else:
                    finding.status = "unconfirmed"
            else:
                finding.status = "informational"
                finding.reason_for_suppression = "Reflected input without executed payload confirmation."

    # Must have evidence
    if not finding.evidence and finding.status == "confirmed":
         finding.status = "unconfirmed"
         finding.reason_for_suppression = "Missing evidence."

    # Ensure parameter differentiation in dedupe if not explicitly set
    if not finding.parameter and "?" in finding.url:
        try:
            parsed = urllib.parse.urlparse(finding.url)
            query_keys = sorted(urllib.parse.parse_qs(parsed.query).keys())
            finding.parameter = ",".join(query_keys)
        except Exception:
            pass

    return finding
