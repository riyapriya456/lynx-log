"""
Lynx VAPT - Multi-Stage Vulnerability Validation Framework

Features:
- Multi-stage validation pipeline (signature → context → secondary → noise filter)
- Baseline response comparison (clean vs injected vs control)
- Context-aware regex matching (skip comments, test values, minified code)
- Confidence scoring for findings

Author: Lynx Team
"""

import asyncio
import re
import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable
from enum import Enum


class ValidationStage(Enum):
    """Stages in the validation pipeline."""
    SIGNATURE = "signature"
    CONTEXTUAL = "contextual"
    SECONDARY = "secondary"
    NOISE_FILTER = "noise_filter"


class ValidationResult(Enum):
    """Result of a validation check."""
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"  # Can't determine, skip to next stage
    NEEDS_VERIFICATION = "needs_verification"


@dataclass
class ValidationContext:
    """Context passed through validation stages."""
    vuln_type: str
    url: str
    payload: str
    details: str
    
    # Request/Response data
    original_response: Optional[str] = None
    original_status: Optional[int] = None
    original_length: Optional[int] = None
    
    payload_response: Optional[str] = None
    payload_status: Optional[int] = None
    payload_length: Optional[int] = None
    
    control_response: Optional[str] = None
    control_status: Optional[int] = None
    control_length: Optional[int] = None
    
    # Additional metadata
    reflection_found: bool = False
    reflection_location: Optional[str] = None
    error_pattern_found: bool = False
    behavior_change: bool = False
    
    # Confidence tracking
    confidence: float = 0.5
    stage_results: Dict[str, ValidationResult] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


@dataclass
class BaselineResult:
    """Result of baseline comparison."""
    is_significant: bool
    length_diff: int
    length_diff_percent: float
    status_changed: bool
    unique_patterns: List[str]
    confidence_adjustment: float


class ValidationStageHandler(ABC):
    """Base class for validation stage handlers."""
    
    @abstractmethod
    async def validate(self, context: ValidationContext) -> ValidationResult:
        """Run this validation stage."""
        pass
    
    @abstractmethod
    def get_confidence_adjustment(self, result: ValidationResult) -> float:
        """Get confidence adjustment based on result."""
        pass


class SignatureDetectionStage(ValidationStageHandler):
    """
    Stage 1: Initial signature detection.
    
    Checks if the potential vulnerability signature is present.
    """
    
    # Signature patterns per vulnerability type
    SIGNATURES = {
        "SQL Injection": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"SQLite.*error",
            r"SQLITE_ERROR",
            r"Microsoft OLE DB Provider for SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
            r"syntax error.*SQL",
        ],
        "XSS": [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
        ],
        "Command Injection": [
            r"uid=\d+\([\w]+\)",  # Unix id output
            r"root:x:0:0",  # /etc/passwd
            r"Volume in drive",  # Windows dir
            r"Directory of",
            r"bin/bash",
            r"bin/sh",
        ],
        "XXE": [
            r"root:x:0:0",
            r"\[boot loader\]",  # Windows boot.ini
            r"DOCTYPE.*ENTITY",
        ],
        "LFI": [
            r"root:.*:0:0",
            r"\[boot loader\]",
            r"<\?php",
            r"Warning.*include\(",
            r"failed to open stream",
        ],
        "SSRF": [
            r"169\.254\.169\.254",  # AWS metadata
            r"metadata\.google\.internal",
            r"localhost",
            r"127\.0\.0\.1",
        ],
        "SSTI": [
            r"\b49\b",  # Result of 7*7
            r"\b7777777\b",  # Result of 7*'7' in some engines
            r"sandbox",
            r"template.*error",
        ],
    }
    
    async def validate(self, context: ValidationContext) -> ValidationResult:
        """Check for vulnerability signatures in response."""
        if not context.payload_response:
            return ValidationResult.SKIP
        
        patterns = self.SIGNATURES.get(context.vuln_type, [])
        if not patterns:
            # No specific signatures, defer to other stages
            return ValidationResult.SKIP
        
        for pattern in patterns:
            try:
                if re.search(pattern, context.payload_response, re.I):
                    context.notes.append(f"Signature found: {pattern[:50]}")
                    return ValidationResult.PASS
            except re.error:
                continue
        
        return ValidationResult.FAIL
    
    def get_confidence_adjustment(self, result: ValidationResult) -> float:
        if result == ValidationResult.PASS:
            return 0.3
        elif result == ValidationResult.FAIL:
            return -0.2
        return 0.0


class ContextualConfirmationStage(ValidationStageHandler):
    """
    Stage 2: Contextual confirmation.
    
    Verifies that the finding makes contextual sense:
    - Payload is actually reflected
    - Behavior changed in expected way
    - Not inside a comment or benign context
    """
    
    # Patterns for benign contexts (false positive indicators)
    BENIGN_CONTEXTS = [
        r'<!--.*?-->',  # HTML comments
        r'/\*.*?\*/',   # CSS/JS block comments
        r'//.*$',       # JS line comments
        r'<!\[CDATA\[.*?\]\]>',  # CDATA sections
    ]
    
    # Known false positive values
    FALSE_POSITIVE_VALUES = [
        'test', 'example', 'sample', 'demo', 'dummy',
        'foo', 'bar', 'baz', 'lorem', 'ipsum',
        'placeholder', 'undefined', 'null', 'none',
        'todo', 'fixme', 'xxx', 'development',
    ]
    
    async def validate(self, context: ValidationContext) -> ValidationResult:
        """Verify contextual validity of the finding."""
        if not context.payload_response:
            return ValidationResult.SKIP
        
        response = context.payload_response
        payload = context.payload
        
        # Check for reflection
        if payload and len(payload) > 3:
            # Basic reflection check
            if payload in response:
                context.reflection_found = True
                
                # Check if reflection is in a benign context
                for benign_pattern in self.BENIGN_CONTEXTS:
                    for match in re.finditer(benign_pattern, response, re.DOTALL | re.MULTILINE):
                        if payload in match.group():
                            context.notes.append("Payload reflected in benign context (comment/CDATA)")
                            return ValidationResult.FAIL
                
                # Check if near false positive values
                payload_pos = response.find(payload)
                surrounding = response[max(0, payload_pos - 100):payload_pos + len(payload) + 100].lower()
                
                for fp_value in self.FALSE_POSITIVE_VALUES:
                    if fp_value in surrounding:
                        context.notes.append(f"Near false-positive indicator: '{fp_value}'")
                        context.confidence -= 0.1
                        break
                
                context.notes.append("Payload reflected in response")
                return ValidationResult.PASS
            
            # Check for encoded reflection
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload)
            if encoded_payload in response and encoded_payload != payload:
                context.reflection_found = True
                context.notes.append("Payload reflected (URL encoded)")
                return ValidationResult.PASS
        
        # If no reflection required for this vuln type, check for behavior change
        if context.original_response and context.payload_response:
            # Significant behavior change
            orig_len = len(context.original_response)
            payload_len = len(context.payload_response)
            
            if abs(payload_len - orig_len) > orig_len * 0.2:  # >20% length change
                context.behavior_change = True
                context.notes.append(f"Significant length change: {orig_len} → {payload_len}")
                return ValidationResult.PASS
        
        return ValidationResult.NEEDS_VERIFICATION
    
    def get_confidence_adjustment(self, result: ValidationResult) -> float:
        if result == ValidationResult.PASS:
            return 0.2
        elif result == ValidationResult.FAIL:
            return -0.3
        return 0.0


class SecondaryValidationStage(ValidationStageHandler):
    """
    Stage 3: Secondary validation with control payload.
    
    Uses a control payload to distinguish true positives from
    server behavior that would occur for any input.
    """
    
    # Control payloads by vulnerability type
    CONTROL_PAYLOADS = {
        "SQL Injection": "1",  # Non-malicious value
        "XSS": "test123",
        "Command Injection": "echo test",
        "XXE": "<test>control</test>",
        "LFI": "nonexistent.txt",
        "SSTI": "test{{test}}",
    }
    
    async def validate(self, context: ValidationContext) -> ValidationResult:
        """Compare with control payload response."""
        if not context.control_response:
            return ValidationResult.SKIP
        
        payload_resp = context.payload_response or ""
        control_resp = context.control_response
        
        # If both responses are identical, might be false positive
        if payload_resp == control_resp:
            context.notes.append("Response identical to control - possible false positive")
            return ValidationResult.FAIL
        
        # Check if payload response has unique error patterns
        payload_has_error = self._has_vuln_indicators(context.vuln_type, payload_resp)
        control_has_error = self._has_vuln_indicators(context.vuln_type, control_resp)
        
        if payload_has_error and not control_has_error:
            context.notes.append("Vuln indicators present in payload response but not control")
            return ValidationResult.PASS
        
        if payload_has_error and control_has_error:
            context.notes.append("Vuln indicators in both responses - investigate site stability")
            return ValidationResult.NEEDS_VERIFICATION
        
        return ValidationResult.FAIL
    
    def _has_vuln_indicators(self, vuln_type: str, response: str) -> bool:
        """Check if response has vulnerability indicators."""
        patterns = SignatureDetectionStage.SIGNATURES.get(vuln_type, [])
        for pattern in patterns:
            try:
                if re.search(pattern, response, re.I):
                    return True
            except re.error:
                continue
        return False
    
    def get_confidence_adjustment(self, result: ValidationResult) -> float:
        if result == ValidationResult.PASS:
            return 0.25
        elif result == ValidationResult.FAIL:
            return -0.4
        return 0.0


class NoiseFilterStage(ValidationStageHandler):
    """
    Stage 4: Noise filtering.
    
    Final stage to filter out common noise patterns:
    - Generic error pages
    - Length-based false positives
    - Known safe patterns
    """
    
    # Generic error page indicators
    ERROR_PAGE_INDICATORS = [
        r"A server error occurred",
        r"Internal Server Error",
        r"Service Unavailable",
        r"404 Not Found",
        r"403 Forbidden",
        r"Page not found",
        r"An error occurred",
        r"Something went wrong",
        r"We're sorry",
        r"maintenance mode",
    ]
    
    # Minimum confidence to pass
    MIN_CONFIDENCE = 0.6
    
    async def validate(self, context: ValidationContext) -> ValidationResult:
        """Apply noise filtering."""
        response = context.payload_response or ""
        
        # Check for generic error pages
        for pattern in self.ERROR_PAGE_INDICATORS:
            if re.search(pattern, response, re.I):
                # Check if this is the ONLY indicator (generic error, not our injection)
                if context.original_response:
                    if re.search(pattern, context.original_response, re.I):
                        context.notes.append(f"Error page pattern also in original: {pattern[:30]}")
                        # Same error in original, might be generic
                        pass
                    else:
                        # New error from our payload
                        context.notes.append(f"New error pattern after injection: {pattern[:30]}")
        
        # Length-based noise filtering
        if context.original_length and context.payload_length:
            diff = abs(context.payload_length - context.original_length)
            
            # Very small differences might be timestamps/random tokens
            if diff < 10:
                context.notes.append("Response length difference < 10 bytes")
        
        # Final confidence check
        if context.confidence < self.MIN_CONFIDENCE:
            context.notes.append(f"Confidence {context.confidence:.2f} below threshold {self.MIN_CONFIDENCE}")
            return ValidationResult.FAIL
        
        return ValidationResult.PASS
    
    def get_confidence_adjustment(self, result: ValidationResult) -> float:
        return 0.0  # No adjustment at final stage


class ValidationPipeline:
    """
    Multi-stage validation pipeline for vulnerability findings.
    
    Runs findings through multiple validation stages to reduce false positives.
    """
    
    def __init__(self, min_confidence: float = 0.6):
        self.min_confidence = min_confidence
        self.stages: List[Tuple[str, ValidationStageHandler]] = [
            ("signature", SignatureDetectionStage()),
            ("contextual", ContextualConfirmationStage()),
            ("secondary", SecondaryValidationStage()),
            ("noise_filter", NoiseFilterStage()),
        ]
        
        # Stats
        self.validated = 0
        self.rejected = 0
    
    async def validate(
        self,
        vuln_type: str,
        url: str,
        payload: str,
        details: str,
        original_response: Optional[str] = None,
        payload_response: Optional[str] = None,
        control_response: Optional[str] = None,
        **kwargs
    ) -> Tuple[bool, float, List[str]]:
        """
        Validate a potential vulnerability finding.
        
        Args:
            vuln_type: Type of vulnerability
            url: Target URL
            payload: Payload used
            details: Finding details
            original_response: Response without payload
            payload_response: Response with payload
            control_response: Response with control (benign) payload
            **kwargs: Additional context
        
        Returns:
            (is_valid, confidence, notes): Validation result
        """
        context = ValidationContext(
            vuln_type=vuln_type,
            url=url,
            payload=payload,
            details=details,
            original_response=original_response,
            original_length=len(original_response) if original_response else None,
            payload_response=payload_response,
            payload_length=len(payload_response) if payload_response else None,
            control_response=control_response,
            control_length=len(control_response) if control_response else None,
        )
        
        # Run through stages
        for stage_name, handler in self.stages:
            try:
                result = await handler.validate(context)
                context.stage_results[stage_name] = result
                
                # Adjust confidence
                adjustment = handler.get_confidence_adjustment(result)
                context.confidence = max(0.0, min(1.0, context.confidence + adjustment))
                
                # Early termination on definite fail
                if result == ValidationResult.FAIL and stage_name in ["signature", "contextual"]:
                    # Allow to continue but with penalty
                    pass
                    
            except Exception as e:
                context.notes.append(f"Stage {stage_name} error: {str(e)}")
        
        # Final decision
        is_valid = context.confidence >= self.min_confidence
        
        if is_valid:
            self.validated += 1
        else:
            self.rejected += 1
        
        return is_valid, context.confidence, context.notes
    
    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        total = self.validated + self.rejected
        return {
            "validated": self.validated,
            "rejected": self.rejected,
            "rejection_rate": f"{(self.rejected / total * 100):.1f}%" if total > 0 else "0%"
        }


class BaselineComparator:
    """
    Compare baseline, payload, and control responses.
    
    This helps eliminate false positives by comparing:
    - Original (clean) request
    - Request with payload
    - Request with benign control value
    """
    
    def __init__(
        self,
        length_threshold: float = 0.1,
        pattern_threshold: int = 3
    ):
        self.length_threshold = length_threshold
        self.pattern_threshold = pattern_threshold
    
    async def compare(
        self,
        original: str,
        payload_response: str,
        control: Optional[str] = None
    ) -> BaselineResult:
        """
        Compare responses and determine if changes are significant.
        
        Args:
            original: Original response (no payload)
            payload_response: Response with payload
            control: Response with control value (optional)
        
        Returns:
            BaselineResult with comparison details
        """
        orig_len = len(original)
        payload_len = len(payload_response)
        
        # Length comparison
        length_diff = abs(payload_len - orig_len)
        length_diff_percent = length_diff / orig_len if orig_len > 0 else 0
        
        # Status would be extracted from response objects
        status_changed = False  # Would need full response objects
        
        # Find unique patterns in payload response
        unique_patterns = self._find_unique_patterns(original, payload_response)
        
        # Determine significance
        is_significant = (
            length_diff_percent > self.length_threshold or
            len(unique_patterns) >= self.pattern_threshold
        )
        
        # Calculate confidence adjustment
        confidence_adjustment = 0.0
        if is_significant:
            confidence_adjustment = min(0.3, length_diff_percent + len(unique_patterns) * 0.05)
        
        # If control provided, compare
        if control:
            control_len = len(control)
            control_unique = self._find_unique_patterns(original, control)
            
            # If control also has the patterns, less significant
            overlap = set(unique_patterns) & set(control_unique)
            if overlap:
                confidence_adjustment -= 0.2 * (len(overlap) / len(unique_patterns))
        
        return BaselineResult(
            is_significant=is_significant,
            length_diff=length_diff,
            length_diff_percent=length_diff_percent,
            status_changed=status_changed,
            unique_patterns=unique_patterns,
            confidence_adjustment=confidence_adjustment
        )
    
    def _find_unique_patterns(self, original: str, modified: str) -> List[str]:
        """Find patterns present in modified but not original."""
        unique = []
        
        # Look for error patterns
        error_patterns = [
            r"error", r"exception", r"warning", r"syntax",
            r"SQL", r"mysql", r"ORA-", r"postgresql"
        ]
        
        for pattern in error_patterns:
            orig_matches = len(re.findall(pattern, original, re.I))
            mod_matches = len(re.findall(pattern, modified, re.I))
            
            if mod_matches > orig_matches:
                unique.append(pattern)
        
        return unique


class ContextAwareRegex:
    """
    Context-aware regex matching that avoids false positives.
    
    Features:
    - Skip matches inside comments
    - Skip test values
    - Skip minified placeholder code
    - Validate via follow-up request
    """
    
    # Contexts to exclude
    EXCLUDE_CONTEXTS = [
        (r'<!--', r'-->'),  # HTML comments
        (r'/\*', r'\*/'),   # Block comments
        (r'"', r'"'),       # String literals (be careful)
        (r"'", r"'"),       # String literals
    ]
    
    # False positive indicators
    FALSE_POSITIVE_INDICATORS = [
        r'\btest\b', r'\bexample\b', r'\bsample\b', r'\bdemo\b',
        r'\bdummy\b', r'\bfoo\b', r'\bbar\b', r'\bplaceholder\b',
        r'\blorem\b', r'\bipsum\b', r'\btodo\b', r'\bfixme\b',
    ]
    
    # Minified code indicators
    MINIFIED_INDICATORS = [
        r'[a-z]\.[a-z]\([a-z]\)',  # a.b(c) pattern
        r'function\([a-z],[a-z],[a-z]\)',  # function(a,b,c)
        r';[a-z]=',  # ;a=
    ]
    
    def __init__(self, skip_comments: bool = True, skip_test_values: bool = True):
        self.skip_comments = skip_comments
        self.skip_test_values = skip_test_values
    
    def search(
        self,
        pattern: str,
        text: str,
        flags: int = 0
    ) -> List[Tuple[int, int, str]]:
        """
        Search for pattern, filtering out false positive contexts.
        
        Returns:
            List of (start, end, match_text) tuples for valid matches
        """
        valid_matches = []
        
        try:
            regex = re.compile(pattern, flags)
        except re.error:
            return []
        
        # Find all excluded regions
        excluded_regions = []
        if self.skip_comments:
            excluded_regions.extend(self._find_excluded_regions(text))
        
        for match in regex.finditer(text):
            start, end = match.start(), match.end()
            matched_text = match.group()
            
            # Check if in excluded region
            in_excluded = False
            for ex_start, ex_end in excluded_regions:
                if ex_start <= start < ex_end or ex_start < end <= ex_end:
                    in_excluded = True
                    break
            
            if in_excluded:
                continue
            
            # Check for false positive indicators nearby
            if self.skip_test_values:
                surrounding = text[max(0, start - 50):end + 50]
                is_test_value = any(
                    re.search(fp_pattern, surrounding, re.I)
                    for fp_pattern in self.FALSE_POSITIVE_INDICATORS
                )
                if is_test_value:
                    continue
            
            valid_matches.append((start, end, matched_text))
        
        return valid_matches
    
    def _find_excluded_regions(self, text: str) -> List[Tuple[int, int]]:
        """Find regions to exclude (comments, strings, etc.)."""
        regions = []
        
        # HTML comments
        for match in re.finditer(r'<!--.*?-->', text, re.DOTALL):
            regions.append((match.start(), match.end()))
        
        # Block comments
        for match in re.finditer(r'/\*.*?\*/', text, re.DOTALL):
            regions.append((match.start(), match.end()))
        
        # Line comments (be careful not to over-match URLs)
        for match in re.finditer(r'^\s*//.*$', text, re.MULTILINE):
            regions.append((match.start(), match.end()))
        
        return regions
    
    def is_likely_minified(self, code: str, threshold: float = 0.5) -> bool:
        """Check if code appears to be minified."""
        if not code:
            return False
        
        # Check line length (minified = very long lines)
        lines = code.split('\n')
        avg_line_length = sum(len(l) for l in lines) / len(lines) if lines else 0
        
        if avg_line_length > 500:
            return True
        
        # Check for minified patterns
        pattern_count = sum(
            len(re.findall(pattern, code))
            for pattern in self.MINIFIED_INDICATORS
        )
        
        pattern_density = pattern_count / (len(code) / 1000)  # per 1000 chars
        
        return pattern_density > threshold
