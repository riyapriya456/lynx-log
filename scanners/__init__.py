from .sqli import SQLiScanner
from .xss import SeleniumXSSScanner
from .injection import HTMLInjectionScanner, CommandInjectionScanner, XXEScanner, LFIScanner
from .misconfig import SecurityHeadersCheck, CORSCheck, CMSScanner
from .ssrf import SSRFScanner
from .idor import IDORScanner
from .csrf import CSRFScanner
from .redirect import OpenRedirectScanner
from .js_analyzer import JSAnalyzerScanner

# New scanners from vulnerability checklist
from .bypass403 import Bypass403Scanner
from .auth_bypass import AuthBypassScanner
from .rate_limit import RateLimitBypassScanner
from .twofa_bypass import TwoFABypassScanner
from .json_attack import JSONAttackScanner
from .mass_assignment import MassAssignmentScanner
from .cookie_attack import CookieAttackScanner
from .password_reset import PasswordResetScanner

# Bug bounty specialized scanners
from .jwt import JWTScanner
from .ssti import SSTIScanner
from .graphql import GraphQLScanner
from .file_upload import FileUploadScanner
from .websocket import WebSocketScanner

# Advanced scanners
from .param_fuzzer import ParamFuzzer
from .dom_security import DOMSecurityScanner
from .recon import ReconScanner



def get_all_scanners():
    """Return all available scanner classes."""
    return [
        # Core injection scanners
        SQLiScanner,
        SeleniumXSSScanner,
        HTMLInjectionScanner,
        CommandInjectionScanner,
        XXEScanner,
        LFIScanner,
        
        # Configuration scanners
        SecurityHeadersCheck,
        CORSCheck,
        CMSScanner,
        
        # Logic/access control scanners
        SSRFScanner,
        IDORScanner,
        CSRFScanner,
        OpenRedirectScanner,
        
        # JavaScript analysis scanner
        JSAnalyzerScanner,
        
        # New vulnerability checklist scanners
        Bypass403Scanner,
        AuthBypassScanner,
        RateLimitBypassScanner,
        TwoFABypassScanner,
        JSONAttackScanner,
        MassAssignmentScanner,
        CookieAttackScanner,
        PasswordResetScanner,
        
        # Bug bounty specialized scanners
        JWTScanner,
        SSTIScanner,
        GraphQLScanner,
        FileUploadScanner,
        WebSocketScanner,
        
        # Advanced scanners
        ParamFuzzer,
        DOMSecurityScanner,
        ReconScanner,
    ]



def get_checklist_scanners():
    """Return only the new checklist-based scanners."""
    return [
        Bypass403Scanner,
        AuthBypassScanner,
        RateLimitBypassScanner,
        TwoFABypassScanner,
        JSONAttackScanner,
        MassAssignmentScanner,
        CookieAttackScanner,
        PasswordResetScanner,
    ]



def get_bug_bounty_scanners():
    """Return bug bounty specialized scanners."""
    return [
        JWTScanner,
        SSTIScanner,
        GraphQLScanner,
        FileUploadScanner,
        WebSocketScanner,
    ]


def get_advanced_scanners():
    """Return advanced analysis scanners."""
    return [
        ParamFuzzer,
        DOMSecurityScanner,
        ReconScanner,
    ]


SCANNER_PROFILES = {
    "SecurityHeadersCheck": {"cost": "low", "priority": 10},
    "CORSCheck": {"cost": "low", "priority": 12},
    "CMSScanner": {"cost": "low", "priority": 14},
    "JSAnalyzerScanner": {"cost": "low", "priority": 16},
    "OpenRedirectScanner": {"cost": "medium", "priority": 24},
    "SQLiScanner": {"cost": "medium", "priority": 26},
    "HTMLInjectionScanner": {"cost": "medium", "priority": 28},
    "CommandInjectionScanner": {"cost": "medium", "priority": 30},
    "XXEScanner": {"cost": "medium", "priority": 32},
    "LFIScanner": {"cost": "medium", "priority": 34},
    "SSRFScanner": {"cost": "medium", "priority": 36},
    "IDORScanner": {"cost": "medium", "priority": 38},
    "CSRFScanner": {"cost": "medium", "priority": 40},
    "Bypass403Scanner": {"cost": "medium", "priority": 42},
    "AuthBypassScanner": {"cost": "medium", "priority": 44},
    "RateLimitBypassScanner": {"cost": "medium", "priority": 46},
    "TwoFABypassScanner": {"cost": "medium", "priority": 48},
    "JSONAttackScanner": {"cost": "medium", "priority": 50},
    "MassAssignmentScanner": {"cost": "medium", "priority": 52},
    "CookieAttackScanner": {"cost": "medium", "priority": 54},
    "PasswordResetScanner": {"cost": "medium", "priority": 56},
    "JWTScanner": {"cost": "medium", "priority": 58},
    "SSTIScanner": {"cost": "high", "priority": 62},
    "GraphQLScanner": {"cost": "high", "priority": 64},
    "FileUploadScanner": {"cost": "high", "priority": 66},
    "WebSocketScanner": {"cost": "high", "priority": 68},
    "ParamFuzzer": {"cost": "high", "priority": 70},
    "DOMSecurityScanner": {"cost": "high", "priority": 72},
    "ReconScanner": {"cost": "high", "priority": 74},
    "SeleniumXSSScanner": {"cost": "high", "priority": 76},
}


def get_scanner_profile(scanner_name: str):
    """Return a profile for a scanner class name."""
    return SCANNER_PROFILES.get(scanner_name, {"cost": "medium", "priority": 100})
