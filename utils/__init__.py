"""
HyperRecon Pro Utils Package
Modular components for advanced bug bounty scanning

This package provides a comprehensive set of utilities for reconnaissance tasks,
following a clean modular architecture with shared interfaces and consistent error handling.
"""

__version__ = "4.0"
__author__ = "Saurabh Tomar"

# Import base classes and shared utilities
from .base_utility import BaseUtility, UtilityResult
from .config import ConfigManager
from .file_manager import FileManager
from .uro_filter import UROFilter

# Import specialized utility modules
from .subdomain_enum import SubdomainEnumerator
from .url_collection import URLCollector
from .http_probe import HTTPProber
from .param_scan import ParamScanner
from .tech_detection import TechDetector
from .vuln_scan import VulnScanner
from .dir_brute import DirBruteforcer
from .social_recon import SocialRecon
from .js_analysis import JSAnalyzer
from .sensitive_data import SensitiveDataDetector
from .security_checks import SecurityChecker
from .document_analyzer import DocumentAnalyzer
from .extension_organizer import ExtensionOrganizer
from .gf_pattern_analyzer import GFPatternAnalyzer
from .unfurl_analyzer import UnfurlAnalyzer
from .report import ReportGenerator

__all__ = [
    # Base classes
    'BaseUtility',
    'UtilityResult',
    'ConfigManager',
    'FileManager', 
    'UROFilter',
    
    # Specialized utilities
    'SubdomainEnumerator',
    'URLCollector',
    'HTTPProber',
    'ParamScanner',
    'TechDetector',
    'VulnScanner',
    'DirBruteforcer',
    'SocialRecon',
    'JSAnalyzer',
    'SensitiveDataDetector',
    'SecurityChecker',
    'DocumentAnalyzer',
    'ExtensionOrganizer',
    'GFPatternAnalyzer',
    'UnfurlAnalyzer',
    'ReportGenerator'
]