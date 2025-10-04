"""
GF Pattern Analyzer Utility for HyperRecon Pro v4.0
Advanced URL pattern analysis using GF (Grep-like) patterns

This module provides comprehensive URL pattern analysis capabilities including:
- GF pattern-based URL filtering and categorization
- Security-focused pattern matching (XSS, SQLi, SSRF, etc.)
- Custom pattern support and management
- Organized pattern-based file structure
- Vulnerability-focused URL analysis
"""

import os
import re
import json
import subprocess
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .base_utility import BaseUtility, UtilityResult
from .error_handler import ErrorCategory


@dataclass
class PatternMatch:
    """Information about a pattern match"""
    pattern_name: str
    pattern_description: str
    vulnerability_type: str
    risk_level: str
    urls: List[str] = field(default_factory=list)
    count: int = 0
    parameters: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


class GFPatternAnalyzer(BaseUtility):
    """
    Advanced GF pattern analyzer for security-focused URL analysis
    Identifies potential vulnerabilities using pattern matching
    """

    def __init__(self, hyperrecon_instance):
        """Initialize GF Pattern Analyzer with comprehensive patterns"""
        super().__init__(hyperrecon_instance)
        
        # GF patterns with security focus
        self.gf_patterns = {
            # Injection Vulnerabilities
            'xss': {
                'description': 'Cross-Site Scripting (XSS) patterns',
                'vulnerability_type': 'XSS',
                'risk_level': 'HIGH',
                'patterns': [
                    r'[?&](q|query|search|keyword|term)=',
                    r'[?&](message|msg|text|comment|content)=',
                    r'[?&](name|title|subject|description)=',
                    r'[?&](callback|jsonp)=',
                    r'[?&](html|data|input|value)='
                ],
                'parameters': ['q', 'query', 'search', 'message', 'callback', 'html']
            },
            
            'sqli': {
                'description': 'SQL Injection patterns',
                'vulnerability_type': 'SQLi',
                'risk_level': 'CRITICAL',
                'patterns': [
                    r'[?&](id|user_id|product_id|item_id)=\d+',
                    r'[?&](category|cat|type|sort|order)=',
                    r'[?&](table|column|field|db)=',
                    r'[?&](limit|offset|page|count)=\d+',
                    r'[?&](filter|where|having)='
                ],
                'parameters': ['id', 'user_id', 'category', 'table', 'limit', 'filter']
            },
            
            'ssrf': {
                'description': 'Server-Side Request Forgery patterns',
                'vulnerability_type': 'SSRF',
                'risk_level': 'HIGH',
                'patterns': [
                    r'[?&](url|uri|link|href|src)=',
                    r'[?&](redirect|return|next|continue)=',
                    r'[?&](proxy|gateway|fetch|load)=',
                    r'[?&](host|server|domain|endpoint)=',
                    r'[?&](api|webhook|callback)='
                ],
                'parameters': ['url', 'redirect', 'proxy', 'host', 'api']
            },
            
            'lfi': {
                'description': 'Local File Inclusion patterns',
                'vulnerability_type': 'LFI',
                'risk_level': 'HIGH',
                'patterns': [
                    r'[?&](file|path|page|include|require)=',
                    r'[?&](template|view|layout|theme)=',
                    r'[?&](document|doc|pdf|download)=',
                    r'[?&](config|conf|settings)=',
                    r'[?&](lang|language|locale)='
                ],
                'parameters': ['file', 'path', 'template', 'document', 'config']
            },
            
            'rce': {
                'description': 'Remote Code Execution patterns',
                'vulnerability_type': 'RCE',
                'risk_level': 'CRITICAL',
                'patterns': [
                    r'[?&](cmd|command|exec|system)=',
                    r'[?&](shell|bash|powershell|ps)=',
                    r'[?&](eval|execute|run|call)=',
                    r'[?&](function|method|action)=',
                    r'[?&](code|script|program)='
                ],
                'parameters': ['cmd', 'exec', 'shell', 'eval', 'function']
            },
            
            # Authentication & Authorization
            'auth_bypass': {
                'description': 'Authentication bypass patterns',
                'vulnerability_type': 'Auth Bypass',
                'risk_level': 'HIGH',
                'patterns': [
                    r'[?&](admin|administrator|root|superuser)=',
                    r'[?&](role|privilege|permission|access)=',
                    r'[?&](token|key|secret|hash)=',
                    r'[?&](login|auth|authenticate|signin)=',
                    r'[?&](user|username|userid|uid)='
                ],
                'parameters': ['admin', 'role', 'token', 'login', 'user']
            },
            
            'idor': {
                'description': 'Insecure Direct Object Reference patterns',
                'vulnerability_type': 'IDOR',
                'risk_level': 'MEDIUM',
                'patterns': [
                    r'[?&](id|user_id|account_id|profile_id)=\d+',
                    r'[?&](file_id|doc_id|item_id|object_id)=\d+',
                    r'[?&](order_id|transaction_id|payment_id)=\d+',
                    r'[?&](session_id|sess_id|sid)=',
                    r'[?&](uuid|guid|reference|ref)='
                ],
                'parameters': ['id', 'user_id', 'file_id', 'session_id', 'uuid']
            },
            
            # Information Disclosure
            'debug': {
                'description': 'Debug and development patterns',
                'vulnerability_type': 'Info Disclosure',
                'risk_level': 'MEDIUM',
                'patterns': [
                    r'[?&](debug|test|dev|development)=',
                    r'[?&](trace|log|verbose|detail)=',
                    r'[?&](error|exception|stack|dump)=',
                    r'[?&](info|information|status|health)=',
                    r'[?&](version|ver|build|revision)='
                ],
                'parameters': ['debug', 'trace', 'error', 'info', 'version']
            },
            
            'sensitive_data': {
                'description': 'Sensitive data exposure patterns',
                'vulnerability_type': 'Data Exposure',
                'risk_level': 'MEDIUM',
                'patterns': [
                    r'[?&](email|mail|address|contact)=',
                    r'[?&](phone|mobile|tel|number)=',
                    r'[?&](ssn|social|tax|credit)=',
                    r'[?&](password|pass|pwd|secret)=',
                    r'[?&](api_key|apikey|access_token)='
                ],
                'parameters': ['email', 'phone', 'ssn', 'password', 'api_key']
            },
            
            # Business Logic
            'business_logic': {
                'description': 'Business logic vulnerability patterns',
                'vulnerability_type': 'Business Logic',
                'risk_level': 'MEDIUM',
                'patterns': [
                    r'[?&](price|cost|amount|total|sum)=',
                    r'[?&](quantity|qty|count|number)=',
                    r'[?&](discount|coupon|promo|offer)=',
                    r'[?&](balance|credit|debit|payment)=',
                    r'[?&](status|state|flag|enabled)='
                ],
                'parameters': ['price', 'quantity', 'discount', 'balance', 'status']
            }
        }
        
        # Risk level priorities
        self.risk_priorities = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }

    def execute(self, urls: List[str], domain_path: str) -> UtilityResult:
        """
        Execute GF pattern analysis on provided URLs
        
        Args:
            urls: List of URLs to analyze for patterns
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult with pattern analysis results
        """
        self.start_execution()
        self.set_operation("gf_pattern_analysis")
        
        try:
            if not urls:
                self.log_warning("No URLs provided for GF pattern analysis")
                return self.create_result(True, {'patterns': {}, 'summary': {}}, 0)
            
            self.log_info(f"Starting GF pattern analysis on {len(urls)} URLs")
            
            # Analyze URLs with GF patterns
            pattern_matches = self._analyze_urls_with_patterns(urls)
            
            # Generate vulnerability analysis
            vulnerability_analysis = self._analyze_vulnerabilities(pattern_matches)
            
            # Create comprehensive summary
            summary = self._generate_pattern_summary(pattern_matches, vulnerability_analysis)
            
            # Save pattern results
            self._save_pattern_results(domain_path, pattern_matches, vulnerability_analysis, summary)
            
            result_data = {
                'patterns': pattern_matches,
                'vulnerability_analysis': vulnerability_analysis,
                'summary': summary,
                'total_urls': len(urls),
                'matched_urls': sum(len(match.urls) for match in pattern_matches.values()),
                'patterns_found': len(pattern_matches)
            }
            
            self.log_info(f"GF pattern analysis completed: {len(pattern_matches)} patterns matched, {result_data['matched_urls']} URLs with patterns")
            
            return self.create_result(True, result_data, len(urls))
            
        except Exception as e:
            self.log_error("GF pattern analysis failed", e, ErrorCategory.PROCESSING_ERROR)
            return self.create_result(False, {'error': str(e)}, 0)

    def _analyze_urls_with_patterns(self, urls: List[str]) -> Dict[str, PatternMatch]:
        """Analyze URLs using GF patterns"""
        pattern_matches = {}
        
        for pattern_name, pattern_info in self.gf_patterns.items():
            matched_urls = []
            parameters_found = set()
            
            for url in urls:
                try:
                    # Check each pattern in the pattern group
                    for pattern in pattern_info['patterns']:
                        if re.search(pattern, url, re.IGNORECASE):
                            matched_urls.append(url)
                            
                            # Extract parameters
                            parsed_url = urlparse(url)
                            if parsed_url.query:
                                params = parse_qs(parsed_url.query)
                                for param in params.keys():
                                    if param.lower() in [p.lower() for p in pattern_info['parameters']]:
                                        parameters_found.add(param)
                            break
                            
                except Exception as e:
                    self.log_warning(f"Failed to analyze URL {url} with pattern {pattern_name}: {str(e)}")
                    continue
            
            if matched_urls:
                pattern_matches[pattern_name] = PatternMatch(
                    pattern_name=pattern_name,
                    pattern_description=pattern_info['description'],
                    vulnerability_type=pattern_info['vulnerability_type'],
                    risk_level=pattern_info['risk_level'],
                    urls=list(set(matched_urls)),  # Remove duplicates
                    count=len(set(matched_urls)),
                    parameters=list(parameters_found),
                    examples=matched_urls[:5]  # First 5 as examples
                )
        
        return pattern_matches

    def _analyze_vulnerabilities(self, pattern_matches: Dict[str, PatternMatch]) -> Dict[str, Any]:
        """Analyze vulnerability implications of pattern matches"""
        analysis = {
            'vulnerability_distribution': defaultdict(int),
            'risk_distribution': defaultdict(int),
            'critical_vulnerabilities': [],
            'high_risk_patterns': [],
            'vulnerability_recommendations': [],
            'attack_scenarios': [],
            'priority_targets': []
        }
        
        for pattern_name, match in pattern_matches.items():
            vuln_type = match.vulnerability_type
            risk_level = match.risk_level
            count = match.count
            
            # Update distributions
            analysis['vulnerability_distribution'][vuln_type] += count
            analysis['risk_distribution'][risk_level] += count
            
            # Identify critical vulnerabilities
            if risk_level == 'CRITICAL':
                analysis['critical_vulnerabilities'].append({
                    'pattern': pattern_name,
                    'vulnerability_type': vuln_type,
                    'count': count,
                    'description': match.pattern_description,
                    'examples': match.examples
                })
            
            # Identify high-risk patterns
            if risk_level in ['CRITICAL', 'HIGH']:
                analysis['high_risk_patterns'].append({
                    'pattern': pattern_name,
                    'risk_level': risk_level,
                    'count': count,
                    'vulnerability_type': vuln_type,
                    'parameters': match.parameters
                })
            
            # Generate attack scenarios
            scenarios = self._generate_attack_scenarios(pattern_name, match)
            analysis['attack_scenarios'].extend(scenarios)
        
        # Generate recommendations
        analysis['vulnerability_recommendations'] = self._generate_vulnerability_recommendations(pattern_matches)
        
        # Calculate priority targets
        priority_targets = []
        for pattern_name, match in pattern_matches.items():
            priority_score = self._calculate_vulnerability_priority(match.risk_level, match.count)
            priority_targets.append({
                'pattern': pattern_name,
                'vulnerability_type': match.vulnerability_type,
                'priority_score': priority_score,
                'risk_level': match.risk_level,
                'count': match.count
            })
        
        analysis['priority_targets'] = sorted(priority_targets, key=lambda x: x['priority_score'], reverse=True)[:10]
        
        return analysis

    def _generate_attack_scenarios(self, pattern_name: str, match: PatternMatch) -> List[Dict[str, str]]:
        """Generate attack scenarios for pattern matches"""
        scenarios = []
        
        scenario_templates = {
            'xss': [
                "Inject malicious JavaScript through search parameters",
                "Perform DOM-based XSS via callback parameters",
                "Execute stored XSS through message/comment fields"
            ],
            'sqli': [
                "Perform UNION-based SQL injection via ID parameters",
                "Execute blind SQL injection through filter parameters",
                "Attempt time-based SQL injection via sorting parameters"
            ],
            'ssrf': [
                "Access internal services via URL parameters",
                "Perform port scanning through redirect parameters",
                "Access cloud metadata via proxy parameters"
            ],
            'lfi': [
                "Access sensitive files via file parameters",
                "Perform directory traversal through path parameters",
                "Read configuration files via include parameters"
            ],
            'rce': [
                "Execute system commands via cmd parameters",
                "Perform code injection through eval parameters",
                "Execute shell commands via exec parameters"
            ]
        }
        
        if pattern_name in scenario_templates:
            for scenario in scenario_templates[pattern_name]:
                scenarios.append({
                    'pattern': pattern_name,
                    'vulnerability_type': match.vulnerability_type,
                    'scenario': scenario,
                    'risk_level': match.risk_level
                })
        
        return scenarios

    def _calculate_vulnerability_priority(self, risk_level: str, count: int) -> int:
        """Calculate vulnerability priority score"""
        base_score = self.risk_priorities.get(risk_level, 1) * 25
        count_bonus = min(count * 2, 25)  # Max 25 bonus points
        return base_score + count_bonus

    def _generate_vulnerability_recommendations(self, pattern_matches: Dict[str, PatternMatch]) -> List[str]:
        """Generate vulnerability-specific recommendations"""
        recommendations = []
        
        # Check for critical vulnerabilities
        critical_patterns = [name for name, match in pattern_matches.items() if match.risk_level == 'CRITICAL']
        if critical_patterns:
            recommendations.append(f"URGENT: Test {len(critical_patterns)} critical vulnerability patterns immediately")
        
        # Specific recommendations by vulnerability type
        vuln_types = set(match.vulnerability_type for match in pattern_matches.values())
        
        if 'SQLi' in vuln_types:
            recommendations.append("Implement parameterized queries and input validation for SQL injection prevention")
        
        if 'XSS' in vuln_types:
            recommendations.append("Apply output encoding and Content Security Policy for XSS protection")
        
        if 'SSRF' in vuln_types:
            recommendations.append("Implement URL validation and network segmentation for SSRF prevention")
        
        if 'RCE' in vuln_types:
            recommendations.append("Remove or secure command execution functionality immediately")
        
        if 'LFI' in vuln_types:
            recommendations.append("Implement file access controls and input sanitization")
        
        # General recommendations
        high_risk_count = sum(1 for match in pattern_matches.values() if match.risk_level in ['CRITICAL', 'HIGH'])
        if high_risk_count > 5:
            recommendations.append("Conduct comprehensive security testing and code review")
            recommendations.append("Implement Web Application Firewall (WAF) protection")
        
        if not recommendations:
            recommendations.append("Continue monitoring for new vulnerability patterns")
        
        return recommendations

    def _generate_pattern_summary(self, pattern_matches: Dict[str, PatternMatch], 
                                vulnerability_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive pattern analysis summary"""
        
        total_matches = sum(match.count for match in pattern_matches.values())
        total_patterns = len(pattern_matches)
        
        # Calculate statistics
        vuln_stats = dict(vulnerability_analysis['vulnerability_distribution'])
        risk_stats = dict(vulnerability_analysis['risk_distribution'])
        
        # Top patterns by count
        top_patterns = sorted(
            [(name, match.count, match.risk_level, match.vulnerability_type) 
             for name, match in pattern_matches.items()],
            key=lambda x: x[1], reverse=True
        )[:10]
        
        # Critical and high-risk counts
        critical_count = risk_stats.get('CRITICAL', 0)
        high_risk_count = risk_stats.get('HIGH', 0)
        
        return {
            'total_urls_matched': total_matches,
            'total_patterns_found': total_patterns,
            'vulnerability_distribution': vuln_stats,
            'risk_distribution': risk_stats,
            'top_patterns': top_patterns,
            'critical_vulnerabilities': critical_count,
            'high_risk_vulnerabilities': high_risk_count,
            'vulnerability_score': self._calculate_vulnerability_score(risk_stats),
            'analysis_timestamp': datetime.now().isoformat(),
            'recommendations_count': len(vulnerability_analysis['vulnerability_recommendations']),
            'attack_scenarios_count': len(vulnerability_analysis['attack_scenarios']),
            'priority_targets_count': len(vulnerability_analysis['priority_targets'])
        }

    def _calculate_vulnerability_score(self, risk_stats: Dict[str, int]) -> Dict[str, Any]:
        """Calculate overall vulnerability score"""
        total_matches = sum(risk_stats.values())
        if total_matches == 0:
            return {'score': 100, 'level': 'SECURE', 'description': 'No vulnerability patterns found'}
        
        # Weight different risk levels (negative impact)
        weights = {'CRITICAL': -40, 'HIGH': -25, 'MEDIUM': -10, 'LOW': -5}
        
        weighted_score = sum(risk_stats.get(risk, 0) * weight for risk, weight in weights.items())
        base_score = 100
        normalized_penalty = weighted_score / total_matches if total_matches > 0 else 0
        final_score = max(0, min(100, base_score + normalized_penalty))
        
        # Determine vulnerability level
        if final_score >= 90:
            level = 'SECURE'
        elif final_score >= 70:
            level = 'LOW_RISK'
        elif final_score >= 50:
            level = 'MODERATE_RISK'
        elif final_score >= 30:
            level = 'HIGH_RISK'
        else:
            level = 'CRITICAL_RISK'
        
        return {
            'score': round(final_score, 1),
            'level': level,
            'description': f'Vulnerability score based on {total_matches} pattern matches'
        }

    def _save_pattern_results(self, domain_path: str, pattern_matches: Dict[str, PatternMatch],
                            vulnerability_analysis: Dict[str, Any], summary: Dict[str, Any]):
        """Save GF pattern analysis results to files"""
        try:
            # Save pattern matches by vulnerability type
            for pattern_name, match in pattern_matches.items():
                # Clean pattern name for filename
                clean_name = pattern_name.replace('/', '_').replace(' ', '_')
                
                # Create vulnerability type subdirectory
                vuln_type_clean = match.vulnerability_type.replace('/', '_').replace(' ', '_')
                
                # Save URLs for this pattern
                pattern_content = []
                pattern_content.append(f"# {pattern_name.upper()} Pattern Matches")
                pattern_content.append(f"# Vulnerability Type: {match.vulnerability_type}")
                pattern_content.append(f"# Risk Level: {match.risk_level}")
                pattern_content.append(f"# Description: {match.pattern_description}")
                pattern_content.append(f"# Total Matches: {match.count}")
                pattern_content.append("")
                
                if match.parameters:
                    pattern_content.append("# Common Parameters:")
                    for param in match.parameters:
                        pattern_content.append(f"# - {param}")
                    pattern_content.append("")
                
                pattern_content.append("# Matched URLs:")
                pattern_content.extend(match.urls)
                
                self.save_results(domain_path, f'gf_patterns/{vuln_type_clean}', 
                                f'{clean_name}_urls.txt', '\n'.join(pattern_content))
            
            # Save comprehensive summary
            self.save_results(domain_path, 'gf_patterns', 'pattern_summary.json',
                            json.dumps(summary, indent=2))
            
            # Save vulnerability analysis
            # Convert defaultdict to regular dict for JSON serialization
            vuln_analysis_clean = {}
            for key, value in vulnerability_analysis.items():
                if isinstance(value, defaultdict):
                    vuln_analysis_clean[key] = dict(value)
                else:
                    vuln_analysis_clean[key] = value
            
            self.save_results(domain_path, 'gf_patterns', 'vulnerability_analysis.json',
                            json.dumps(vuln_analysis_clean, indent=2))
            
            # Save critical vulnerabilities report
            if vulnerability_analysis['critical_vulnerabilities']:
                critical_report = []
                critical_report.append("CRITICAL VULNERABILITY PATTERNS FOUND")
                critical_report.append("=" * 50)
                
                for vuln in vulnerability_analysis['critical_vulnerabilities']:
                    critical_report.append(f"\nPattern: {vuln['pattern']}")
                    critical_report.append(f"Vulnerability Type: {vuln['vulnerability_type']}")
                    critical_report.append(f"Count: {vuln['count']}")
                    critical_report.append(f"Description: {vuln['description']}")
                    critical_report.append("Example URLs:")
                    for url in vuln['examples']:
                        critical_report.append(f"  - {url}")
                    critical_report.append("-" * 30)
                
                self.save_results(domain_path, 'gf_patterns', 'critical_vulnerabilities.txt',
                                '\n'.join(critical_report))
            
            # Save overview
            overview = []
            overview.append("GF PATTERN ANALYSIS OVERVIEW")
            overview.append("=" * 40)
            overview.append(f"Total URLs Matched: {summary['total_urls_matched']}")
            overview.append(f"Total Patterns Found: {summary['total_patterns_found']}")
            overview.append(f"Critical Vulnerabilities: {summary['critical_vulnerabilities']}")
            overview.append(f"High Risk Vulnerabilities: {summary['high_risk_vulnerabilities']}")
            overview.append(f"Vulnerability Score: {summary['vulnerability_score']['score']}/100 ({summary['vulnerability_score']['level']})")
            overview.append("")
            
            overview.append("TOP PATTERNS BY COUNT:")
            for pattern, count, risk, vuln_type in summary['top_patterns']:
                overview.append(f"  {pattern}: {count} matches ({risk} - {vuln_type})")
            
            overview.append("")
            overview.append("VULNERABILITY RECOMMENDATIONS:")
            for i, rec in enumerate(vulnerability_analysis['vulnerability_recommendations'], 1):
                overview.append(f"  {i}. {rec}")
            
            self.save_results(domain_path, 'gf_patterns', 'overview.txt', '\n'.join(overview))
            
            self.log_info(f"GF pattern analysis results saved to {domain_path}/gf_patterns/")
            
        except Exception as e:
            self.log_error("Failed to save GF pattern results", e, ErrorCategory.FILE_ERROR)

    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """Validate dependencies for GF pattern analysis"""
        missing_deps = []
        
        try:
            import re
            import json
            from urllib.parse import urlparse, parse_qs
            from collections import defaultdict
        except ImportError as e:
            missing_deps.append(str(e))
        
        return len(missing_deps) == 0, missing_deps

    def get_supported_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Get all supported GF patterns"""
        return self.gf_patterns.copy()

    def add_custom_pattern(self, pattern_name: str, description: str, vulnerability_type: str,
                          risk_level: str, patterns: List[str], parameters: List[str]):
        """Add custom GF pattern"""
        self.gf_patterns[pattern_name] = {
            'description': description,
            'vulnerability_type': vulnerability_type,
            'risk_level': risk_level,
            'patterns': patterns,
            'parameters': parameters
        }
        
        self.log_info(f"Added custom GF pattern: {pattern_name}")

    def get_pattern_statistics(self, pattern_matches: Dict[str, PatternMatch]) -> Dict[str, Any]:
        """Get detailed statistics about pattern matches"""
        stats = {
            'total_patterns': len(pattern_matches),
            'total_matches': sum(match.count for match in pattern_matches.values()),
            'by_vulnerability_type': defaultdict(int),
            'by_risk_level': defaultdict(int),
            'most_common_parameters': defaultdict(int),
            'pattern_coverage': {}
        }
        
        for match in pattern_matches.values():
            stats['by_vulnerability_type'][match.vulnerability_type] += match.count
            stats['by_risk_level'][match.risk_level] += match.count
            
            for param in match.parameters:
                stats['most_common_parameters'][param] += 1
            
            stats['pattern_coverage'][match.pattern_name] = {
                'count': match.count,
                'risk_level': match.risk_level,
                'vulnerability_type': match.vulnerability_type
            }
        
        # Convert to regular dicts
        stats['by_vulnerability_type'] = dict(stats['by_vulnerability_type'])
        stats['by_risk_level'] = dict(stats['by_risk_level'])
        stats['most_common_parameters'] = dict(sorted(stats['most_common_parameters'].items(), 
                                                     key=lambda x: x[1], reverse=True)[:10])
        
        return stats