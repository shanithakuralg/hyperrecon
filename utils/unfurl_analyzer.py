"""
Unfurl Analyzer Utility for HyperRecon Pro v4.0
Advanced URL component analysis and extraction

This module provides comprehensive URL analysis capabilities including:
- URL component extraction (domains, paths, parameters, etc.)
- Parameter analysis and categorization
- Domain and subdomain analysis
- Path structure analysis
- Query parameter security analysis
"""

import os
import re
import json
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, Counter

from .base_utility import BaseUtility, UtilityResult
from .error_handler import ErrorCategory


@dataclass
class URLComponents:
    """Extracted URL components"""
    domains: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    paths: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    extensions: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    fragments: Set[str] = field(default_factory=set)


class UnfurlAnalyzer(BaseUtility):
    """
    Advanced URL component analyzer similar to unfurl tool
    Extracts and analyzes various URL components for reconnaissance
    """

    def __init__(self, hyperrecon_instance):
        """Initialize Unfurl Analyzer"""
        super().__init__(hyperrecon_instance)
        
        # Interesting parameter patterns for security analysis
        self.interesting_parameters = {
            'authentication': [
                'token', 'auth', 'key', 'api_key', 'apikey', 'access_token',
                'session', 'sess', 'sid', 'login', 'user', 'username', 'password'
            ],
            'file_operations': [
                'file', 'path', 'filename', 'document', 'doc', 'pdf', 'download',
                'upload', 'include', 'require', 'template', 'view'
            ],
            'database': [
                'id', 'user_id', 'item_id', 'product_id', 'order_id', 'table',
                'column', 'field', 'query', 'sql', 'db', 'database'
            ],
            'redirection': [
                'redirect', 'return', 'next', 'continue', 'url', 'uri', 'link',
                'href', 'src', 'goto', 'forward'
            ],
            'injection_prone': [
                'search', 'q', 'query', 'keyword', 'term', 'filter', 'sort',
                'order', 'cmd', 'command', 'exec', 'eval', 'code'
            ],
            'business_logic': [
                'price', 'amount', 'total', 'quantity', 'discount', 'coupon',
                'balance', 'payment', 'status', 'role', 'permission'
            ]
        }
        
        # Common file extensions to track
        self.tracked_extensions = {
            'web_apps': ['.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl'],
            'documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'configs': ['.json', '.xml', '.yaml', '.yml', '.conf', '.cfg'],
            'scripts': ['.js', '.css', '.ts', '.coffee'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico'],
            'data': ['.csv', '.tsv', '.sql', '.db', '.sqlite']
        }

    def execute(self, urls: List[str], domain_path: str) -> UtilityResult:
        """
        Execute unfurl-style URL analysis
        
        Args:
            urls: List of URLs to analyze
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult with unfurl analysis results
        """
        self.start_execution()
        self.set_operation("unfurl_analysis")
        
        try:
            if not urls:
                self.log_warning("No URLs provided for unfurl analysis")
                return self.create_result(True, {'components': {}, 'summary': {}}, 0)
            
            self.log_info(f"Starting unfurl analysis on {len(urls)} URLs")
            
            # Extract URL components
            components = self._extract_url_components(urls)
            
            # Analyze components for security insights
            analysis = self._analyze_components(components, urls)
            
            # Generate comprehensive summary
            summary = self._generate_unfurl_summary(components, analysis)
            
            # Save unfurl results
            self._save_unfurl_results(domain_path, components, analysis, summary)
            
            result_data = {
                'components': self._components_to_dict(components),
                'analysis': analysis,
                'summary': summary,
                'total_urls': len(urls),
                'unique_domains': len(components.domains),
                'unique_parameters': len(components.parameters)
            }
            
            self.log_info(f"Unfurl analysis completed: {len(components.domains)} domains, {len(components.parameters)} parameters extracted")
            
            return self.create_result(True, result_data, len(urls))
            
        except Exception as e:
            self.log_error("Unfurl analysis failed", e, ErrorCategory.PROCESSING_ERROR)
            return self.create_result(False, {'error': str(e)}, 0)

    def _extract_url_components(self, urls: List[str]) -> URLComponents:
        """Extract all URL components from the URL list"""
        components = URLComponents()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Extract domain and subdomain
                if parsed.netloc:
                    domain_parts = parsed.netloc.split(':')[0].split('.')
                    if len(domain_parts) >= 2:
                        # Main domain (last two parts)
                        main_domain = '.'.join(domain_parts[-2:])
                        components.domains.add(main_domain)
                        
                        # Subdomains (everything before main domain)
                        if len(domain_parts) > 2:
                            subdomain = '.'.join(domain_parts[:-2])
                            components.subdomains.add(subdomain)
                            components.subdomains.add(parsed.netloc.split(':')[0])  # Full subdomain
                
                # Extract protocol
                if parsed.scheme:
                    components.protocols.add(parsed.scheme)
                
                # Extract port
                if parsed.port:
                    components.ports.add(parsed.port)
                
                # Extract path
                if parsed.path and parsed.path != '/':
                    components.paths.add(parsed.path)
                    
                    # Extract file extension from path
                    if '.' in parsed.path:
                        extension = '.' + parsed.path.split('.')[-1].lower()
                        if len(extension) <= 10:  # Reasonable extension length
                            components.extensions.add(extension)
                
                # Extract parameters
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param in params.keys():
                        components.parameters.add(param)
                
                # Extract fragment
                if parsed.fragment:
                    components.fragments.add(parsed.fragment)
                    
            except Exception as e:
                self.log_warning(f"Failed to parse URL {url}: {str(e)}")
                continue
        
        return components

    def _analyze_components(self, components: URLComponents, urls: List[str]) -> Dict[str, Any]:
        """Analyze extracted components for security insights"""
        analysis = {
            'domain_analysis': self._analyze_domains(components.domains, components.subdomains),
            'parameter_analysis': self._analyze_parameters(components.parameters, urls),
            'path_analysis': self._analyze_paths(components.paths),
            'extension_analysis': self._analyze_extensions(components.extensions),
            'protocol_analysis': self._analyze_protocols(components.protocols, components.ports),
            'security_insights': self._generate_security_insights(components, urls)
        }
        
        return analysis

    def _analyze_domains(self, domains: Set[str], subdomains: Set[str]) -> Dict[str, Any]:
        """Analyze domain patterns and characteristics"""
        domain_analysis = {
            'total_domains': len(domains),
            'total_subdomains': len(subdomains),
            'domain_list': sorted(list(domains)),
            'subdomain_list': sorted(list(subdomains)),
            'domain_patterns': self._identify_domain_patterns(domains),
            'subdomain_patterns': self._identify_subdomain_patterns(subdomains)
        }
        
        return domain_analysis

    def _analyze_parameters(self, parameters: Set[str], urls: List[str]) -> Dict[str, Any]:
        """Analyze URL parameters for security implications"""
        param_analysis = {
            'total_parameters': len(parameters),
            'parameter_list': sorted(list(parameters)),
            'parameter_frequency': self._calculate_parameter_frequency(parameters, urls),
            'interesting_parameters': self._categorize_interesting_parameters(parameters),
            'security_sensitive_params': self._identify_security_sensitive_params(parameters)
        }
        
        return param_analysis

    def _analyze_paths(self, paths: Set[str]) -> Dict[str, Any]:
        """Analyze URL paths for patterns and insights"""
        path_analysis = {
            'total_paths': len(paths),
            'path_list': sorted(list(paths)),
            'path_depths': self._analyze_path_depths(paths),
            'common_directories': self._identify_common_directories(paths),
            'interesting_paths': self._identify_interesting_paths(paths)
        }
        
        return path_analysis

    def _analyze_extensions(self, extensions: Set[str]) -> Dict[str, Any]:
        """Analyze file extensions found in URLs"""
        extension_analysis = {
            'total_extensions': len(extensions),
            'extension_list': sorted(list(extensions)),
            'extension_categories': self._categorize_extensions(extensions),
            'security_relevant_extensions': self._identify_security_extensions(extensions)
        }
        
        return extension_analysis

    def _analyze_protocols(self, protocols: Set[str], ports: Set[int]) -> Dict[str, Any]:
        """Analyze protocols and ports"""
        protocol_analysis = {
            'protocols_found': sorted(list(protocols)),
            'ports_found': sorted(list(ports)),
            'security_assessment': self._assess_protocol_security(protocols, ports)
        }
        
        return protocol_analysis

    def _identify_domain_patterns(self, domains: Set[str]) -> Dict[str, Any]:
        """Identify patterns in domain names"""
        patterns = {
            'tld_distribution': defaultdict(int),
            'domain_lengths': [],
            'common_words': defaultdict(int)
        }
        
        for domain in domains:
            # TLD analysis
            if '.' in domain:
                tld = domain.split('.')[-1]
                patterns['tld_distribution'][tld] += 1
            
            # Length analysis
            patterns['domain_lengths'].append(len(domain))
            
            # Common words in domain names
            domain_parts = re.split(r'[.-]', domain.lower())
            for part in domain_parts:
                if len(part) > 2:  # Ignore very short parts
                    patterns['common_words'][part] += 1
        
        # Convert to regular dicts and get top items
        patterns['tld_distribution'] = dict(patterns['tld_distribution'])
        patterns['common_words'] = dict(sorted(patterns['common_words'].items(), 
                                             key=lambda x: x[1], reverse=True)[:10])
        
        return patterns

    def _identify_subdomain_patterns(self, subdomains: Set[str]) -> Dict[str, Any]:
        """Identify patterns in subdomain names"""
        patterns = {
            'subdomain_count': len(subdomains),
            'common_prefixes': defaultdict(int),
            'interesting_subdomains': []
        }
        
        interesting_keywords = [
            'admin', 'api', 'dev', 'test', 'staging', 'beta', 'internal',
            'mail', 'ftp', 'vpn', 'db', 'database', 'backup', 'old'
        ]
        
        for subdomain in subdomains:
            # Common prefixes
            if '.' in subdomain:
                prefix = subdomain.split('.')[0].lower()
                patterns['common_prefixes'][prefix] += 1
                
                # Interesting subdomains
                if any(keyword in prefix for keyword in interesting_keywords):
                    patterns['interesting_subdomains'].append(subdomain)
        
        patterns['common_prefixes'] = dict(sorted(patterns['common_prefixes'].items(), 
                                                key=lambda x: x[1], reverse=True)[:10])
        
        return patterns

    def _calculate_parameter_frequency(self, parameters: Set[str], urls: List[str]) -> Dict[str, int]:
        """Calculate how frequently each parameter appears"""
        param_frequency = defaultdict(int)
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param in params.keys():
                        param_frequency[param] += 1
            except:
                continue
        
        return dict(sorted(param_frequency.items(), key=lambda x: x[1], reverse=True))

    def _categorize_interesting_parameters(self, parameters: Set[str]) -> Dict[str, List[str]]:
        """Categorize parameters by their potential security implications"""
        categorized = defaultdict(list)
        
        for param in parameters:
            param_lower = param.lower()
            
            for category, keywords in self.interesting_parameters.items():
                if any(keyword in param_lower for keyword in keywords):
                    categorized[category].append(param)
        
        return dict(categorized)

    def _identify_security_sensitive_params(self, parameters: Set[str]) -> List[str]:
        """Identify parameters that are particularly security-sensitive"""
        sensitive_params = []
        
        high_risk_keywords = [
            'password', 'token', 'key', 'secret', 'auth', 'admin', 'root',
            'cmd', 'exec', 'eval', 'file', 'path', 'url', 'redirect'
        ]
        
        for param in parameters:
            param_lower = param.lower()
            if any(keyword in param_lower for keyword in high_risk_keywords):
                sensitive_params.append(param)
        
        return sorted(sensitive_params)

    def _analyze_path_depths(self, paths: Set[str]) -> Dict[str, Any]:
        """Analyze the depth distribution of URL paths"""
        depths = []
        depth_distribution = defaultdict(int)
        
        for path in paths:
            depth = len([p for p in path.split('/') if p])
            depths.append(depth)
            depth_distribution[depth] += 1
        
        return {
            'average_depth': sum(depths) / len(depths) if depths else 0,
            'max_depth': max(depths) if depths else 0,
            'depth_distribution': dict(depth_distribution)
        }

    def _identify_common_directories(self, paths: Set[str]) -> List[str]:
        """Identify common directory names in paths"""
        directories = defaultdict(int)
        
        for path in paths:
            path_parts = [p for p in path.split('/') if p and '.' not in p]
            for part in path_parts:
                directories[part.lower()] += 1
        
        return [dir_name for dir_name, count in sorted(directories.items(), 
                                                      key=lambda x: x[1], reverse=True)[:20]]

    def _identify_interesting_paths(self, paths: Set[str]) -> List[str]:
        """Identify potentially interesting paths"""
        interesting = []
        
        interesting_keywords = [
            'admin', 'api', 'backup', 'config', 'debug', 'test', 'dev',
            'private', 'internal', 'secret', 'hidden', 'temp', 'old'
        ]
        
        for path in paths:
            path_lower = path.lower()
            if any(keyword in path_lower for keyword in interesting_keywords):
                interesting.append(path)
        
        return sorted(interesting)

    def _categorize_extensions(self, extensions: Set[str]) -> Dict[str, List[str]]:
        """Categorize file extensions by type"""
        categorized = defaultdict(list)
        
        for ext in extensions:
            for category, ext_list in self.tracked_extensions.items():
                if ext in ext_list:
                    categorized[category].append(ext)
                    break
            else:
                categorized['other'].append(ext)
        
        return dict(categorized)

    def _identify_security_extensions(self, extensions: Set[str]) -> List[str]:
        """Identify security-relevant file extensions"""
        security_extensions = []
        
        high_risk_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl', '.cgi',
            '.sql', '.db', '.sqlite', '.bak', '.old', '.conf', '.cfg',
            '.env', '.key', '.pem', '.crt'
        ]
        
        for ext in extensions:
            if ext in high_risk_extensions:
                security_extensions.append(ext)
        
        return sorted(security_extensions)

    def _assess_protocol_security(self, protocols: Set[str], ports: Set[int]) -> Dict[str, Any]:
        """Assess security implications of protocols and ports"""
        assessment = {
            'secure_protocols': [],
            'insecure_protocols': [],
            'non_standard_ports': [],
            'security_recommendations': []
        }
        
        # Protocol assessment
        for protocol in protocols:
            if protocol in ['https', 'ftps', 'sftp']:
                assessment['secure_protocols'].append(protocol)
            elif protocol in ['http', 'ftp', 'telnet']:
                assessment['insecure_protocols'].append(protocol)
        
        # Port assessment
        standard_ports = {80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995}
        for port in ports:
            if port not in standard_ports:
                assessment['non_standard_ports'].append(port)
        
        # Generate recommendations
        if assessment['insecure_protocols']:
            assessment['security_recommendations'].append(
                f"Consider upgrading insecure protocols: {', '.join(assessment['insecure_protocols'])}"
            )
        
        if assessment['non_standard_ports']:
            assessment['security_recommendations'].append(
                f"Review non-standard ports for security: {', '.join(map(str, assessment['non_standard_ports']))}"
            )
        
        return assessment

    def _generate_security_insights(self, components: URLComponents, urls: List[str]) -> Dict[str, Any]:
        """Generate overall security insights from URL analysis"""
        insights = {
            'potential_attack_surface': [],
            'information_disclosure_risks': [],
            'injection_opportunities': [],
            'access_control_concerns': [],
            'recommendations': []
        }
        
        # Analyze attack surface
        if len(components.parameters) > 50:
            insights['potential_attack_surface'].append(
                f"Large parameter space ({len(components.parameters)} unique parameters) increases attack surface"
            )
        
        # Information disclosure
        sensitive_extensions = self._identify_security_extensions(components.extensions)
        if sensitive_extensions:
            insights['information_disclosure_risks'].append(
                f"Sensitive file extensions found: {', '.join(sensitive_extensions)}"
            )
        
        # Injection opportunities
        injection_params = []
        for param in components.parameters:
            if any(keyword in param.lower() for keyword in ['search', 'query', 'filter', 'sort']):
                injection_params.append(param)
        
        if injection_params:
            insights['injection_opportunities'].append(
                f"Parameters prone to injection: {', '.join(injection_params[:10])}"
            )
        
        # Access control
        admin_paths = [path for path in components.paths if 'admin' in path.lower()]
        if admin_paths:
            insights['access_control_concerns'].append(
                f"Administrative paths found: {len(admin_paths)} paths"
            )
        
        # Generate recommendations
        if len(components.parameters) > 20:
            insights['recommendations'].append("Review parameter validation and sanitization")
        
        if sensitive_extensions:
            insights['recommendations'].append("Secure or remove sensitive file types")
        
        if 'http' in components.protocols:
            insights['recommendations'].append("Implement HTTPS for all communications")
        
        return insights

    def _generate_unfurl_summary(self, components: URLComponents, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive unfurl analysis summary"""
        
        return {
            'extraction_summary': {
                'total_domains': len(components.domains),
                'total_subdomains': len(components.subdomains),
                'total_paths': len(components.paths),
                'total_parameters': len(components.parameters),
                'total_extensions': len(components.extensions),
                'total_protocols': len(components.protocols),
                'total_ports': len(components.ports)
            },
            'security_summary': {
                'sensitive_parameters': len(analysis['parameter_analysis']['security_sensitive_params']),
                'security_extensions': len(analysis['extension_analysis']['security_relevant_extensions']),
                'interesting_paths': len(analysis['path_analysis']['interesting_paths']),
                'insecure_protocols': len(analysis['protocol_analysis']['security_assessment']['insecure_protocols'])
            },
            'top_findings': {
                'most_common_parameters': list(analysis['parameter_analysis']['parameter_frequency'].items())[:10],
                'most_common_extensions': list(Counter(components.extensions).most_common(10)),
                'deepest_paths': sorted(components.paths, key=lambda x: len(x.split('/')), reverse=True)[:10]
            },
            'analysis_timestamp': datetime.now().isoformat(),
            'recommendations_count': len(analysis['security_insights']['recommendations'])
        }

    def _save_unfurl_results(self, domain_path: str, components: URLComponents, 
                           analysis: Dict[str, Any], summary: Dict[str, Any]):
        """Save unfurl analysis results to files"""
        try:
            # Save individual components
            self.save_results(domain_path, 'unfurl', 'domains.txt', 
                            '\n'.join(sorted(components.domains)))
            
            self.save_results(domain_path, 'unfurl', 'subdomains.txt', 
                            '\n'.join(sorted(components.subdomains)))
            
            self.save_results(domain_path, 'unfurl', 'paths.txt', 
                            '\n'.join(sorted(components.paths)))
            
            self.save_results(domain_path, 'unfurl', 'parameters.txt', 
                            '\n'.join(sorted(components.parameters)))
            
            self.save_results(domain_path, 'unfurl', 'extensions.txt', 
                            '\n'.join(sorted(components.extensions)))
            
            # Save analysis results
            self.save_results(domain_path, 'unfurl', 'analysis.json',
                            json.dumps(analysis, indent=2))
            
            # Save summary
            self.save_results(domain_path, 'unfurl', 'summary.json',
                            json.dumps(summary, indent=2))
            
            # Save security-focused report
            security_report = []
            security_report.append("UNFURL SECURITY ANALYSIS REPORT")
            security_report.append("=" * 40)
            security_report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            security_report.append("")
            
            # Security-sensitive parameters
            sensitive_params = analysis['parameter_analysis']['security_sensitive_params']
            if sensitive_params:
                security_report.append("SECURITY-SENSITIVE PARAMETERS:")
                for param in sensitive_params:
                    security_report.append(f"  - {param}")
                security_report.append("")
            
            # Interesting paths
            interesting_paths = analysis['path_analysis']['interesting_paths']
            if interesting_paths:
                security_report.append("INTERESTING PATHS:")
                for path in interesting_paths[:20]:
                    security_report.append(f"  - {path}")
                security_report.append("")
            
            # Security insights
            insights = analysis['security_insights']
            if insights['recommendations']:
                security_report.append("SECURITY RECOMMENDATIONS:")
                for i, rec in enumerate(insights['recommendations'], 1):
                    security_report.append(f"  {i}. {rec}")
            
            self.save_results(domain_path, 'unfurl', 'security_report.txt',
                            '\n'.join(security_report))
            
            # Save overview
            overview = []
            overview.append("UNFURL ANALYSIS OVERVIEW")
            overview.append("=" * 30)
            overview.append(f"Domains Found: {len(components.domains)}")
            overview.append(f"Subdomains Found: {len(components.subdomains)}")
            overview.append(f"Unique Paths: {len(components.paths)}")
            overview.append(f"Unique Parameters: {len(components.parameters)}")
            overview.append(f"File Extensions: {len(components.extensions)}")
            overview.append(f"Protocols: {', '.join(sorted(components.protocols))}")
            overview.append("")
            
            overview.append("TOP PARAMETERS BY FREQUENCY:")
            for param, count in list(analysis['parameter_analysis']['parameter_frequency'].items())[:10]:
                overview.append(f"  {param}: {count}")
            
            self.save_results(domain_path, 'unfurl', 'overview.txt', '\n'.join(overview))
            
            self.log_info(f"Unfurl analysis results saved to {domain_path}/unfurl/")
            
        except Exception as e:
            self.log_error("Failed to save unfurl results", e, ErrorCategory.FILE_ERROR)

    def _components_to_dict(self, components: URLComponents) -> Dict[str, List[str]]:
        """Convert URLComponents to dictionary for JSON serialization"""
        return {
            'domains': sorted(list(components.domains)),
            'subdomains': sorted(list(components.subdomains)),
            'paths': sorted(list(components.paths)),
            'parameters': sorted(list(components.parameters)),
            'extensions': sorted(list(components.extensions)),
            'ports': sorted(list(components.ports)),
            'protocols': sorted(list(components.protocols)),
            'fragments': sorted(list(components.fragments))
        }

    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """Validate dependencies for unfurl analysis"""
        missing_deps = []
        
        try:
            import re
            import json
            from urllib.parse import urlparse, parse_qs, unquote
            from collections import defaultdict, Counter
        except ImportError as e:
            missing_deps.append(str(e))
        
        return len(missing_deps) == 0, missing_deps

    def get_component_statistics(self, components: URLComponents) -> Dict[str, Any]:
        """Get detailed statistics about extracted components"""
        return {
            'component_counts': {
                'domains': len(components.domains),
                'subdomains': len(components.subdomains),
                'paths': len(components.paths),
                'parameters': len(components.parameters),
                'extensions': len(components.extensions),
                'ports': len(components.ports),
                'protocols': len(components.protocols),
                'fragments': len(components.fragments)
            },
            'top_items': {
                'domains': sorted(list(components.domains))[:10],
                'parameters': sorted(list(components.parameters))[:20],
                'extensions': sorted(list(components.extensions))[:10],
                'protocols': sorted(list(components.protocols))
            }
        }