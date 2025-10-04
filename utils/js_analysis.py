"""
JavaScript analysis module - Detect and analyze JavaScript files for endpoints and sensitive data
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import re
import os
import tempfile
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Tuple, Dict, Any, Set
from datetime import datetime

try:
    from .base_utility import BaseUtility, UtilityResult
    from .uro_filter import UROFilter
except ImportError:
    # Fallback for direct testing
    from utils.base_utility import BaseUtility, UtilityResult
    from utils.uro_filter import UROFilter


class JSAnalyzer(BaseUtility):
    """
    JavaScript file detection and analysis utility for endpoint extraction
    and API call detection with URO integration
    """
    
    def __init__(self, hyperrecon_instance):
        """
        Initialize JavaScript analyzer with URO filtering integration
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance
        """
        super().__init__(hyperrecon_instance)
        self.uro_filter = UROFilter(hyperrecon_instance)
        
        # JavaScript file patterns
        self.js_patterns = [
            r'\.js(\?[^"\s]*)?$',
            r'\.js(\?[^"\s]*)?["\s]',
            r'/js/',
            r'/javascript/',
            r'/assets/.*\.js',
            r'/static/.*\.js',
            r'/dist/.*\.js',
            r'/build/.*\.js'
        ]
        
        # Endpoint extraction patterns
        self.endpoint_patterns = {
            'api_endpoints': [
                r'["\']([/]?api[/][^"\']*)["\']',
                r'["\']([/]?v\d+[/][^"\']*)["\']',
                r'["\']([/]?rest[/][^"\']*)["\']',
                r'["\']([/]?graphql[^"\']*)["\']'
            ],
            'url_patterns': [
                r'["\']((https?://[^"\']+))["\']',
                r'["\']([/][^"\']*\?[^"\']*)["\']',
                r'url\s*:\s*["\']([^"\']+)["\']',
                r'endpoint\s*:\s*["\']([^"\']+)["\']',
                r'baseURL\s*:\s*["\']([^"\']+)["\']'
            ],
            'ajax_calls': [
                r'\$\.ajax\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.get\s*\(\s*["\']([^"\']+)["\']',
                r'\$\.post\s*\(\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
                r'url\s*:\s*["\']([^"\']+)["\']'
            ],
            'websocket_endpoints': [
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                r'ws://[^"\']+',
                r'wss://[^"\']+',
                r'socket\.io[^"\']*'
            ]
        }
        
        # Sensitive data patterns in JavaScript
        self.sensitive_js_patterns = {
            'api_keys': [
                r'api[-_]?key\s*[:=]\s*["\']([^"\']+)["\']',
                r'apikey\s*[:=]\s*["\']([^"\']+)["\']',
                r'access[-_]?token\s*[:=]\s*["\']([^"\']+)["\']',
                r'secret\s*[:=]\s*["\']([^"\']+)["\']'
            ],
            'credentials': [
                r'password\s*[:=]\s*["\']([^"\']+)["\']',
                r'username\s*[:=]\s*["\']([^"\']+)["\']',
                r'auth\s*[:=]\s*["\']([^"\']+)["\']'
            ],
            'config_data': [
                r'config\s*[:=]\s*\{[^}]*\}',
                r'settings\s*[:=]\s*\{[^}]*\}',
                r'env\s*[:=]\s*\{[^}]*\}'
            ]
        }
        
        # Request timeout and headers
        self.request_timeout = 10
        self.request_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def execute(self, urls: List[str], domain_path: str) -> UtilityResult:
        """
        Execute JavaScript file detection and analysis
        
        Args:
            urls: List of URLs to analyze for JavaScript files
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult: Analysis results with extracted endpoints and data
        """
        self.start_execution()
        
        if not urls:
            self.log_error("No URLs provided for JavaScript analysis")
            return self.create_result(False, {}, 0)
        
        self.log_info(f"Starting JavaScript analysis on {len(urls)} URLs")
        
        try:
            # Extract JavaScript URLs from the provided URL list
            js_urls = self._extract_js_urls(urls)
            
            if not js_urls:
                self.log_info("No JavaScript files found in provided URLs")
                # Save empty results with appropriate indicators
                self._save_empty_results(domain_path)
                return self.create_result(True, {'js_files': [], 'endpoints': [], 'sensitive_data': []}, 0)
            
            # Apply URO filtering to JavaScript URLs
            filtered_js_urls = self._apply_uro_filtering(js_urls, domain_path)
            
            # Analyze JavaScript files for endpoints and sensitive data
            analysis_results = self._analyze_js_files(filtered_js_urls, domain_path)
            
            # Save comprehensive results
            self._save_analysis_results(analysis_results, domain_path)
            
            # Generate summary
            summary = self._generate_analysis_summary(analysis_results)
            self.save_results(domain_path, 'javascript', 'analysis_summary.txt', summary)
            
            self.log_info(f"JavaScript analysis completed: {len(filtered_js_urls)} files analyzed")
            
            return self.create_result(True, analysis_results, len(filtered_js_urls))
            
        except Exception as e:
            self.log_error("JavaScript analysis execution failed", e)
            return self.create_result(False, {}, 0)
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate JavaScript analysis dependencies
        
        Returns:
            Tuple[bool, List[str]]: (has_dependencies, missing_tools)
        """
        missing_tools = []
        
        # Check for requests library (should be available)
        try:
            import requests
        except ImportError:
            missing_tools.append('requests (Python library)')
        
        # URO is recommended but not required
        if not self.uro_filter.is_uro_available():
            missing_tools.append('uro (recommended for better deduplication)')
        
        # JavaScript analysis doesn't require external tools, just Python libraries
        has_dependencies = len(missing_tools) == 0 or 'requests' not in str(missing_tools)
        
        if missing_tools:
            self.log_warning(f"Missing recommended tools: {', '.join(missing_tools)}")
        else:
            self.log_info("All JavaScript analysis dependencies are available")
        
        return has_dependencies, missing_tools
    
    def _extract_js_urls(self, urls: List[str]) -> List[str]:
        """
        Extract JavaScript URLs from the provided URL list
        
        Args:
            urls: List of URLs to filter for JavaScript files
            
        Returns:
            List[str]: JavaScript URLs found
        """
        js_urls = []
        
        for url in urls:
            # Check if URL matches JavaScript patterns
            for pattern in self.js_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    js_urls.append(url)
                    break
        
        self.log_info(f"Extracted {len(js_urls)} JavaScript URLs from {len(urls)} total URLs")
        return js_urls
    
    def _apply_uro_filtering(self, js_urls: List[str], domain_path: str) -> List[str]:
        """
        Apply URO filtering to JavaScript URLs for deduplication
        
        Args:
            js_urls: List of JavaScript URLs
            domain_path: Domain output path
            
        Returns:
            List[str]: Filtered JavaScript URLs
        """
        if not js_urls:
            return []
        
        self.log_info(f"Applying URO filtering to {len(js_urls)} JavaScript URLs")
        
        # Apply URO filtering
        filtered_urls = self.uro_filter.filter_and_save(
            js_urls, domain_path, 'javascript', 'js_urls_raw.txt'
        )
        
        self.log_info(f"URO filtering: {len(js_urls)} → {len(filtered_urls)} JavaScript URLs")
        return filtered_urls
    
    def _analyze_js_files(self, js_urls: List[str], domain_path: str) -> Dict[str, Any]:
        """
        Analyze JavaScript files for endpoints and sensitive data
        
        Args:
            js_urls: List of JavaScript URLs to analyze
            domain_path: Domain output path
            
        Returns:
            Dict containing analysis results
        """
        analysis_results = {
            'js_files': js_urls,
            'endpoints': [],
            'api_calls': [],
            'websocket_endpoints': [],
            'sensitive_data': [],
            'analysis_errors': [],
            'successful_analyses': 0,
            'failed_analyses': 0
        }
        
        self.log_info(f"Analyzing {len(js_urls)} JavaScript files for endpoints and sensitive data")
        
        for js_url in js_urls:
            try:
                # Download and analyze JavaScript file
                js_content = self._download_js_file(js_url)
                
                if js_content:
                    # Extract endpoints and sensitive data
                    file_analysis = self._analyze_js_content(js_content, js_url)
                    
                    # Merge results
                    analysis_results['endpoints'].extend(file_analysis['endpoints'])
                    analysis_results['api_calls'].extend(file_analysis['api_calls'])
                    analysis_results['websocket_endpoints'].extend(file_analysis['websocket_endpoints'])
                    analysis_results['sensitive_data'].extend(file_analysis['sensitive_data'])
                    
                    analysis_results['successful_analyses'] += 1
                    self.log_info(f"Successfully analyzed: {js_url}")
                else:
                    analysis_results['failed_analyses'] += 1
                    analysis_results['analysis_errors'].append(f"Failed to download: {js_url}")
                    
            except Exception as e:
                analysis_results['failed_analyses'] += 1
                error_msg = f"Analysis failed for {js_url}: {str(e)}"
                analysis_results['analysis_errors'].append(error_msg)
                self.log_warning(error_msg)
        
        # Remove duplicates from results
        analysis_results['endpoints'] = list(set(analysis_results['endpoints']))
        analysis_results['api_calls'] = list(set(analysis_results['api_calls']))
        analysis_results['websocket_endpoints'] = list(set(analysis_results['websocket_endpoints']))
        
        return analysis_results
    
    def _download_js_file(self, js_url: str) -> str:
        """
        Download JavaScript file content
        
        Args:
            js_url: URL of the JavaScript file
            
        Returns:
            str: JavaScript file content or empty string on failure
        """
        try:
            response = requests.get(
                js_url, 
                headers=self.request_headers,
                timeout=self.request_timeout,
                verify=False  # Skip SSL verification for reconnaissance
            )
            
            if response.status_code == 200:
                return response.text
            else:
                self.log_warning(f"HTTP {response.status_code} for {js_url}")
                return ""
                
        except requests.exceptions.Timeout:
            self.log_warning(f"Timeout downloading {js_url}")
            return ""
        except requests.exceptions.RequestException as e:
            self.log_warning(f"Request failed for {js_url}: {str(e)}")
            return ""
        except Exception as e:
            self.log_warning(f"Unexpected error downloading {js_url}: {str(e)}")
            return ""
    
    def _analyze_js_content(self, content: str, js_url: str) -> Dict[str, List[str]]:
        """
        Analyze JavaScript content for endpoints and sensitive data
        
        Args:
            content: JavaScript file content
            js_url: URL of the JavaScript file (for context)
            
        Returns:
            Dict containing extracted endpoints and sensitive data
        """
        results = {
            'endpoints': [],
            'api_calls': [],
            'websocket_endpoints': [],
            'sensitive_data': []
        }
        
        # Extract API endpoints
        for pattern in self.endpoint_patterns['api_endpoints']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            results['endpoints'].extend(matches)
        
        # Extract URL patterns
        for pattern in self.endpoint_patterns['url_patterns']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            results['endpoints'].extend([match[0] if isinstance(match, tuple) else match for match in matches])
        
        # Extract AJAX calls
        for pattern in self.endpoint_patterns['ajax_calls']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            results['api_calls'].extend(matches)
        
        # Extract WebSocket endpoints
        for pattern in self.endpoint_patterns['websocket_endpoints']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            results['websocket_endpoints'].extend(matches)
        
        # Extract sensitive data
        for category, patterns in self.sensitive_js_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    sensitive_item = f"{js_url} -> {category}: {match}"
                    results['sensitive_data'].append(sensitive_item)
        
        return results
    
    def _save_analysis_results(self, analysis_results: Dict[str, Any], domain_path: str):
        """
        Save JavaScript analysis results to files
        
        Args:
            analysis_results: Analysis results dictionary
            domain_path: Domain output path
        """
        # Save JavaScript URLs to js.txt (main requirement)
        if analysis_results['js_files']:
            self.save_results(domain_path, 'javascript', 'js.txt', analysis_results['js_files'])
        
        # Save extracted endpoints
        if analysis_results['endpoints']:
            self.save_results(domain_path, 'javascript', 'endpoints.txt', analysis_results['endpoints'])
        
        # Save API calls
        if analysis_results['api_calls']:
            self.save_results(domain_path, 'javascript', 'api_calls.txt', analysis_results['api_calls'])
        
        # Save WebSocket endpoints
        if analysis_results['websocket_endpoints']:
            self.save_results(domain_path, 'javascript', 'websocket_endpoints.txt', analysis_results['websocket_endpoints'])
        
        # Save sensitive data findings
        if analysis_results['sensitive_data']:
            self.save_results(domain_path, 'javascript', 'sensitive_findings.txt', analysis_results['sensitive_data'])
        
        # Save detailed analysis report
        detailed_report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_js_files': len(analysis_results['js_files']),
                'successful_analyses': analysis_results['successful_analyses'],
                'failed_analyses': analysis_results['failed_analyses']
            },
            'results': {
                'js_files_count': len(analysis_results['js_files']),
                'endpoints_count': len(analysis_results['endpoints']),
                'api_calls_count': len(analysis_results['api_calls']),
                'websocket_endpoints_count': len(analysis_results['websocket_endpoints']),
                'sensitive_findings_count': len(analysis_results['sensitive_data'])
            },
            'js_files': analysis_results['js_files'],
            'endpoints': analysis_results['endpoints'],
            'api_calls': analysis_results['api_calls'],
            'websocket_endpoints': analysis_results['websocket_endpoints'],
            'sensitive_data': analysis_results['sensitive_data'],
            'errors': analysis_results['analysis_errors']
        }
        
        self.save_results(domain_path, 'javascript', 'detailed_analysis.json', detailed_report)
    
    def _save_empty_results(self, domain_path: str):
        """
        Save appropriate indicators when no JavaScript files are found
        
        Args:
            domain_path: Domain output path
        """
        empty_message = "No JavaScript files found in the provided URLs"
        
        # Save empty js.txt with indicator message
        self.save_results(domain_path, 'javascript', 'js.txt', [empty_message])
        
        # Save empty analysis summary
        summary = f"""JavaScript Analysis Summary
Generated: {datetime.now().isoformat()}

Status: No JavaScript files detected
Total URLs analyzed: 0
JavaScript files found: 0
Endpoints extracted: 0
API calls found: 0
WebSocket endpoints: 0
Sensitive data findings: 0

Note: {empty_message}
"""
        self.save_results(domain_path, 'javascript', 'analysis_summary.txt', summary)
    
    def _generate_analysis_summary(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a comprehensive analysis summary
        
        Args:
            analysis_results: Analysis results dictionary
            
        Returns:
            str: Formatted summary text
        """
        summary = f"""JavaScript Analysis Summary
Generated: {datetime.now().isoformat()}

=== Analysis Statistics ===
Total JavaScript files: {len(analysis_results['js_files'])}
Successful analyses: {analysis_results['successful_analyses']}
Failed analyses: {analysis_results['failed_analyses']}

=== Extraction Results ===
Endpoints extracted: {len(analysis_results['endpoints'])}
API calls found: {len(analysis_results['api_calls'])}
WebSocket endpoints: {len(analysis_results['websocket_endpoints'])}
Sensitive data findings: {len(analysis_results['sensitive_data'])}

=== JavaScript Files Analyzed ===
"""
        
        for js_file in analysis_results['js_files']:
            summary += f"- {js_file}\n"
        
        if analysis_results['endpoints']:
            summary += f"\n=== Endpoints Found ({len(analysis_results['endpoints'])}) ===\n"
            for endpoint in analysis_results['endpoints'][:20]:  # Limit to first 20
                summary += f"- {endpoint}\n"
            if len(analysis_results['endpoints']) > 20:
                summary += f"... and {len(analysis_results['endpoints']) - 20} more endpoints\n"
        
        if analysis_results['api_calls']:
            summary += f"\n=== API Calls Found ({len(analysis_results['api_calls'])}) ===\n"
            for api_call in analysis_results['api_calls'][:10]:  # Limit to first 10
                summary += f"- {api_call}\n"
            if len(analysis_results['api_calls']) > 10:
                summary += f"... and {len(analysis_results['api_calls']) - 10} more API calls\n"
        
        if analysis_results['sensitive_data']:
            summary += f"\n=== Sensitive Data Findings ({len(analysis_results['sensitive_data'])}) ===\n"
            for finding in analysis_results['sensitive_data'][:10]:  # Limit to first 10
                summary += f"- {finding}\n"
            if len(analysis_results['sensitive_data']) > 10:
                summary += f"... and {len(analysis_results['sensitive_data']) - 10} more findings\n"
        
        if analysis_results['analysis_errors']:
            summary += f"\n=== Analysis Errors ({len(analysis_results['analysis_errors'])}) ===\n"
            for error in analysis_results['analysis_errors']:
                summary += f"- {error}\n"
        
        return summary