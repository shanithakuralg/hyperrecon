"""
URL collection module - Extract URLs from multiple sources with URO filtering
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import tempfile
import os
from typing import List, Tuple, Dict, Any, Set
from datetime import datetime
try:
    from .base_utility import BaseUtility, UtilityResult
    from .uro_filter import UROFilter
except ImportError:
    # Fallback for direct testing
    from utils.base_utility import BaseUtility, UtilityResult
    from utils.uro_filter import UROFilter


class URLCollector(BaseUtility):
    """
    URL collection utility from multiple sources including Wayback Machine and GAU
    with comprehensive filtering and validation
    """
    
    def __init__(self, hyperrecon_instance):
        """
        Initialize URL collector with URO filtering integration
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance
        """
        super().__init__(hyperrecon_instance)
        self.uro_filter = UROFilter(hyperrecon_instance)
        
        # Excluded file extensions for URL filtering
        self.excluded_extensions = [
            'png', 'jpg', 'gif', 'jpeg', 'svg', 'ico', 'css', 
            'woff', 'woff2', 'ttf', 'otf', 'avi', 'mov', 'wmv',
            'wav', 'flac'
        ]
        
        # URL collection sources configuration
        self.sources = {
            'waybackurls': {
                'command': 'waybackurls',
                'timeout': 360,
                'description': 'Wayback Machine URL collection',
                'enabled_flag': 'enable_waybackurls'
            },
            'gau': {
                'command': 'gau',
                'timeout': 360,
                'description': 'GetAllUrls (GAU) collection',
                'enabled_flag': 'enable_gau'
            }
        }
    
    def execute(self, target: str, domain_path: str) -> UtilityResult:
        """
        Execute comprehensive URL collection from multiple sources
        
        Args:
            target: Target domain to collect URLs for
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult: Collection results with filtered URLs
        """
        self.start_execution()
        
        if not target:
            self.log_error("No target provided for URL collection")
            return self.create_result(False, {}, 0)
        
        self.log_info(f"Starting URL collection for {target}")
        
        try:
            # Validate dependencies
            available_sources = self._check_available_sources()
            
            if not available_sources:
                self.log_warning("No URL collection tools available")
                return self.create_result(False, {}, 0)
            
            # Collect URLs from all available sources
            all_urls = set()
            source_results = {}
            
            for source_name in available_sources:
                urls = self._collect_from_source(source_name, target, domain_path)
                if urls:
                    source_results[source_name] = urls
                    all_urls.update(urls)
                    self.log_info(f"Collected {len(urls)} URLs from {source_name}")
            
            # Apply comprehensive URL filtering
            filtered_urls = self._apply_comprehensive_filtering(list(all_urls), domain_path)
            
            # Save final results
            if filtered_urls:
                self.save_results(domain_path, 'urls', 'all_urls.txt', filtered_urls)
                self.log_info(f"Saved {len(filtered_urls)} filtered URLs")
            
            # Generate collection summary
            summary = self._generate_collection_summary(source_results, filtered_urls, target)
            self.save_results(domain_path, 'urls', 'collection_summary.txt', summary)
            
            # Prepare result data
            result_data = {
                'target': target,
                'sources_used': list(available_sources),
                'source_results': {k: len(v) for k, v in source_results.items()},
                'total_collected': len(all_urls),
                'filtered_urls': filtered_urls,
                'final_count': len(filtered_urls)
            }
            
            self.log_info(f"URL collection completed: {len(all_urls)} → {len(filtered_urls)} URLs")
            
            return self.create_result(True, result_data, len(all_urls))
            
        except Exception as e:
            self.log_error("URL collection execution failed", e)
            return self.create_result(False, {}, 0)
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate URL collection tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (has_dependencies, missing_tools)
        """
        missing_tools = []
        available_tools = []
        
        for source_name, config in self.sources.items():
            if not self.check_tool_installed(config['command']):
                missing_tools.append(config['command'])
            else:
                available_tools.append(config['command'])
        
        # URO is recommended but not required
        if not self.uro_filter.is_uro_available():
            missing_tools.append('uro (recommended for better deduplication)')
        
        has_at_least_one = len(available_tools) > 0
        
        # Log dependency status
        if available_tools:
            self.log_info(f"Available URL collection tools: {', '.join(available_tools)}")
        if missing_tools:
            self.log_warning(f"Missing URL collection tools: {', '.join(missing_tools)}")
        
        return has_at_least_one, missing_tools
    
    def _check_available_sources(self) -> List[str]:
        """
        Check which URL collection sources are available and enabled
        
        Returns:
            List[str]: Available and enabled source names
        """
        available = []
        
        for source_name, config in self.sources.items():
            # Check if the source is enabled in feature flags
            if source_name == 'waybackurls':
                is_enabled = self.hyperrecon.feature_flags.get('waybackurls', False)
            elif source_name == 'gau':
                is_enabled = self.hyperrecon.feature_flags.get('gau', True)
            else:
                is_enabled = True  # Default to enabled for unknown sources
            
            if not is_enabled:
                self.log_info(f"{source_name} is disabled in feature flags")
                continue
            
            # Check if the tool is installed
            if self.check_tool_installed(config['command']):
                available.append(source_name)
                self.log_info(f"{config['command']} is available and enabled")
            else:
                self.log_warning(f"{config['command']} is not installed")
        
        return available
    
    def _collect_from_source(self, source_name: str, target: str, domain_path: str) -> List[str]:
        """
        Collect URLs from a specific source
        
        Args:
            source_name: Name of the source (waybackurls, gau)
            target: Target domain
            domain_path: Domain output path
            
        Returns:
            List[str]: URLs collected from the source
        """
        if source_name not in self.sources:
            self.log_error(f"Unknown source: {source_name}")
            return []
        
        config = self.sources[source_name]
        
        try:
            self.log_info(f"Collecting URLs from {source_name}")
            
            # Execute the collection command
            result = self.run_command(
                [config['command'], target],
                timeout=config['timeout'],
                description=config['description']
            )
            
            if not result:
                self.log_warning(f"No results from {source_name}")
                return []
            
            # Parse URLs from result
            urls = [url.strip() for url in result.split('\n') if url.strip()]
            
            if urls:
                # Save raw results from this source
                raw_filename = f'{source_name}_raw_results.txt'
                self.save_results(domain_path, 'urls', raw_filename, urls)
                
                # Apply URO filtering to source results
                filtered_urls = self.uro_filter.filter_and_save_with_stats(
                    urls, domain_path, 'urls', f'{source_name}_results.txt', source_name
                )
                
                self.log_info(f"Collected {len(urls)} URLs from {source_name}, filtered to {len(filtered_urls)}")
                return filtered_urls
            
            return []
            
        except Exception as e:
            self.log_error(f"Failed to collect from {source_name}", e)
            return []
    
    def _apply_comprehensive_filtering(self, urls: List[str], domain_path: str) -> List[str]:
        """
        Apply comprehensive URL filtering including extension filtering and URO
        
        Args:
            urls: List of URLs to filter
            domain_path: Domain output path
            
        Returns:
            List[str]: Comprehensively filtered URLs
        """
        if not urls:
            return []
        
        self.log_info(f"Applying comprehensive filtering to {len(urls)} URLs")
        
        # Step 1: Basic validation and cleanup
        valid_urls = []
        invalid_count = 0
        
        for url in urls:
            url = url.strip()
            if url and self._is_valid_url(url):
                valid_urls.append(url)
            else:
                invalid_count += 1
        
        self.log_info(f"Valid URLs after basic filtering: {len(valid_urls)} (removed {invalid_count} invalid)")
        
        # Step 2: Extension filtering
        filtered_urls = []
        excluded_count = 0
        
        for url in valid_urls:
            if not self._is_excluded_extension(url):
                filtered_urls.append(url)
            else:
                excluded_count += 1
        
        self.log_info(f"URLs after extension filtering: {len(filtered_urls)} (excluded {excluded_count})")
        
        # Step 3: Apply URO filtering for final deduplication
        if filtered_urls:
            final_urls = self.uro_filter.apply_consistent_filtering(filtered_urls, "Combined URLs")
            
            # Save filtering statistics
            self._save_filtering_statistics(
                len(urls), len(valid_urls), len(filtered_urls), 
                len(final_urls), excluded_count, domain_path
            )
            
            return final_urls
        
        return []
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and structure
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if URL is valid
        """
        if not url or not isinstance(url, str):
            return False
        
        url = url.strip()
        
        # Must start with http or https
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Must contain a domain
        if len(url) < 10:  # Minimum: http://a.b
            return False
        
        # Basic structure validation
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return bool(parsed.netloc and parsed.scheme in ['http', 'https'])
        except Exception:
            return False
    
    def _is_excluded_extension(self, url: str) -> bool:
        """
        Check if URL has an excluded file extension
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL should be excluded
        """
        url_lower = url.lower()
        
        for ext in self.excluded_extensions:
            # Check for extension at end of URL or before query parameters
            if (url_lower.endswith(f'.{ext}') or 
                f'.{ext}?' in url_lower or 
                f'.{ext}#' in url_lower):
                return True
        
        return False
    
    def _save_filtering_statistics(self, original_count: int, valid_count: int, 
                                 extension_filtered_count: int, final_count: int,
                                 excluded_count: int, domain_path: str) -> None:
        """
        Save detailed filtering statistics
        
        Args:
            original_count: Original URL count
            valid_count: Valid URLs after basic filtering
            extension_filtered_count: URLs after extension filtering
            final_count: Final URL count after URO filtering
            excluded_count: Number of URLs excluded by extension filtering
            domain_path: Domain output path
        """
        stats = [
            f"URL Filtering Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"Original URLs collected: {original_count}",
            f"Valid URLs (http/https): {valid_count}",
            f"After extension filtering: {extension_filtered_count}",
            f"Final URLs (after URO): {final_count}",
            "",
            f"Filtering Summary:",
            f"  • Invalid URLs removed: {original_count - valid_count}",
            f"  • Extension-based exclusions: {excluded_count}",
            f"  • URO deduplication: {extension_filtered_count - final_count}",
            f"  • Total reduction: {original_count - final_count} ({((original_count - final_count) / original_count * 100):.1f}%)" if original_count > 0 else "  • Total reduction: 0 (0%)",
            "",
            f"Excluded extensions: {', '.join(self.excluded_extensions)}",
            f"URO available: {self.uro_filter.is_uro_available()}"
        ]
        
        self.save_results(domain_path, 'urls', 'filtering_statistics.txt', stats)
    
    def _generate_collection_summary(self, source_results: Dict[str, List[str]], 
                                   final_urls: List[str], target: str) -> List[str]:
        """
        Generate comprehensive collection summary
        
        Args:
            source_results: Results from each source
            final_urls: Final filtered URLs
            target: Target domain
            
        Returns:
            List[str]: Summary lines
        """
        summary = [
            f"URL Collection Summary for {target}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Collection Sources:"
        ]
        
        total_collected = 0
        for source_name, urls in source_results.items():
            count = len(urls)
            total_collected += count
            summary.append(f"  • {source_name}: {count} URLs")
        
        summary.extend([
            "",
            f"Total URLs collected: {total_collected}",
            f"Final filtered URLs: {len(final_urls)}",
            f"Overall reduction: {total_collected - len(final_urls)} URLs ({((total_collected - len(final_urls)) / total_collected * 100):.1f}%)" if total_collected > 0 else "Overall reduction: 0 URLs (0%)",
            "",
            "Output Files:",
            "  • all_urls.txt - Final filtered URLs",
            "  • waybackurls_results.txt - Wayback Machine URLs (if available)",
            "  • gau_results.txt - GAU URLs (if available)",
            "  • filtering_statistics.txt - Detailed filtering statistics",
            "",
            f"URO filtering: {'Enabled' if self.uro_filter.is_uro_available() else 'Disabled (tool not available)'}",
            f"Extension filtering: Enabled ({len(self.excluded_extensions)} extensions excluded)"
        ])
        
        return summary
    
    def collect_urls_for_analysis(self, target: str, domain_path: str) -> Dict[str, Any]:
        """
        Collect URLs specifically for further analysis (parameters, extensions, etc.)
        
        Args:
            target: Target domain
            domain_path: Domain output path
            
        Returns:
            Dict containing URLs categorized for different analysis types
        """
        self.log_info(f"Collecting URLs for analysis: {target}")
        
        # Execute main collection
        result = self.execute(target, domain_path)
        
        if not result.success or not result.data.get('filtered_urls'):
            return {}
        
        urls = result.data['filtered_urls']
        
        # Categorize URLs for different analysis types
        categorized = {
            'all_urls': urls,
            'parameterized_urls': [],
            'extension_urls': {},
            'potential_endpoints': [],
            'api_endpoints': []
        }
        
        # Analyze each URL
        for url in urls:
            # Check for parameters
            if '?' in url and '=' in url:
                categorized['parameterized_urls'].append(url)
            
            # Check for API patterns
            if any(pattern in url.lower() for pattern in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
                categorized['api_endpoints'].append(url)
            
            # Check for interesting endpoints
            if any(pattern in url.lower() for pattern in ['/admin', '/login', '/dashboard', '/config']):
                categorized['potential_endpoints'].append(url)
            
            # Categorize by extension
            for ext in ['php', 'asp', 'aspx', 'jsp', 'json', 'xml']:
                if url.lower().endswith(f'.{ext}') or f'.{ext}?' in url.lower():
                    if ext not in categorized['extension_urls']:
                        categorized['extension_urls'][ext] = []
                    categorized['extension_urls'][ext].append(url)
        
        # Apply URO filtering to parameterized URLs for better deduplication
        if categorized['parameterized_urls']:
            categorized['parameterized_urls'] = self.uro_filter.apply_consistent_filtering(
                categorized['parameterized_urls'], "Parameterized URLs"
            )
        
        # Save categorized results
        for category, urls_list in categorized.items():
            if isinstance(urls_list, list) and urls_list:
                self.save_results(domain_path, 'urls', f'{category}.txt', urls_list)
            elif isinstance(urls_list, dict):
                for ext, ext_urls in urls_list.items():
                    if ext_urls:
                        self.save_results(domain_path, 'urls', f'{ext}_urls.txt', ext_urls)
        
        return categorized
    
    def extract_parameterized_urls(self, urls: List[str], domain_path: str) -> List[str]:
        """
        Extract and deduplicate parameterized URLs with URO filtering
        
        Args:
            urls: List of URLs to process
            domain_path: Domain output path
            
        Returns:
            List[str]: Filtered parameterized URLs
        """
        if not urls:
            return []
        
        self.log_info(f"Extracting parameterized URLs from {len(urls)} URLs")
        
        # Extract URLs with parameters
        parameterized = []
        for url in urls:
            if '?' in url and '=' in url:
                parameterized.append(url)
        
        self.log_info(f"Found {len(parameterized)} parameterized URLs")
        
        if parameterized:
            # Apply URO filtering for better deduplication based on URL structure
            filtered_params = self.uro_filter.apply_consistent_filtering(
                parameterized, "Parameterized URLs"
            )
            
            # Save results
            self.save_results(domain_path, 'urls', 'parameterized_urls.txt', filtered_params)
            
            self.log_info(f"Filtered to {len(filtered_params)} unique parameterized URLs")
            return filtered_params
        
        return []
    
    def get_collection_capabilities(self) -> Dict[str, Any]:
        """
        Get information about URL collection capabilities
        
        Returns:
            Dict containing capability information
        """
        available_sources = self._check_available_sources()
        
        return {
            'available_sources': available_sources,
            'total_sources': len(self.sources),
            'uro_filtering': self.uro_filter.is_uro_available(),
            'extension_filtering': True,
            'excluded_extensions': self.excluded_extensions,
            'supports_categorization': True,
            'supports_batch_processing': True,
            'timeout_per_source': max(config['timeout'] for config in self.sources.values())
        }
    
    def provide_installation_guidance(self) -> None:
        """
        Provide installation guidance for missing URL collection tools
        """
        has_deps, missing_tools = self.validate_dependencies()
        
        if not missing_tools:
            self.log_info("All URL collection tools are available")
            return
        
        guidance = [
            "URL Collection Tools Installation Guide:",
            ""
        ]
        
        for tool in missing_tools:
            if tool == 'waybackurls':
                guidance.extend([
                    "• waybackurls - Wayback Machine URL fetcher",
                    "  Installation: go install github.com/tomnomnom/waybackurls@latest",
                    ""
                ])
            elif tool == 'gau':
                guidance.extend([
                    "• gau - GetAllUrls tool",
                    "  Installation: go install github.com/lc/gau/v2/cmd/gau@latest",
                    ""
                ])
            elif 'uro' in tool:
                guidance.extend([
                    "• uro - URL deduplication tool (recommended)",
                    "  Installation: pip3 install uro",
                    "  Note: URO provides better URL deduplication based on structure",
                    ""
                ])
        
        guidance.extend([
            "After installation, restart the tool to detect the new tools.",
            "URL collection will work with any available tools."
        ])
        
        for line in guidance:
            self.log_info(line)
    
    def get_results_summary(self) -> Dict[str, Any]:
        """
        Get summary of URL collection results
        
        Returns:
            Dict containing results summary
        """
        return {
            'module': 'URLCollector',
            'description': 'URL collection from multiple sources with URO filtering',
            'sources': list(self.sources.keys()),
            'filtering_enabled': True,
            'uro_integration': self.uro_filter.is_uro_available(),
            'excluded_extensions': len(self.excluded_extensions),
            'supports_parameterized_extraction': True
        }