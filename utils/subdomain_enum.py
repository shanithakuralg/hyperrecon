"""
Subdomain enumeration module with URO integration and comprehensive error handling
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

from typing import List, Tuple, Set
from datetime import datetime
from .base_utility import BaseUtility, UtilityResult, ToolValidator
from .uro_filter import UROFilter


class SubdomainEnumerator(BaseUtility):
    """
    Subdomain enumeration utility with multiple tool integration and URO filtering
    Supports subfinder and assetfinder with proper error handling and dependency validation
    """
    
    def __init__(self, hyperrecon_instance):
        """
        Initialize subdomain enumerator with URO integration
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance
        """
        super().__init__(hyperrecon_instance)
        self.uro_filter = UROFilter(hyperrecon_instance)
        self.supported_tools = ['subfinder', 'assetfinder']
        
    def execute(self, domain: str, domain_path: str) -> UtilityResult:
        """
        Execute comprehensive subdomain enumeration with enhanced error handling
        
        Args:
            domain: Target domain for subdomain enumeration
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult: Enumerated subdomains and execution details
        """
        self.start_execution()
        self.set_operation("subdomain_enumeration")
        
        if not domain:
            from .error_handler import ErrorCategory
            self.log_error("No domain provided for subdomain enumeration", 
                          category=ErrorCategory.VALIDATION_ERROR)
            return self.create_result(False, [], 0)
        
        self.log_info(f"Starting subdomain enumeration for {domain}")
        
        try:
            # Validate dependencies with enhanced error handling
            available_tools, missing_tools = self.validate_dependencies()
            
            # Handle missing tools gracefully
            for tool in missing_tools:
                if not self.handle_tool_missing(tool, required=False):  # Make all tools optional
                    self.log_warning(f"Tool {tool} is not available, continuing with available tools")
            
            if not available_tools:
                self.log_warning("No subdomain enumeration tools available, using target domain only")
                # Use the target domain itself as a subdomain
                fallback_subdomains = [domain]
                
                # Save the fallback result
                self.save_results(domain_path, 'subdomains', 'fallback_subdomains.txt', fallback_subdomains)
                
                # Save statistics
                stats = [
                    f"Subdomain Enumeration Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Source: Fallback (no tools available)",
                    f"Target Domain: {domain}",
                    f"Subdomains Found: 1",
                    f"Tools Used: None (fallback mode)",
                    f"Missing Tools: {', '.join(missing_tools)}",
                    f"Timestamp: {datetime.now().isoformat()}"
                ]
                self.save_results(domain_path, 'subdomains', 'subdomain_statistics.txt', stats)
                
                result_data = {
                    'subdomains': fallback_subdomains,
                    'tool_results': {'manual': fallback_subdomains},
                    'domain': domain,
                    'total_found': 1,
                    'successful_tools': ['manual'],
                    'failed_tools': missing_tools,
                    'fallback_used': True
                }
                return self.create_result(True, result_data, 1)
            
            # Collect subdomains from all available tools with error handling
            all_subdomains = set()
            tool_results = {}
            successful_tools = []
            failed_tools = []
            
            # Run Subfinder with error handling
            if self.check_tool_installed('subfinder'):
                try:
                    self.set_operation("subfinder_execution")
                    subfinder_results = self._run_subfinder(domain, domain_path)
                    if subfinder_results:
                        all_subdomains.update(subfinder_results)
                        tool_results['subfinder'] = subfinder_results
                        successful_tools.append('subfinder')
                        self.log_info(f"Subfinder found {len(subfinder_results)} subdomains")
                    else:
                        self.log_warning("Subfinder returned no results")
                except Exception as e:
                    from .error_handler import ErrorCategory
                    self.log_error(f"Subfinder execution failed", e, ErrorCategory.NETWORK_ERROR)
                    failed_tools.append('subfinder')
            
            # Run Assetfinder with error handling
            if (getattr(self.hyperrecon, 'enable_assetfinder', True) and 
                self.check_tool_installed('assetfinder')):
                try:
                    self.set_operation("assetfinder_execution")
                    assetfinder_results = self._run_assetfinder(domain, domain_path)
                    if assetfinder_results:
                        all_subdomains.update(assetfinder_results)
                        tool_results['assetfinder'] = assetfinder_results
                        successful_tools.append('assetfinder')
                        self.log_info(f"Assetfinder found {len(assetfinder_results)} subdomains")
                    else:
                        self.log_warning("Assetfinder returned no results")
                except Exception as e:
                    from .error_handler import ErrorCategory
                    self.log_error(f"Assetfinder execution failed", e, ErrorCategory.NETWORK_ERROR)
                    failed_tools.append('assetfinder')
            
            # Check if we have any results
            if not all_subdomains and not successful_tools:
                self.log_warning("No subdomains found by any tool")
                # Still return success but with empty results
                result_data = {
                    'subdomains': [],
                    'tool_results': {},
                    'domain': domain,
                    'total_found': 0,
                    'successful_tools': successful_tools,
                    'failed_tools': failed_tools
                }
                return self.create_result(True, result_data, 0)
            
            # Process and filter results with error handling
            try:
                self.set_operation("subdomain_processing")
                final_subdomains = self._process_subdomains(all_subdomains, domain, domain_path)
            except Exception as e:
                from .error_handler import ErrorCategory
                self.log_error("Subdomain processing failed, using unprocessed results", 
                              e, ErrorCategory.PARSING_ERROR)
                final_subdomains = list(all_subdomains)
            
            # Create comprehensive result with error tracking
            result_data = {
                'subdomains': final_subdomains,
                'tool_results': tool_results,
                'domain': domain,
                'total_found': len(final_subdomains),
                'successful_tools': successful_tools,
                'failed_tools': failed_tools
            }
            
            self.log_info(f"Subdomain enumeration completed: {len(final_subdomains)} unique subdomains found")
            
            # Mark as successful even if some tools failed, as long as we got results
            success = len(final_subdomains) > 0 or len(successful_tools) > 0
            
            return self.create_result(success, result_data, len(final_subdomains))
            
        except Exception as e:
            from .error_handler import ErrorCategory
            self.log_error("Subdomain enumeration failed", e, ErrorCategory.UNKNOWN_ERROR)
            
            # Return empty result but mark the attempt
            result_data = {
                'subdomains': [],
                'tool_results': {},
                'domain': domain,
                'total_found': 0,
                'error_occurred': True
            }
            return self.create_result(False, result_data, 0)
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate subdomain enumeration tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (has_available_tools, missing_tools)
        """
        available_tools = []
        missing_tools = []
        
        for tool in self.supported_tools:
            if self.check_tool_installed(tool):
                available_tools.append(tool)
            else:
                missing_tools.append(tool)
        
        # At least one tool should be available
        has_tools = len(available_tools) > 0
        
        return has_tools, missing_tools
    
    def _run_subfinder(self, domain: str, domain_path: str) -> List[str]:
        """
        Run subfinder for subdomain enumeration
        
        Args:
            domain: Target domain
            domain_path: Output directory path
            
        Returns:
            List[str]: Found subdomains
        """
        try:
            self.log_info("Running Subfinder")
            
            result = self.run_command(
                ['subfinder', '-d', domain, '-silent'],
                timeout=300,  # 5 minute timeout
                description="Running Subfinder"
            )
            
            if result:
                subdomains = [sub.strip() for sub in result.split('\n') if sub.strip()]
                
                # Save raw subfinder results
                if subdomains:
                    self.save_results(domain_path, 'subdomains', 'subfinder_results.txt', subdomains)
                
                return subdomains
            else:
                self.log_warning("Subfinder returned no results")
                return []
                
        except Exception as e:
            self.log_error("Subfinder execution failed", e)
            return []
    
    def _run_assetfinder(self, domain: str, domain_path: str) -> List[str]:
        """
        Run assetfinder for subdomain enumeration
        
        Args:
            domain: Target domain
            domain_path: Output directory path
            
        Returns:
            List[str]: Found subdomains
        """
        try:
            self.log_info("Running Assetfinder")
            
            result = self.run_command(
                ['assetfinder', '--subs-only', domain],
                timeout=300,  # 5 minute timeout
                description="Running Assetfinder"
            )
            
            if result:
                subdomains = [sub.strip() for sub in result.split('\n') if sub.strip()]
                
                # Save raw assetfinder results
                if subdomains:
                    self.save_results(domain_path, 'subdomains', 'assetfinder_results.txt', subdomains)
                
                return subdomains
            else:
                self.log_warning("Assetfinder returned no results")
                return []
                
        except Exception as e:
            self.log_error("Assetfinder execution failed", e)
            return []
    
    def _process_subdomains(self, all_subdomains: Set[str], domain: str, domain_path: str) -> List[str]:
        """
        Process and filter collected subdomains with URO integration
        
        Args:
            all_subdomains: Set of all collected subdomains
            domain: Target domain for validation
            domain_path: Output directory path
            
        Returns:
            List[str]: Processed and filtered subdomains
        """
        if not all_subdomains:
            self.log_info("No subdomains to process")
            return []
        
        # Convert to list and filter for domain relevance
        subdomain_list = []
        for sub in all_subdomains:
            sub = sub.strip()
            if sub and domain in sub:
                # Ensure it's a valid subdomain format
                if self._is_valid_subdomain(sub, domain):
                    subdomain_list.append(sub)
        
        if not subdomain_list:
            self.log_warning("No valid subdomains found after filtering")
            return []
        
        self.log_info(f"Processing {len(subdomain_list)} valid subdomains")
        
        # Apply URO filtering to remove duplicates (for subdomains, not URLs)
        # Use simple deduplication for subdomains since they don't have URL format
        unique_subdomains = list(set(subdomain_list))
        
        # Save all unique subdomains
        if unique_subdomains:
            self.save_results(domain_path, 'subdomains', 'all_subdomains.txt', unique_subdomains)
            
            # Save filtering statistics
            original_count = len(subdomain_list)
            filtered_count = len(unique_subdomains)
            duplicates_removed = original_count - filtered_count
            
            stats = [
                f"Subdomains Filtering Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Source: Subdomains",
                f"Original URLs: {original_count}",
                f"Filtered URLs: {filtered_count}",
                f"Duplicates Removed: {duplicates_removed}",
                f"Reduction: {(duplicates_removed / original_count * 100):.1f}%" if original_count > 0 else "0%",
                f"URO Available: {self.uro_filter.is_uro_available()}",
                f"Timestamp: {datetime.now().isoformat()}"
            ]
            
            self.save_results(domain_path, 'subdomains', 'all_subdomains_stats.txt', stats)
        
        filtered_subdomains = unique_subdomains
        
        # Save additional metadata
        self._save_subdomain_metadata(filtered_subdomains, domain, domain_path)
        
        return filtered_subdomains
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """
        Validate if a subdomain is properly formatted and relevant
        
        Args:
            subdomain: Subdomain to validate
            domain: Parent domain
            
        Returns:
            bool: True if valid subdomain
        """
        try:
            # Basic format validation
            if not subdomain or not domain:
                return False
            
            # Must contain the domain
            if domain not in subdomain:
                return False
            
            # Should not be just the domain itself (unless it's a direct match)
            if subdomain == domain:
                return True
            
            # Should end with the domain or be a proper subdomain
            if subdomain.endswith(f'.{domain}') or subdomain.endswith(domain):
                return True
            
            # Check if it's a subdomain with the domain in the middle (less common but valid)
            if f'.{domain}.' in subdomain:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _save_subdomain_metadata(self, subdomains: List[str], domain: str, domain_path: str) -> None:
        """
        Save comprehensive subdomain metadata and statistics
        
        Args:
            subdomains: Final list of subdomains
            domain: Target domain
            domain_path: Output directory path
        """
        try:
            from datetime import datetime
            
            # Generate subdomain statistics
            stats = [
                f"Subdomain Enumeration Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Target Domain: {domain}",
                f"Total Subdomains Found: {len(subdomains)}",
                f"Tools Used: {', '.join([tool for tool in self.supported_tools if self.check_tool_installed(tool)])}",
                f"URO Filtering Applied: {self.uro_filter.is_uro_available()}",
                "",
                "Subdomain Breakdown:"
            ]
            
            # Analyze subdomain levels
            level_counts = {}
            for sub in subdomains:
                level = sub.count('.') - domain.count('.')
                level_counts[level] = level_counts.get(level, 0) + 1
            
            for level in sorted(level_counts.keys()):
                if level == 0:
                    stats.append(f"  Direct domain: {level_counts[level]}")
                else:
                    stats.append(f"  Level {level} subdomains: {level_counts[level]}")
            
            # Save statistics
            self.save_results(domain_path, 'subdomains', 'subdomain_statistics.txt', stats)
            
            # Create a summary file with just the count for quick reference
            summary = [f"{len(subdomains)} subdomains found for {domain}"]
            self.save_results(domain_path, 'subdomains', 'subdomain_count.txt', summary)
            
        except Exception as e:
            self.log_warning(f"Failed to save subdomain metadata: {e}")
    
    def _provide_installation_guidance(self, missing_tools: List[str]) -> None:
        """
        Provide installation guidance for missing tools
        
        Args:
            missing_tools: List of missing tool names
        """
        if not missing_tools:
            return
        
        guidance_msg = "Missing subdomain enumeration tools detected:\n"
        
        for tool in missing_tools:
            instruction = ToolValidator.get_installation_instructions(tool)
            guidance_msg += f"  • {tool}: {instruction}\n"
        
        guidance_msg += "\nAt least one tool is required for subdomain enumeration."
        
        if self.console:
            self.console.print(f"💡 [yellow]{guidance_msg}[/yellow]")
        else:
            self.log_warning(guidance_msg)
    
    def get_supported_tools(self) -> List[str]:
        """
        Get list of supported subdomain enumeration tools
        
        Returns:
            List[str]: Supported tool names
        """
        return self.supported_tools.copy()
    
    def get_available_tools(self) -> List[str]:
        """
        Get list of currently available subdomain enumeration tools
        
        Returns:
            List[str]: Available tool names
        """
        return [tool for tool in self.supported_tools if self.check_tool_installed(tool)]
    
    def test_tool_functionality(self, tool_name: str) -> bool:
        """
        Test if a specific tool is working correctly
        
        Args:
            tool_name: Name of the tool to test
            
        Returns:
            bool: True if tool is functional
        """
        if not self.check_tool_installed(tool_name):
            return False
        
        try:
            if tool_name == 'subfinder':
                # Test with help flag
                result = self.run_command(['subfinder', '-h'], timeout=10)
                return 'subfinder' in result.lower()
            elif tool_name == 'assetfinder':
                # Test with help flag
                result = self.run_command(['assetfinder', '-h'], timeout=10)
                return 'assetfinder' in result.lower()
            
        except Exception:
            pass
        
        return False
    
    def get_enumeration_summary(self) -> dict:
        """
        Get a summary of subdomain enumeration capabilities
        
        Returns:
            dict: Enumeration capabilities and status
        """
        available_tools = self.get_available_tools()
        missing_tools = [tool for tool in self.supported_tools if tool not in available_tools]
        
        return {
            'supported_tools': self.supported_tools,
            'available_tools': available_tools,
            'missing_tools': missing_tools,
            'uro_integration': self.uro_filter.is_uro_available(),
            'ready_for_enumeration': len(available_tools) > 0,
            'tool_functionality': {
                tool: self.test_tool_functionality(tool) 
                for tool in self.supported_tools
            }
        }