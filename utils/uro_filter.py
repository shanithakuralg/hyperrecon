"""
Centralized URO integration and URL deduplication system
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import subprocess
import tempfile
from datetime import datetime
from typing import List, Optional, Tuple
from .base_utility import BaseUtility


class UROFilter(BaseUtility):
    """
    Centralized URO filtering utility for URL deduplication across all modules
    """
    
    def __init__(self, hyperrecon_instance):
        """
        Initialize URO filter with reference to main HyperRecon instance
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance
        """
        super().__init__(hyperrecon_instance)
        self.tool_name = 'uro'
        self._uro_available = None
    
    def execute(self, targets: List[str], domain_path: str) -> 'UtilityResult':
        """
        Execute URO filtering on a list of URLs with comprehensive error handling
        
        Args:
            targets: List of URLs to filter
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Filtered URLs and execution details
        """
        self.start_execution()
        self.set_operation("uro_filtering")
        
        if not targets:
            self.log_info("No URLs provided for filtering")
            return self.create_result(True, [], 0)
        
        try:
            # Check URO availability with enhanced error handling
            if not self.is_uro_available():
                if not self.handle_tool_missing('uro', required=False):
                    self.log_warning("Continuing without URO - no deduplication will be performed")
                    # Return original URLs without filtering
                    result = self.create_result(True, targets, len(targets))
                    result.metadata['uro_available'] = False
                    result.metadata['deduplication_performed'] = False
                    return result
            
            # Apply consistent filtering with error handling
            filtered_urls = self.apply_consistent_filtering(targets, "Input URLs")
            
            # Save filtering results with detailed statistics
            original_count = len(targets)
            filtered_count = len(filtered_urls)
            
            if filtered_count > 0:
                if not self.save_results(domain_path, 'url_filtering', 'uro_filtered_urls.txt', filtered_urls):
                    self.log_warning("Failed to save filtered URLs, continuing with in-memory results")
            
            # Always save filtering statistics
            stats = [
                f"URO Filtering Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Original URLs: {original_count}",
                f"Filtered URLs: {filtered_count}",
                f"URO Available: {self.is_uro_available()}",
                f"Duplicates Removed: {original_count - filtered_count}",
                f"Reduction: {((original_count - filtered_count) / original_count * 100):.1f}%" if original_count > 0 else "0%"
            ]
            
            if not self.is_uro_available():
                stats.append("Note: URO not available - no deduplication performed")
                stats.append(f"Installation: {self.get_installation_instructions()}")
            
            self.save_results(domain_path, 'url_filtering', 'filtering_statistics.txt', stats)
            
            # Create result with metadata
            result_metadata = {
                'original_count': original_count,
                'filtered_count': filtered_count,
                'duplicates_removed': original_count - filtered_count,
                'uro_available': self.is_uro_available(),
                'reduction_percentage': ((original_count - filtered_count) / original_count * 100) if original_count > 0 else 0
            }
            
            result = self.create_result(True, filtered_urls, original_count)
            result.metadata.update(result_metadata)
            
            return result
            
        except Exception as e:
            from .error_handler import ErrorCategory
            self.log_error("URO filtering execution failed", e, ErrorCategory.UNKNOWN_ERROR)
            
            # Graceful degradation - return original URLs as fallback
            self.log_info("Using fallback: returning original URLs without filtering")
            result = self.create_result(False, targets, len(targets))
            result.metadata['fallback_used'] = True
            result.metadata['error_occurred'] = True
            return result
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate URO tool availability
        
        Returns:
            Tuple[bool, List[str]]: (is_available, missing_dependencies)
        """
        if self.is_uro_available():
            return True, []
        else:
            return False, ['uro']
    
    def is_uro_available(self) -> bool:
        """
        Check if URO tool is available in the system
        
        Returns:
            bool: True if URO is available
        """
        if self._uro_available is not None:
            return self._uro_available
        
        try:
            result = subprocess.run(['uro', '--help'], capture_output=True, timeout=5)
            self._uro_available = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            self._uro_available = False
        
        return self._uro_available
    
    def provide_installation_guidance(self) -> None:
        """
        Provide clear installation instructions when URO is not available
        """
        if not self.is_uro_available():
            installation_msg = (
                "URO tool is not installed or not available in PATH.\n"
                f"Installation: {self.get_installation_instructions()}\n"
                "URO is recommended for removing duplicate URLs and improving scan efficiency.\n"
                "Without URO, duplicate URLs may remain in results."
            )
            
            if self.console:
                self.console.print(f"💡 [yellow]{installation_msg}[/yellow]")
            else:
                self.log_warning(installation_msg)
    
    def filter_urls(self, urls: List[str], show_counts: bool = True) -> List[str]:
        """
        Apply URO filtering to remove duplicate URLs with proper error handling and fallbacks
        
        Args:
            urls: List of URLs to filter
            show_counts: Whether to display original and filtered counts
            
        Returns:
            List[str]: Filtered URLs (original list if URO unavailable)
        """
        if not urls:
            return []
        
        original_count = len(urls)
        
        if not self.is_uro_available():
            if show_counts and self.verbose:
                self.log_warning(f"URO not available, keeping all {original_count} URLs")
                self.provide_installation_guidance()
            return urls
        
        try:
            # URO expects input from stdin
            urls_input = '\n'.join(urls)
            
            result = subprocess.run(
                ['uro'],
                input=urls_input,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large URL lists
            )
            
            if result.returncode == 0:
                filtered_urls = [url.strip() for url in result.stdout.split('\n') if url.strip()]
                filtered_count = len(filtered_urls)
                
                if show_counts and (self.verbose or filtered_count != original_count):
                    reduction = original_count - filtered_count
                    if reduction > 0:
                        percentage = (reduction / original_count) * 100
                        self.log_info(f"URO filtered: {original_count} → {filtered_count} URLs ({reduction} duplicates removed, {percentage:.1f}% reduction)")
                    else:
                        self.log_info(f"URO processed: {original_count} URLs (no duplicates found)")
                
                return filtered_urls
            else:
                error_msg = result.stderr.strip()[:200] if result.stderr else "Unknown error"
                self.log_warning(f"URO filtering failed: {error_msg}")
                if show_counts:
                    self.log_info(f"Fallback: keeping all {original_count} URLs")
                return urls
                
        except subprocess.TimeoutExpired:
            self.log_warning(f"URO filtering timeout after 300s for {original_count} URLs, returning original URLs")
            return urls
        except Exception as e:
            self.log_warning(f"URO filtering error: {str(e)}")
            if show_counts:
                self.log_info(f"Fallback: keeping all {original_count} URLs")
            return urls
    
    def filter_and_save(self, urls: List[str], domain_path: str, category: str, filename: str) -> List[str]:
        """
        Filter URLs and save results to specified location
        
        Args:
            urls: List of URLs to filter
            domain_path: Path to domain output directory
            category: Result category for saving
            filename: Output filename
            
        Returns:
            List[str]: Filtered URLs
        """
        if not urls:
            return []
        
        original_count = len(urls)
        filtered_urls = self.filter_urls(urls)
        filtered_count = len(filtered_urls)
        
        # Save filtered results
        if filtered_urls:
            self.save_results(domain_path, category, filename, filtered_urls)
            
            # Save filtering statistics if there was a reduction
            if filtered_count < original_count:
                stats_filename = f"{filename.rsplit('.', 1)[0]}_filtering_stats.txt"
                stats = [
                    f"Original URLs: {original_count}",
                    f"Filtered URLs: {filtered_count}",
                    f"Duplicates removed: {original_count - filtered_count}",
                    f"Reduction: {((original_count - filtered_count) / original_count * 100):.1f}%"
                ]
                self.save_results(domain_path, category, stats_filename, stats)
        
        return filtered_urls
    
    def filter_parameterized_urls(self, urls: List[str]) -> List[str]:
        """
        Filter parameterized URLs with special handling for parameter deduplication
        Deduplicates based on URL structure, not just parameter values
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List[str]: Filtered parameterized URLs
        """
        if not urls:
            return []
        
        # First filter for URLs that actually have parameters
        param_urls = [url for url in urls if '?' in url and '=' in url]
        
        if not param_urls:
            if self.verbose:
                self.log_info("No parameterized URLs found to filter")
            return []
        
        original_param_count = len(param_urls)
        
        # Apply URO filtering specifically for parameterized URLs
        # URO handles parameter-based deduplication by URL structure
        filtered_urls = self.filter_urls(param_urls, show_counts=False)
        filtered_count = len(filtered_urls)
        
        if self.verbose:
            if filtered_count != original_param_count:
                reduction = original_param_count - filtered_count
                percentage = (reduction / original_param_count) * 100
                self.log_info(f"Parameter URL deduplication: {original_param_count} → {filtered_count} URLs ({reduction} duplicates removed, {percentage:.1f}% reduction)")
            else:
                self.log_info(f"Parameter URL processing: {original_param_count} URLs (no duplicates found)")
        
        return filtered_urls
    
    def batch_filter_urls(self, url_batches: List[List[str]], batch_size: int = 1000) -> List[str]:
        """
        Filter large URL lists in batches to handle memory constraints
        
        Args:
            url_batches: List of URL batches to filter
            batch_size: Maximum URLs per batch
            
        Returns:
            List[str]: All filtered URLs combined
        """
        all_filtered_urls = []
        
        for i, batch in enumerate(url_batches):
            if self.verbose:
                self.log_info(f"Processing batch {i+1}/{len(url_batches)} ({len(batch)} URLs)")
            
            # Split large batches if needed
            if len(batch) > batch_size:
                sub_batches = [batch[j:j+batch_size] for j in range(0, len(batch), batch_size)]
                for sub_batch in sub_batches:
                    filtered_sub_batch = self.filter_urls(sub_batch)
                    all_filtered_urls.extend(filtered_sub_batch)
            else:
                filtered_batch = self.filter_urls(batch)
                all_filtered_urls.extend(filtered_batch)
        
        # Final deduplication across all batches
        final_filtered = self.filter_urls(all_filtered_urls)
        
        return final_filtered
    
    def get_installation_instructions(self) -> str:
        """
        Get URO installation instructions
        
        Returns:
            str: Installation command
        """
        return "pip3 install uro"
    
    def get_detailed_installation_guide(self) -> str:
        """
        Get detailed installation guide with troubleshooting
        
        Returns:
            str: Detailed installation instructions
        """
        guide = """
URO Installation Guide:

1. Standard Installation:
   pip3 install uro

2. If pip3 is not available:
   python3 -m pip install uro

3. For system-wide installation (may require sudo):
   sudo pip3 install uro

4. Using virtual environment (recommended):
   python3 -m venv venv
   source venv/bin/activate
   pip install uro

5. Verify installation:
   uro --help

Troubleshooting:
- Ensure Python 3.6+ is installed
- Update pip: pip3 install --upgrade pip
- Check PATH includes Python scripts directory
- For permission issues, use --user flag: pip3 install --user uro

URO improves scan efficiency by removing duplicate URLs based on structure.
"""
        return guide.strip()
    
    def get_uro_version(self) -> Optional[str]:
        """
        Get installed URO version
        
        Returns:
            Optional[str]: URO version or None if not available
        """
        if not self.is_uro_available():
            return None
        
        try:
            result = subprocess.run(['uro', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def filter_and_save_with_stats(self, urls: List[str], domain_path: str, 
                                  category: str, filename: str, source_name: str = "URLs") -> List[str]:
        """
        Filter URLs, save results, and generate comprehensive statistics
        
        Args:
            urls: List of URLs to filter
            domain_path: Path to domain output directory
            category: Result category for saving
            filename: Output filename
            source_name: Name of the URL source for logging
            
        Returns:
            List[str]: Filtered URLs
        """
        if not urls:
            return []
        
        # Apply consistent filtering
        filtered_urls = self.apply_consistent_filtering(urls, source_name)
        
        # Save filtered results and statistics
        if filtered_urls:
            self.save_results(domain_path, category, filename, filtered_urls)
        
        # Generate and save detailed statistics
        original_count = len(urls)
        filtered_count = len(filtered_urls)
        
        stats_filename = f"{filename.rsplit('.', 1)[0]}_stats.txt"
        stats = [
            f"{source_name} Filtering Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Source: {source_name}",
            f"Original URLs: {original_count}",
            f"Filtered URLs: {filtered_count}",
            f"Duplicates Removed: {original_count - filtered_count}",
            f"Reduction: {((original_count - filtered_count) / original_count * 100):.1f}%" if original_count > 0 else "0%",
            f"URO Available: {self.is_uro_available()}",
            f"Timestamp: {datetime.now().isoformat()}"
        ]
        
        if not self.is_uro_available():
            stats.extend([
                "",
                "Note: URO tool not available - no deduplication performed",
                f"Installation: {self.get_installation_instructions()}",
                "URO improves scan efficiency by removing duplicate URLs"
            ])
        
        self.save_results(domain_path, category, stats_filename, stats)
        
        return filtered_urls
    
    def apply_consistent_filtering(self, urls: List[str], source_name: str = "URLs") -> List[str]:
        """
        Apply consistent URO filtering across all URL collection functions
        
        Args:
            urls: List of URLs to filter
            source_name: Name of the URL source for logging
            
        Returns:
            List[str]: Consistently filtered URLs
        """
        if not urls:
            if self.verbose:
                self.log_info(f"No {source_name} to filter")
            return []
        
        original_count = len(urls)
        
        # Remove empty and invalid URLs first
        valid_urls = [url.strip() for url in urls if url.strip() and url.startswith(('http://', 'https://'))]
        
        if not valid_urls:
            if self.verbose:
                self.log_warning(f"No valid URLs found in {source_name} list")
            return []
        
        # Apply URO filtering
        filtered_urls = self.filter_urls(valid_urls, show_counts=False)
        
        # Log comprehensive filtering results
        if self.verbose:
            valid_count = len(valid_urls)
            filtered_count = len(filtered_urls)
            invalid_removed = original_count - valid_count
            duplicates_removed = valid_count - filtered_count
            
            self.log_info(f"{source_name} filtering summary:")
            self.log_info(f"  • Original: {original_count}")
            if invalid_removed > 0:
                self.log_info(f"  • Invalid removed: {invalid_removed}")
            self.log_info(f"  • Valid: {valid_count}")
            if duplicates_removed > 0:
                self.log_info(f"  • Duplicates removed: {duplicates_removed}")
            self.log_info(f"  • Final: {filtered_count}")
        
        return filtered_urls
    
    def test_uro_functionality(self) -> bool:
        """
        Test URO functionality with sample URLs
        
        Returns:
            bool: True if URO is working correctly
        """
        if not self.is_uro_available():
            return False
        
        # Test with sample duplicate URLs
        test_urls = [
            'https://example.com/page?id=1',
            'https://example.com/page?id=2',
            'https://example.com/page?id=1',  # Duplicate
            'https://example.com/other'
        ]
        
        try:
            filtered = self.filter_urls(test_urls, show_counts=False)
            # Should remove the duplicate
            return len(filtered) < len(test_urls)
        except:
            return False
    
    @classmethod
    def create_shared_instance(cls, hyperrecon_instance):
        """
        Create a shared URO filter instance for use across multiple modules
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance
            
        Returns:
            UROFilter: Shared URO filter instance
        """
        return cls(hyperrecon_instance)
    
    def get_filtering_summary(self) -> dict:
        """
        Get a summary of URO filtering capabilities and status
        
        Returns:
            dict: URO filter status and capabilities
        """
        return {
            'uro_available': self.is_uro_available(),
            'version': self.get_uro_version(),
            'installation_command': self.get_installation_instructions(),
            'functionality_test': self.test_uro_functionality(),
            'supports_batch_filtering': True,
            'supports_parameterized_urls': True,
            'provides_statistics': True,
            'fallback_available': True
        }