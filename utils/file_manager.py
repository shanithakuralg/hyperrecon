"""
Centralized file operations and output management system
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import json
import shutil
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime


class FileManager:
    """
    Centralized file management for consistent output handling and organization
    """
    
    def __init__(self, hyperrecon_instance):
        """
        Initialize file manager with reference to main HyperRecon instance
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance
        """
        self.hyperrecon = hyperrecon_instance
        self.console = getattr(hyperrecon_instance, 'console', None)
        self.verbose = getattr(hyperrecon_instance, 'verbose', False)
        
        # Initialize file operation statistics
        self.stats = {
            'files_created': 0,
            'files_updated': 0,
            'bytes_written': 0,
            'errors': 0,
            'last_operation': None
        }
        
        # Directory structure for organized output
        self.directory_structure = {
            'subdomains': 'Subdomain enumeration results',
            'urls': 'URL collection results',
            'parameters': 'Parameter discovery results',
            'live_hosts': 'HTTP probing results',
            'technology_detection': 'Technology fingerprinting',
            'gf_patterns': 'GF pattern extraction',
            'extensions': 'File extension filtering',
            'documents': 'PDF/DOC/PPT analysis',
            'js_analysis': 'JavaScript file analysis',
            'vulnerabilities': 'Nuclei vulnerability results',
            'directories': 'Directory bruteforce results',
            'unfurl_results': 'URL unfurling results',
            'sensitive_data': 'Sensitive data patterns',
            'url_filtering': 'URO filtering results',
            'security_checks': 'Security misconfiguration',
            'social_media_recon': 'Social media reconnaissance'
        }
    
    def create_output_structure(self, domain: str, base_output_dir: Optional[str] = None) -> str:
        """
        Create organized output directory structure for a domain
        
        Args:
            domain: Target domain name
            base_output_dir: Base output directory (optional)
            
        Returns:
            str: Path to domain-specific output directory
        """
        # Determine base output directory
        if not base_output_dir:
            if hasattr(self.hyperrecon, 'output_dir') and self.hyperrecon.output_dir:
                base_output_dir = self.hyperrecon.output_dir
            else:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                base_output_dir = f"hyperrecon_results_{timestamp}"
        
        # Create base directory
        os.makedirs(base_output_dir, exist_ok=True)
        
        # Create domain-specific folder
        domain_folder = domain.replace('.', '_').replace(':', '_')
        domain_path = os.path.join(base_output_dir, domain_folder)
        os.makedirs(domain_path, exist_ok=True)
        
        # Create all subdirectories
        for subdir, description in self.directory_structure.items():
            subdir_path = os.path.join(domain_path, subdir)
            os.makedirs(subdir_path, exist_ok=True)
            
            # Create a README file in each subdirectory
            readme_path = os.path.join(subdir_path, 'README.txt')
            if not os.path.exists(readme_path):
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write(f"# {subdir.upper()}\n")
                    f.write(f"Description: {description}\n")
                    f.write(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if self.console and self.verbose:
            self.console.print(f"📁 [green]Created output structure: {domain_path}[/green]")
        
        return domain_path
    
    def save_results_realtime(self, domain_path: str, category: str, filename: str, 
                             data: Any, append: bool = False) -> bool:
        """
        Save results in real-time to prevent data loss
        
        Args:
            domain_path: Path to domain output directory
            category: Result category (subdirectory)
            filename: Output filename
            data: Data to save
            append: Whether to append to existing file
            
        Returns:
            bool: True if save was successful
        """
        if not data:
            return False
        
        try:
            # Validate domain_path exists or can be created
            if not os.path.exists(domain_path):
                try:
                    os.makedirs(domain_path, exist_ok=True)
                except (OSError, PermissionError) as e:
                    if self.console:
                        self.console.print(f"❌ [red]Cannot create domain path {domain_path}: {e}[/red]")
                    return False
            
            # Ensure category directory exists
            category_path = os.path.join(domain_path, category)
            try:
                os.makedirs(category_path, exist_ok=True)
            except (OSError, PermissionError) as e:
                if self.console:
                    self.console.print(f"❌ [red]Cannot create category path {category_path}: {e}[/red]")
                return False
            
            file_path = os.path.join(category_path, filename)
            mode = 'a' if append else 'w'
            
            # Check if file exists to determine operation type
            file_exists = os.path.exists(file_path)
            operation_type = 'update' if file_exists else 'create'
            
            with open(file_path, mode, encoding='utf-8') as f:
                bytes_written = 0
                if isinstance(data, list):
                    for item in data:
                        line = f"{item}\n"
                        f.write(line)
                        bytes_written += len(line.encode('utf-8'))
                elif isinstance(data, str):
                    f.write(data)
                    bytes_written += len(data.encode('utf-8'))
                    if not data.endswith('\n'):
                        f.write('\n')
                        bytes_written += 1
                elif isinstance(data, dict):
                    json_str = json.dumps(data, indent=2) + '\n'
                    f.write(json_str)
                    bytes_written += len(json_str.encode('utf-8'))
                else:
                    str_data = str(data) + '\n'
                    f.write(str_data)
                    bytes_written += len(str_data.encode('utf-8'))
            
            # Update statistics
            self._update_stats(operation_type, bytes_written)
            
            if self.console and self.verbose:
                item_count = len(data) if isinstance(data, list) else 1
                self.console.print(f"💾 [blue]Saved {item_count} items to {category}/{filename}[/blue]")
            
            return True
            
        except (OSError, PermissionError, IOError) as e:
            self._update_stats('error', error=True)
            if self.console:
                self.console.print(f"❌ [red]Failed to save to {category}/{filename}: {e}[/red]")
            return False
        except Exception as e:
            self._update_stats('error', error=True)
            if self.console:
                self.console.print(f"❌ [red]Unexpected error saving to {category}/{filename}: {e}[/red]")
            return False
    
    def ensure_directory_exists(self, path: str) -> bool:
        """
        Ensure a directory exists, creating it if necessary
        
        Args:
            path: Directory path to create
            
        Returns:
            bool: True if directory exists or was created successfully
        """
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to create directory {path}: {e}[/red]")
            return False
    
    def save_json_results(self, domain_path: str, category: str, filename: str, 
                         data: Dict[str, Any]) -> bool:
        """
        Save results in JSON format
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Output filename (will add .json if not present)
            data: Data to save as JSON
            
        Returns:
            bool: True if save was successful
        """
        if not filename.endswith('.json'):
            filename += '.json'
        
        try:
            category_path = os.path.join(domain_path, category)
            os.makedirs(category_path, exist_ok=True)
            
            file_path = os.path.join(category_path, filename)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            if self.console and self.verbose:
                self.console.print(f"💾 [blue]Saved JSON data to {category}/{filename}[/blue]")
            
            return True
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to save JSON to {category}/{filename}: {e}[/red]")
            return False
    
    def load_json_results(self, domain_path: str, category: str, filename: str) -> Optional[Dict[str, Any]]:
        """
        Load results from JSON file
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Input filename
            
        Returns:
            Dict containing loaded data or None if failed
        """
        try:
            file_path = os.path.join(domain_path, category, filename)
            
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
                
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to load JSON from {category}/{filename}: {e}[/red]")
            return None
    
    def save_timestamped_results(self, domain_path: str, category: str, filename: str, 
                                data: Any, include_metadata: bool = True) -> bool:
        """
        Save results with timestamp and metadata
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Output filename
            data: Data to save
            include_metadata: Whether to include timestamp metadata
            
        Returns:
            bool: True if save was successful
        """
        timestamped_data = []
        
        if include_metadata:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            timestamped_data.append(f"[{timestamp}] Results for {category}")
            timestamped_data.append("")
        
        if isinstance(data, list):
            timestamped_data.extend(data)
        elif isinstance(data, str):
            timestamped_data.append(data)
        else:
            timestamped_data.append(str(data))
        
        return self.save_results_realtime(domain_path, category, filename, timestamped_data)
    
    def get_file_path(self, domain_path: str, category: str, filename: str) -> str:
        """
        Get full file path for a result file
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Filename
            
        Returns:
            str: Full file path
        """
        return os.path.join(domain_path, category, filename)
    
    def file_exists(self, domain_path: str, category: str, filename: str) -> bool:
        """
        Check if a result file exists
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Filename to check
            
        Returns:
            bool: True if file exists
        """
        file_path = self.get_file_path(domain_path, category, filename)
        return os.path.exists(file_path)
    
    def get_file_size(self, domain_path: str, category: str, filename: str) -> int:
        """
        Get size of a result file in bytes
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Filename
            
        Returns:
            int: File size in bytes, -1 if file doesn't exist
        """
        file_path = self.get_file_path(domain_path, category, filename)
        
        try:
            return os.path.getsize(file_path)
        except:
            return -1
    
    def list_category_files(self, domain_path: str, category: str) -> List[str]:
        """
        List all files in a category directory
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            
        Returns:
            List of filenames in the category
        """
        category_path = os.path.join(domain_path, category)
        
        try:
            if os.path.exists(category_path):
                return [f for f in os.listdir(category_path) 
                       if os.path.isfile(os.path.join(category_path, f))]
            else:
                return []
        except:
            return []
    
    def save_filtered_urls(self, domain_path: str, category: str, filename: str, 
                          original_urls: List[str], filtered_urls: List[str], 
                          filter_method: str = "URO") -> bool:
        """
        Save URLs with filtering information and statistics
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Output filename
            original_urls: Original URL list before filtering
            filtered_urls: Filtered URL list
            filter_method: Method used for filtering (default: URO)
            
        Returns:
            bool: True if save was successful
        """
        try:
            # Create metadata about filtering
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            original_count = len(original_urls)
            filtered_count = len(filtered_urls)
            removed_count = original_count - filtered_count
            
            # Prepare content with metadata
            content_lines = [
                f"# URL Filtering Results - {filter_method}",
                f"# Generated: {timestamp}",
                f"# Original URLs: {original_count}",
                f"# Filtered URLs: {filtered_count}",
                f"# Removed duplicates: {removed_count}",
                f"# Reduction: {(removed_count/original_count*100):.1f}%" if original_count > 0 else "# Reduction: 0%",
                "",
                "# Filtered URLs:"
            ]
            
            # Add filtered URLs
            content_lines.extend(filtered_urls)
            
            # Save filtered results
            success = self.save_results_realtime(domain_path, category, filename, content_lines)
            
            # Also save original URLs for reference if requested
            if success and original_count != filtered_count:
                original_filename = f"original_{filename}"
                self.save_results_realtime(domain_path, category, original_filename, original_urls)
            
            if self.console and self.verbose and success:
                self.console.print(f"🔍 [green]Filtered {original_count} → {filtered_count} URLs ({filter_method})[/green]")
            
            return success
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to save filtered URLs: {e}[/red]")
            return False
    
    def backup_existing_file(self, domain_path: str, category: str, filename: str) -> bool:
        """
        Create a backup of an existing file before overwriting
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Filename to backup
            
        Returns:
            bool: True if backup was successful or file doesn't exist
        """
        try:
            file_path = self.get_file_path(domain_path, category, filename)
            
            if not os.path.exists(file_path):
                return True  # No file to backup
            
            # Create backup with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{filename}.backup_{timestamp}"
            backup_path = self.get_file_path(domain_path, category, backup_filename)
            
            shutil.copy2(file_path, backup_path)
            
            if self.console and self.verbose:
                self.console.print(f"💾 [blue]Created backup: {backup_filename}[/blue]")
            
            return True
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to create backup for {filename}: {e}[/red]")
            return False
    
    def cleanup_old_backups(self, domain_path: str, category: str, keep_count: int = 5) -> int:
        """
        Clean up old backup files, keeping only the most recent ones
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            keep_count: Number of backups to keep per file
            
        Returns:
            int: Number of backup files removed
        """
        removed_count = 0
        
        try:
            category_path = os.path.join(domain_path, category)
            if not os.path.exists(category_path):
                return 0
            
            # Group backup files by original filename
            backup_groups = {}
            for filename in os.listdir(category_path):
                if '.backup_' in filename:
                    original_name = filename.split('.backup_')[0]
                    if original_name not in backup_groups:
                        backup_groups[original_name] = []
                    backup_groups[original_name].append(filename)
            
            # Clean up old backups for each file
            for original_name, backups in backup_groups.items():
                if len(backups) > keep_count:
                    # Sort by modification time (newest first)
                    backups.sort(key=lambda x: os.path.getmtime(
                        os.path.join(category_path, x)
                    ), reverse=True)
                    
                    # Remove old backups
                    for old_backup in backups[keep_count:]:
                        backup_path = os.path.join(category_path, old_backup)
                        os.remove(backup_path)
                        removed_count += 1
            
            if self.console and self.verbose and removed_count > 0:
                self.console.print(f"🧹 [blue]Cleaned up {removed_count} old backup files[/blue]")
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to cleanup backups: {e}[/red]")
        
        return removed_count
    
    def get_results_summary(self, domain_path: str) -> Dict[str, Any]:
        """
        Get summary of all results for a domain
        
        Args:
            domain_path: Path to domain output directory
            
        Returns:
            Dict containing results summary
        """
        summary = {
            'domain_path': domain_path,
            'categories': {},
            'total_files': 0,
            'total_size_bytes': 0,
            'created_time': None
        }
        
        try:
            # Get creation time from domain directory
            if os.path.exists(domain_path):
                stat = os.stat(domain_path)
                summary['created_time'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
            
            # Analyze each category
            for category in self.directory_structure.keys():
                category_path = os.path.join(domain_path, category)
                
                if os.path.exists(category_path):
                    files = self.list_category_files(domain_path, category)
                    category_size = sum(
                        self.get_file_size(domain_path, category, f) 
                        for f in files if self.get_file_size(domain_path, category, f) > 0
                    )
                    
                    summary['categories'][category] = {
                        'file_count': len(files),
                        'size_bytes': category_size,
                        'files': files
                    }
                    
                    summary['total_files'] += len(files)
                    summary['total_size_bytes'] += category_size
                else:
                    summary['categories'][category] = {
                        'file_count': 0,
                        'size_bytes': 0,
                        'files': []
                    }
        
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to generate results summary: {e}[/red]")
        
        return summary
    
    def ensure_documents_folder_structure(self, domain_path: str) -> bool:
        """
        Ensure Documents folder contains expected output files and structure
        
        Args:
            domain_path: Path to domain output directory
            
        Returns:
            bool: True if Documents folder is properly structured
        """
        try:
            documents_path = os.path.join(domain_path, 'documents')
            os.makedirs(documents_path, exist_ok=True)
            
            # Create expected subdirectories for different document types
            doc_subdirs = {
                'pdf': 'PDF documents',
                'doc': 'Word documents', 
                'ppt': 'PowerPoint presentations',
                'xls': 'Excel spreadsheets',
                'txt': 'Text files',
                'other': 'Other document types'
            }
            
            for subdir, description in doc_subdirs.items():
                subdir_path = os.path.join(documents_path, subdir)
                os.makedirs(subdir_path, exist_ok=True)
                
                # Create info file if it doesn't exist
                info_file = os.path.join(subdir_path, 'info.txt')
                if not os.path.exists(info_file):
                    with open(info_file, 'w', encoding='utf-8') as f:
                        f.write(f"# {subdir.upper()} Documents\n")
                        f.write(f"Description: {description}\n")
                        f.write(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            if self.console and self.verbose:
                self.console.print(f"📁 [green]Documents folder structure verified: {documents_path}[/green]")
            
            return True
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to ensure Documents folder structure: {e}[/red]")
            return False
    
    def save_document_analysis_results(self, domain_path: str, doc_type: str, 
                                     filename: str, analysis_data: Dict[str, Any]) -> bool:
        """
        Save document analysis results in the Documents folder with proper organization
        
        Args:
            domain_path: Path to domain output directory
            doc_type: Type of document (pdf, doc, ppt, xls, txt, other)
            filename: Output filename
            analysis_data: Document analysis data
            
        Returns:
            bool: True if save was successful
        """
        try:
            # Ensure Documents folder structure exists
            self.ensure_documents_folder_structure(domain_path)
            
            # Save to appropriate subdirectory
            doc_category = f"documents/{doc_type}"
            
            # Add timestamp to analysis data
            timestamped_data = {
                'timestamp': datetime.now().isoformat(),
                'document_type': doc_type,
                'analysis': analysis_data
            }
            
            return self.save_json_results(domain_path, doc_category, filename, timestamped_data)
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to save document analysis: {e}[/red]")
            return False
    
    def get_file_operation_stats(self) -> Dict[str, Any]:
        """
        Get statistics about file operations performed
        
        Returns:
            Dict containing file operation statistics
        """
        return {
            'files_created': self.stats['files_created'],
            'files_updated': self.stats['files_updated'], 
            'total_bytes_written': self.stats['bytes_written'],
            'errors_encountered': self.stats['errors'],
            'last_operation_time': self.stats['last_operation']
        }
    
    def reset_stats(self) -> None:
        """Reset file operation statistics"""
        self.stats = {
            'files_created': 0,
            'files_updated': 0,
            'bytes_written': 0,
            'errors': 0,
            'last_operation': None
        }
    
    def _update_stats(self, operation_type: str, bytes_written: int = 0, error: bool = False) -> None:
        """
        Update internal statistics
        
        Args:
            operation_type: Type of operation (create, update)
            bytes_written: Number of bytes written
            error: Whether an error occurred
        """
        self.stats['last_operation'] = datetime.now().isoformat()
        
        if error:
            self.stats['errors'] += 1
        else:
            if operation_type == 'create':
                self.stats['files_created'] += 1
            elif operation_type == 'update':
                self.stats['files_updated'] += 1
            
            self.stats['bytes_written'] += bytes_written
    
    def validate_file_path_consistency(self, domain_path: str, category: str, filename: str) -> Dict[str, Any]:
        """
        Validate that file paths are consistent and follow expected patterns
        
        Args:
            domain_path: Path to domain output directory
            category: Result category
            filename: Filename to validate
            
        Returns:
            Dict containing validation results
        """
        validation_result = {
            'valid': True,
            'issues': [],
            'recommendations': [],
            'full_path': None
        }
        
        try:
            # Check if category is in expected directory structure
            if category not in self.directory_structure:
                validation_result['valid'] = False
                validation_result['issues'].append(f"Category '{category}' not in expected directory structure")
                validation_result['recommendations'].append(f"Use one of: {list(self.directory_structure.keys())}")
            
            # Validate filename format
            if not filename or filename.startswith('.') or '/' in filename or '\\' in filename:
                validation_result['valid'] = False
                validation_result['issues'].append(f"Invalid filename format: '{filename}'")
                validation_result['recommendations'].append("Use simple filenames without path separators")
            
            # Check for potentially problematic characters
            problematic_chars = ['<', '>', ':', '"', '|', '?', '*']
            if any(char in filename for char in problematic_chars):
                validation_result['valid'] = False
                validation_result['issues'].append(f"Filename contains problematic characters: '{filename}'")
                validation_result['recommendations'].append("Remove special characters from filename")
            
            # Generate full path
            full_path = self.get_file_path(domain_path, category, filename)
            validation_result['full_path'] = full_path
            
            # Check path length (Windows has 260 character limit)
            if len(full_path) > 250:  # Leave some buffer
                validation_result['valid'] = False
                validation_result['issues'].append(f"Path too long ({len(full_path)} characters)")
                validation_result['recommendations'].append("Use shorter domain names or filenames")
            
            # Check if domain_path exists
            if not os.path.exists(domain_path):
                validation_result['issues'].append(f"Domain path does not exist: {domain_path}")
                validation_result['recommendations'].append("Create output structure first")
            
        except Exception as e:
            validation_result['valid'] = False
            validation_result['issues'].append(f"Validation error: {e}")
        
        return validation_result
    
    def get_consistent_filename(self, base_name: str, extension: str = 'txt', 
                              include_timestamp: bool = False) -> str:
        """
        Generate consistent filename following project conventions
        
        Args:
            base_name: Base name for the file
            extension: File extension (without dot)
            include_timestamp: Whether to include timestamp in filename
            
        Returns:
            str: Consistent filename
        """
        # Clean base name
        clean_name = re.sub(r'[^\w\-_.]', '_', base_name.lower())
        clean_name = re.sub(r'_+', '_', clean_name).strip('_')
        
        # Add timestamp if requested
        if include_timestamp:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            clean_name = f"{clean_name}_{timestamp}"
        
        # Add extension
        if not extension.startswith('.'):
            extension = f".{extension}"
        
        return f"{clean_name}{extension}"
    
    def create_master_output_directory(self, base_name: str = None) -> str:
        """
        Create master output directory for multi-domain scans
        
        Args:
            base_name: Base name for output directory
            
        Returns:
            str: Path to created master directory
        """
        if not base_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = f"hyperrecon_results_{timestamp}"
        
        try:
            os.makedirs(base_name, exist_ok=True)
            
            # Create master README
            readme_path = os.path.join(base_name, 'README.txt')
            if not os.path.exists(readme_path):
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write("# HyperRecon Pro Results\n")
                    f.write(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("This directory contains reconnaissance results for multiple domains.\n")
                    f.write("Each subdirectory represents results for a specific domain.\n")
            
            if self.console and self.verbose:
                self.console.print(f"📁 [green]Created master output directory: {base_name}[/green]")
            
            return base_name
            
        except Exception as e:
            if self.console:
                self.console.print(f"❌ [red]Failed to create master directory: {e}[/red]")
            return None