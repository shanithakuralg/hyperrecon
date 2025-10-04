#!/usr/bin/env python3
"""
Example of how to integrate the enhanced FileManager into hyperrecon.py
This shows the proper way to replace duplicate file management code
"""

import os
import sys
from datetime import datetime

# Add utils to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))

from utils.file_manager import FileManager


class HyperReconProExample:
    """Example showing proper FileManager integration"""
    
    def __init__(self):
        self.console = None
        self.verbose = True
        self.output_dir = None
        
        # Initialize FileManager
        self.file_manager = FileManager(self)
    
    def setup_output_structure(self, domain: str) -> str:
        """
        BEFORE: Duplicate code in hyperrecon.py
        AFTER: Use FileManager utility
        """
        # Create master output directory if needed
        if not self.output_dir:
            self.output_dir = self.file_manager.create_master_output_directory()
        
        # Create domain-specific structure
        domain_path = self.file_manager.create_output_structure(domain, self.output_dir)
        
        # Ensure Documents folder is properly structured
        self.file_manager.ensure_documents_folder_structure(domain_path)
        
        return domain_path
    
    def save_scan_results(self, domain_path: str, category: str, filename: str, data: any):
        """
        BEFORE: Manual file operations with inconsistent error handling
        AFTER: Use FileManager with proper validation and statistics
        """
        # Validate file path consistency
        validation = self.file_manager.validate_file_path_consistency(domain_path, category, filename)
        
        if not validation['valid']:
            print(f"❌ File path validation failed: {validation['issues']}")
            return False
        
        # Save with real-time functionality and timestamps
        success = self.file_manager.save_timestamped_results(
            domain_path, category, filename, data, include_metadata=True
        )
        
        return success
    
    def save_filtered_urls(self, domain_path: str, original_urls: list, filtered_urls: list):
        """
        BEFORE: Manual URL saving without filtering statistics
        AFTER: Use FileManager with filtering metadata
        """
        # Generate consistent filename
        filename = self.file_manager.get_consistent_filename('filtered_urls', 'txt', include_timestamp=True)
        
        # Save with filtering statistics
        success = self.file_manager.save_filtered_urls(
            domain_path, 'url_filtering', filename, original_urls, filtered_urls, 'URO'
        )
        
        return success
    
    def save_document_analysis(self, domain_path: str, doc_url: str, doc_type: str, analysis_data: dict):
        """
        BEFORE: No specific document handling
        AFTER: Proper document organization in Documents folder
        """
        # Generate filename from URL
        filename = self.file_manager.get_consistent_filename(f'analysis_{doc_url.split("/")[-1]}', 'json')
        
        # Save to appropriate document subfolder
        success = self.file_manager.save_document_analysis_results(
            domain_path, doc_type, filename, analysis_data
        )
        
        return success
    
    def get_scan_summary(self, domain_path: str):
        """
        BEFORE: No comprehensive result tracking
        AFTER: Detailed statistics and summary
        """
        # Get file operation statistics
        file_stats = self.file_manager.get_file_operation_stats()
        
        # Get results summary
        results_summary = self.file_manager.get_results_summary(domain_path)
        
        return {
            'file_operations': file_stats,
            'results': results_summary
        }


def demonstrate_integration():
    """Demonstrate the enhanced FileManager integration"""
    print("🚀 FileManager Integration Example")
    
    # Initialize HyperRecon with FileManager
    hyperrecon = HyperReconProExample()
    
    # Setup output structure for a domain
    print("\n📁 Setting up output structure...")
    domain = "example.com"
    domain_path = hyperrecon.setup_output_structure(domain)
    print(f"✅ Created structure at: {domain_path}")
    
    # Save some example scan results
    print("\n💾 Saving scan results...")
    
    # Save subdomains
    subdomains = ['sub1.example.com', 'sub2.example.com', 'api.example.com']
    hyperrecon.save_scan_results(domain_path, 'subdomains', 'discovered_subdomains.txt', subdomains)
    
    # Save filtered URLs
    original_urls = [
        'http://example.com/page1',
        'http://example.com/page2', 
        'http://example.com/page1',  # duplicate
        'http://example.com/api/v1'
    ]
    filtered_urls = ['http://example.com/page1', 'http://example.com/page2', 'http://example.com/api/v1']
    hyperrecon.save_filtered_urls(domain_path, original_urls, filtered_urls)
    
    # Save document analysis
    doc_analysis = {
        'file_url': 'http://example.com/document.pdf',
        'metadata': {'title': 'Example Document', 'author': 'Test Author'},
        'extracted_text': 'Sample content from PDF'
    }
    hyperrecon.save_document_analysis(domain_path, 'http://example.com/document.pdf', 'pdf', doc_analysis)
    
    # Get comprehensive summary
    print("\n📊 Generating scan summary...")
    summary = hyperrecon.get_scan_summary(domain_path)
    
    print(f"Files created: {summary['file_operations']['files_created']}")
    print(f"Total bytes written: {summary['file_operations']['total_bytes_written']}")
    print(f"Categories with results: {len([k for k, v in summary['results']['categories'].items() if v['file_count'] > 0])}")
    
    print("\n✅ Integration example completed successfully!")
    print("\n📝 Key Benefits of Enhanced FileManager:")
    print("  • Centralized file operations with consistent error handling")
    print("  • Automatic timestamp and metadata inclusion")
    print("  • File path validation and consistency checking")
    print("  • Comprehensive statistics and result tracking")
    print("  • Proper Documents folder organization")
    print("  • Filtered URL saving with statistics")
    print("  • Real-time saving to prevent data loss")


if __name__ == "__main__":
    demonstrate_integration()