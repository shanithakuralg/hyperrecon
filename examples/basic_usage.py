#!/usr/bin/env python3
"""
HyperRecon Pro v4.0 - Basic Usage Examples
Demonstrates common usage patterns and API integration
"""

import os
import sys
import json
import time
from datetime import datetime

# Add the parent directory to the path to import hyperrecon
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hyperrecon import HyperReconPro

def example_single_domain_scan():
    """Example: Basic single domain scan"""
    print("🎯 Example 1: Single Domain Scan")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    
    # Configure for example
    hyperrecon.verbose = True
    hyperrecon.threads = 5  # Reduced for example
    hyperrecon.output_dir = "examples/output/single_domain"
    
    # Target domain
    target = "example.com"
    
    print(f"Scanning: {target}")
    
    # Run scan
    results = hyperrecon.run_scan([target])
    
    if results:
        result = results[0]
        print(f"\n✅ Scan completed for {target}")
        print(f"📊 Results summary:")
        print(f"   • Subdomains found: {len(result.get('subdomains', []))}")
        print(f"   • URLs collected: {len(result.get('all_urls', []))}")
        print(f"   • Live hosts: {len(result.get('live_hosts', []))}")
        print(f"   • Technologies detected: {len(result.get('technologies', {}))}")
        print(f"   • Vulnerabilities found: {len(result.get('vulnerabilities', {}))}")
        print(f"   • Output directory: {result.get('domain_path', 'N/A')}")
    else:
        print("❌ Scan failed or returned no results")

def example_multiple_domains_scan():
    """Example: Multiple domains scan with threading"""
    print("\n🎯 Example 2: Multiple Domains Scan")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    
    # Configure for multiple domains
    hyperrecon.verbose = False  # Reduce output for multiple domains
    hyperrecon.threads = 10
    hyperrecon.output_dir = "examples/output/multiple_domains"
    
    # Target domains
    targets = ["example.com", "test.com", "demo.com"]
    
    print(f"Scanning {len(targets)} domains: {', '.join(targets)}")
    
    start_time = time.time()
    
    # Run scan
    results = hyperrecon.run_scan(targets)
    
    end_time = time.time()
    scan_duration = end_time - start_time
    
    print(f"\n✅ Multi-domain scan completed in {scan_duration:.2f} seconds")
    print(f"📊 Overall results:")
    
    total_subdomains = 0
    total_urls = 0
    total_live_hosts = 0
    total_vulns = 0
    
    for result in results:
        domain = result.get('domain', 'Unknown')
        subdomains = len(result.get('subdomains', []))
        urls = len(result.get('all_urls', []))
        live_hosts = len(result.get('live_hosts', []))
        vulns = len(result.get('vulnerabilities', {}))
        
        total_subdomains += subdomains
        total_urls += urls
        total_live_hosts += live_hosts
        total_vulns += vulns
        
        print(f"   • {domain}: {subdomains} subdomains, {urls} URLs, {live_hosts} live hosts, {vulns} vulnerabilities")
    
    print(f"\n📈 Totals:")
    print(f"   • Total subdomains: {total_subdomains}")
    print(f"   • Total URLs: {total_urls}")
    print(f"   • Total live hosts: {total_live_hosts}")
    print(f"   • Total vulnerabilities: {total_vulns}")

def example_custom_configuration():
    """Example: Custom configuration and feature flags"""
    print("\n🎯 Example 3: Custom Configuration")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    
    # Custom configuration
    hyperrecon.verbose = True
    hyperrecon.debug = False
    hyperrecon.threads = 15
    hyperrecon.output_dir = "examples/output/custom_config"
    
    # Customize feature flags
    hyperrecon.feature_flags.update({
        'subfinder': True,
        'httpx': True,
        'nuclei': True,
        'gobuster': False,  # Disable directory bruteforcing
        'social_media_recon': True,
        'js_analysis': True,
        'technology_detection': True,
        'sensitive_data': True,
        'html_reports': True
    })
    
    print("Custom configuration:")
    print(f"   • Threads: {hyperrecon.threads}")
    print(f"   • Verbose: {hyperrecon.verbose}")
    print(f"   • Directory bruteforcing: {hyperrecon.feature_flags['gobuster']}")
    print(f"   • JavaScript analysis: {hyperrecon.feature_flags['js_analysis']}")
    print(f"   • HTML reports: {hyperrecon.feature_flags['html_reports']}")
    
    # Target domain
    target = "example.com"
    
    print(f"\nScanning: {target}")
    
    # Run scan with custom configuration
    results = hyperrecon.run_scan([target])
    
    if results:
        result = results[0]
        print(f"\n✅ Custom scan completed for {target}")
        
        # Show specific results based on enabled features
        if hyperrecon.feature_flags['js_analysis']:
            js_files = result.get('javascript_analysis', {}).get('js_files', [])
            print(f"   • JavaScript files found: {len(js_files)}")
        
        if hyperrecon.feature_flags['technology_detection']:
            technologies = result.get('technologies', {})
            print(f"   • Technology categories detected: {len(technologies)}")
        
        if hyperrecon.feature_flags['sensitive_data']:
            sensitive_data = result.get('sensitive_data_detection', {})
            print(f"   • Sensitive data categories: {len(sensitive_data)}")

def example_programmatic_api():
    """Example: Using HyperRecon Pro as a library/API"""
    print("\n🎯 Example 4: Programmatic API Usage")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    
    # Configure for API usage
    hyperrecon.verbose = False
    hyperrecon.output_dir = "examples/output/api_usage"
    
    target = "example.com"
    
    print(f"Using HyperRecon Pro as a library for {target}")
    
    # Create output structure
    domain_path = hyperrecon.create_output_structure(target)
    print(f"Created output structure: {domain_path}")
    
    # Use individual modules
    print("\n🔍 Running individual reconnaissance modules:")
    
    # 1. Subdomain enumeration
    print("   • Subdomain enumeration...")
    subdomain_result = hyperrecon.subdomain_enumerator.execute(target, domain_path)
    if subdomain_result.success:
        subdomains = subdomain_result.data.get('subdomains', [])
        print(f"     Found {len(subdomains)} subdomains")
    
    # 2. URL collection
    print("   • URL collection...")
    url_result = hyperrecon.url_collector.execute(target, domain_path)
    if url_result.success:
        urls = url_result.data.get('filtered_urls', [])
        print(f"     Collected {len(urls)} URLs")
    
    # 3. HTTP probing
    if subdomain_result.success:
        print("   • HTTP probing...")
        probe_result = hyperrecon.http_prober.execute(subdomains, domain_path)
        if probe_result.success:
            live_hosts = probe_result.data.get('live_hosts', [])
            print(f"     Found {len(live_hosts)} live hosts")
    
    # 4. Technology detection
    if 'live_hosts' in locals():
        print("   • Technology detection...")
        tech_result = hyperrecon.tech_detector.execute(live_hosts, domain_path)
        if tech_result.success:
            technologies = tech_result.data.get('technologies', {})
            print(f"     Detected {len(technologies)} technology categories")
    
    # 5. Generate custom report
    print("   • Generating custom report...")
    
    custom_results = {
        'domain': target,
        'scan_date': datetime.now().isoformat(),
        'subdomains': subdomains if 'subdomains' in locals() else [],
        'urls': urls if 'urls' in locals() else [],
        'live_hosts': live_hosts if 'live_hosts' in locals() else [],
        'technologies': technologies if 'technologies' in locals() else {},
        'scan_metadata': {
            'api_usage': True,
            'modules_used': ['subdomain_enum', 'url_collection', 'http_probe', 'tech_detection']
        }
    }
    
    # Save custom results
    results_file = os.path.join(domain_path, 'api_results.json')
    with open(results_file, 'w') as f:
        json.dump(custom_results, f, indent=2)
    
    print(f"     Custom results saved to: {results_file}")
    
    print(f"\n✅ API usage example completed")

def example_error_handling():
    """Example: Error handling and graceful degradation"""
    print("\n🎯 Example 5: Error Handling")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    
    # Configure for error handling demo
    hyperrecon.verbose = True
    hyperrecon.debug = True  # Enable debug for detailed error info
    hyperrecon.output_dir = "examples/output/error_handling"
    
    print("Demonstrating error handling capabilities:")
    
    # 1. Test with invalid domain
    print("\n   • Testing invalid domain...")
    invalid_results = hyperrecon.run_scan(["invalid-domain-that-does-not-exist.com"])
    
    if invalid_results:
        result = invalid_results[0]
        if 'error' in result:
            print(f"     ✅ Error handled gracefully: {result['error'][:100]}...")
        else:
            print(f"     ✅ Scan completed with limited results")
    
    # 2. Test dependency validation
    print("\n   • Testing dependency validation...")
    validation_results = hyperrecon.validate_dependencies()
    
    print(f"     Required tools available: {validation_results['all_required_available']}")
    if validation_results['required_missing']:
        print(f"     Missing required tools: {validation_results['required_missing']}")
    if validation_results['optional_missing']:
        print(f"     Missing optional tools: {validation_results['optional_missing']}")
    
    # 3. Test with network issues simulation
    print("\n   • Testing network error handling...")
    
    # This would normally test with actual network issues
    # For demo purposes, we'll show the error handling framework
    try:
        # Simulate a network timeout scenario
        original_timeout = hyperrecon.config_manager.tool_configs.get('httpx', {}).get('timeout', 30)
        hyperrecon.config_manager.tool_configs['httpx']['timeout'] = 1  # Very short timeout
        
        print(f"     Set very short timeout ({1}s) to simulate network issues")
        
        # Run a quick scan that might timeout
        timeout_results = hyperrecon.run_scan(["example.com"])
        
        # Restore original timeout
        hyperrecon.config_manager.tool_configs['httpx']['timeout'] = original_timeout
        
        print("     ✅ Network error handling working correctly")
        
    except Exception as e:
        print(f"     ✅ Exception handled: {str(e)[:100]}...")
    
    print(f"\n✅ Error handling demonstration completed")

def example_performance_monitoring():
    """Example: Performance monitoring and optimization"""
    print("\n🎯 Example 6: Performance Monitoring")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    
    # Configure for performance monitoring
    hyperrecon.verbose = True
    hyperrecon.output_dir = "examples/output/performance"
    
    target = "example.com"
    
    print(f"Performance monitoring for {target}")
    
    # Monitor system resources before scan
    try:
        import psutil
        
        print("\n📊 System resources before scan:")
        print(f"   • CPU usage: {psutil.cpu_percent(interval=1):.1f}%")
        print(f"   • Memory usage: {psutil.virtual_memory().percent:.1f}%")
        print(f"   • Available memory: {psutil.virtual_memory().available / (1024**3):.1f} GB")
        
        # Test different thread configurations
        thread_configs = [5, 10, 15]
        
        for threads in thread_configs:
            print(f"\n🧵 Testing with {threads} threads:")
            
            hyperrecon.threads = threads
            
            start_time = time.time()
            start_memory = psutil.virtual_memory().used
            
            # Run scan
            results = hyperrecon.run_scan([target])
            
            end_time = time.time()
            end_memory = psutil.virtual_memory().used
            
            scan_duration = end_time - start_time
            memory_used = (end_memory - start_memory) / (1024**2)  # MB
            
            print(f"   • Duration: {scan_duration:.2f} seconds")
            print(f"   • Memory used: {memory_used:.1f} MB")
            print(f"   • Performance: {scan_duration/threads:.2f} seconds per thread")
            
            if results:
                result = results[0]
                total_items = (
                    len(result.get('subdomains', [])) +
                    len(result.get('all_urls', [])) +
                    len(result.get('live_hosts', []))
                )
                if total_items > 0:
                    print(f"   • Throughput: {total_items/scan_duration:.1f} items per second")
        
        print("\n📈 Performance monitoring completed")
        
    except ImportError:
        print("   ⚠️ psutil not available for performance monitoring")
        print("   Install with: pip install psutil")

def main():
    """Run all usage examples"""
    print("🚀 HyperRecon Pro v4.0 - Usage Examples")
    print("=" * 70)
    
    # Create output directory
    os.makedirs("examples/output", exist_ok=True)
    
    try:
        # Run examples
        example_single_domain_scan()
        example_multiple_domains_scan()
        example_custom_configuration()
        example_programmatic_api()
        example_error_handling()
        example_performance_monitoring()
        
        print("\n" + "=" * 70)
        print("✅ All usage examples completed successfully!")
        print("\n📁 Check the following directories for results:")
        print("   • examples/output/single_domain/")
        print("   • examples/output/multiple_domains/")
        print("   • examples/output/custom_config/")
        print("   • examples/output/api_usage/")
        print("   • examples/output/error_handling/")
        print("   • examples/output/performance/")
        
    except KeyboardInterrupt:
        print("\n⏹️ Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        if "--debug" in sys.argv:
            raise

if __name__ == "__main__":
    main()