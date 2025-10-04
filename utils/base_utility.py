"""
Base utility classes and shared interfaces for consistent module design
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
from .error_handler import ReconLogger, ErrorHandler, ErrorContext, ErrorCategory, ErrorSeverity
from .logging_config import LoggingConfig, VerbosityLevel


@dataclass
class UtilityResult:
    """Standard result format for all utility operations"""
    success: bool
    data: Any
    errors: List[str]
    warnings: List[str]
    execution_time: float
    items_processed: int
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseUtility(ABC):
    """
    Base class for all HyperRecon utilities providing consistent interface
    and shared functionality across all modules
    """
    
    def __init__(self, hyperrecon_instance):
        """
        Initialize base utility with reference to main HyperRecon instance
        
        Args:
            hyperrecon_instance: Main HyperRecon Pro instance for shared resources
        """
        self.hyperrecon = hyperrecon_instance
        self.name = self.__class__.__name__
        self.version = "4.0"
        self.start_time = None
        self.errors = []
        self.warnings = []
        
        # Get shared components from hyperrecon instance
        self.console = getattr(hyperrecon_instance, 'console', None)
        self.verbose = getattr(hyperrecon_instance, 'verbose', False)
        self.debug = getattr(hyperrecon_instance, 'debug', False)
        
        # Initialize enhanced error handling and logging
        output_dir = getattr(hyperrecon_instance, 'output_dir', None)
        log_level = "DEBUG" if self.debug else ("INFO" if self.verbose else "WARNING")
        
        self.logger = ReconLogger(
            name=f"HyperRecon.{self.name}",
            log_level=log_level,
            output_dir=output_dir,
            console_output=self.verbose
        )
        
        self.error_handler = ErrorHandler(self.logger)
        
        # Error context for this utility
        self.error_context = ErrorContext(
            utility_name=self.name,
            operation="initialization"
        )
        
    @abstractmethod
    def execute(self, targets: Any, domain_path: str) -> UtilityResult:
        """
        Execute the main functionality of the utility
        
        Args:
            targets: Input targets (format varies by utility)
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult: Standardized result object
        """
        pass
    
    @abstractmethod
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate that all required dependencies are available
        
        Returns:
            Tuple[bool, List[str]]: (success, missing_dependencies)
        """
        pass
    
    def get_results_summary(self) -> Dict[str, Any]:
        """
        Get summary of utility execution results
        
        Returns:
            Dict containing execution summary
        """
        return {
            'utility_name': self.name,
            'version': self.version,
            'execution_time': getattr(self, 'execution_time', 0),
            'errors_count': len(self.errors),
            'warnings_count': len(self.warnings),
            'timestamp': datetime.now().isoformat()
        }
    
    def start_execution(self):
        """Mark the start of utility execution"""
        self.start_time = time.time()
        self.errors = []
        self.warnings = []
        
        if self.console and self.verbose:
            self.console.print(f"🚀 [cyan]Starting {self.name}[/cyan]")
    
    def end_execution(self) -> float:
        """
        Mark the end of utility execution and return duration
        
        Returns:
            float: Execution time in seconds
        """
        if self.start_time is None:
            return 0.0
            
        execution_time = time.time() - self.start_time
        
        if self.console and self.verbose:
            self.console.print(f"✅ [green]{self.name} completed in {execution_time:.2f}s[/green]")
            
        return execution_time
    
    def log_error(self, error: str, exception: Exception = None, 
                  category: ErrorCategory = ErrorCategory.UNKNOWN_ERROR):
        """
        Log an error with comprehensive error handling
        
        Args:
            error: Error message
            exception: Optional exception object
            category: Error category for proper handling
        """
        error_msg = f"[{self.name}] {error}"
        self.errors.append(error_msg)
        
        # Update error context
        self.error_context.operation = getattr(self, '_current_operation', 'unknown')
        
        # Use enhanced error logging
        self.logger.error(error, context=self.error_context, exception=exception)
        
        # Handle error with recovery strategies if exception provided
        if exception:
            try:
                result = self.error_handler.handle_error(exception, category, self.error_context)
                
                # Display suggestions to user if available
                if result.get('suggestions') and self.console:
                    self.console.print(f"💡 [yellow]Suggestions:[/yellow]")
                    for suggestion in result['suggestions']:
                        self.console.print(f"   • {suggestion}")
                
                # Store recovery information for later use
                self._last_error_result = result
                
            except Exception as handler_error:
                self.logger.critical(f"Error handler failed: {handler_error}", 
                                   context=self.error_context, exception=handler_error)
        
        # Fallback to console output if available
        if self.console:
            self.console.print(f"❌ [red]{error_msg}[/red]")
    
    def log_warning(self, warning: str):
        """
        Log a warning with enhanced formatting and context
        
        Args:
            warning: Warning message
        """
        warning_msg = f"[{self.name}] {warning}"
        self.warnings.append(warning_msg)
        
        # Update error context
        self.error_context.operation = getattr(self, '_current_operation', 'unknown')
        
        # Use enhanced warning logging
        self.logger.warning(warning, context=self.error_context)
        
        # Fallback to console output if available
        if self.console:
            self.console.print(f"⚠️ [yellow]{warning_msg}[/yellow]")
    
    def log_info(self, message: str):
        """
        Log an info message with enhanced formatting and context
        
        Args:
            message: Info message
        """
        # Update error context
        self.error_context.operation = getattr(self, '_current_operation', 'unknown')
        
        # Use enhanced info logging
        self.logger.info(message, context=self.error_context)
        
        # Fallback to console output if available and verbose
        if self.console and self.verbose:
            self.console.print(f"ℹ️ [blue][{self.name}] {message}[/blue]")
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """
        Check if a required tool is installed
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            bool: True if tool is available
        """
        if hasattr(self.hyperrecon, 'check_tool_installed'):
            return self.hyperrecon.check_tool_installed(tool_name)
        
        # Fallback implementation
        try:
            import subprocess
            result = subprocess.run(['which', tool_name], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def run_command(self, cmd: List[str], timeout: int = 120, 
                   description: str = "", input_data: str = None) -> str:
        """
        Execute a command with consistent error handling
        
        Args:
            cmd: Command and arguments as list
            timeout: Command timeout in seconds
            description: Description for logging
            input_data: Optional stdin data
            
        Returns:
            str: Command output or empty string on failure
        """
        if hasattr(self.hyperrecon, 'run_command'):
            return self.hyperrecon.run_command(cmd, timeout, description, input_data)
        
        # Fallback implementation
        try:
            import subprocess
            
            if description and self.verbose:
                self.log_info(f"Running: {description}")
            
            if input_data:
                result = subprocess.run(cmd, input=input_data, capture_output=True, 
                                      text=True, timeout=timeout)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                if self.verbose:
                    self.log_warning(f"Command failed: {result.stderr[:100]}")
                return ""
                
        except subprocess.TimeoutExpired:
            self.log_warning(f"Command timeout after {timeout}s")
            return ""
        except Exception as e:
            self.log_error(f"Command execution failed", e)
            return ""
    
    def save_results(self, domain_path: str, category: str, filename: str, 
                    data: Any, append: bool = False) -> bool:
        """
        Save results using the file manager
        
        Args:
            domain_path: Domain output directory path
            category: Result category (subdirectory)
            filename: Output filename
            data: Data to save
            append: Whether to append to existing file
            
        Returns:
            bool: True if save was successful
        """
        if hasattr(self.hyperrecon, 'save_results_realtime'):
            try:
                self.hyperrecon.save_results_realtime(domain_path, category, filename, data, append)
                return True
            except Exception as e:
                self.log_error(f"Failed to save results to {filename}", e)
                return False
        
        # Fallback implementation
        try:
            category_path = os.path.join(domain_path, category)
            os.makedirs(category_path, exist_ok=True)
            
            file_path = os.path.join(category_path, filename)
            mode = 'a' if append else 'w'
            
            with open(file_path, mode, encoding='utf-8') as f:
                if isinstance(data, list):
                    for item in data:
                        f.write(f"{item}\n")
                elif isinstance(data, str):
                    f.write(data)
                elif isinstance(data, dict):
                    import json
                    f.write(json.dumps(data, indent=2))
            
            return True
            
        except Exception as e:
            self.log_error(f"Failed to save results to {filename}", e)
            return False
    
    def create_result(self, success: bool, data: Any = None, 
                     items_processed: int = 0) -> UtilityResult:
        """
        Create a standardized result object with enhanced error information
        
        Args:
            success: Whether the operation was successful
            data: Result data
            items_processed: Number of items processed
            
        Returns:
            UtilityResult: Standardized result object
        """
        execution_time = self.end_execution()
        
        # Include error handling statistics
        error_stats = self.logger.get_stats()
        
        return UtilityResult(
            success=success,
            data=data or {},
            errors=self.errors.copy(),
            warnings=self.warnings.copy(),
            execution_time=execution_time,
            items_processed=items_processed,
            metadata={
                'utility_name': self.name,
                'version': self.version,
                'timestamp': datetime.now().isoformat(),
                'error_stats': error_stats,
                'graceful_degradation_used': getattr(self, '_degradation_used', False),
                'fallback_methods_used': getattr(self, '_fallback_methods', [])
            }
        )
    
    def set_operation(self, operation: str):
        """
        Set current operation for error context tracking
        
        Args:
            operation: Name of the current operation
        """
        self._current_operation = operation
        self.error_context.operation = operation
    
    def handle_tool_missing(self, tool_name: str, required: bool = True) -> bool:
        """
        Handle missing tool with graceful degradation
        
        Args:
            tool_name: Name of the missing tool
            required: Whether the tool is required for operation
            
        Returns:
            bool: True if operation can continue, False if critical failure
        """
        self.log_warning(f"Tool '{tool_name}' is not available")
        
        if not required:
            self.log_info(f"Continuing without {tool_name} (optional tool)")
            self._mark_degradation_used()
            return True
        
        # Get installation instructions
        instructions = self._get_tool_installation_instructions(tool_name)
        
        if self.console:
            self.console.print(f"🔧 [yellow]Installation instructions for {tool_name}:[/yellow]")
            self.console.print(f"   {instructions}")
            self.console.print(f"💡 [blue]Tip: You can continue without {tool_name} but functionality will be limited[/blue]")
        
        # Check if we can continue with degraded functionality
        if self._can_continue_without_tool(tool_name):
            self.log_info(f"Continuing with degraded functionality (missing {tool_name})")
            self._mark_degradation_used()
            return True
        
        self.log_error(f"Cannot continue without required tool: {tool_name}", 
                      category=ErrorCategory.TOOL_MISSING)
        return False
    
    def handle_network_error(self, error: Exception, operation: str, retry_count: int = 0) -> bool:
        """
        Handle network errors with retry logic
        
        Args:
            error: Network error exception
            operation: Description of the operation that failed
            retry_count: Current retry attempt
            
        Returns:
            bool: True if should retry, False if should give up
        """
        max_retries = 3
        
        self.log_warning(f"Network error during {operation}: {str(error)}")
        
        if retry_count < max_retries:
            wait_time = 2 ** retry_count  # Exponential backoff
            self.log_info(f"Retrying in {wait_time} seconds... (attempt {retry_count + 1}/{max_retries})")
            
            import time
            time.sleep(wait_time)
            return True
        
        self.log_error(f"Network operation failed after {max_retries} retries: {operation}", 
                      error, ErrorCategory.NETWORK_ERROR)
        
        # Check if we can use cached data or alternative methods
        if self._has_fallback_for_network_operation(operation):
            self.log_info("Using fallback method for network operation")
            self._mark_fallback_used(f"network_fallback_{operation}")
            return False  # Don't retry, use fallback
        
        return False
    
    def handle_file_error(self, error: Exception, file_path: str, operation: str) -> Optional[str]:
        """
        Handle file operation errors with alternative paths
        
        Args:
            error: File error exception
            file_path: Original file path that failed
            operation: Description of the file operation
            
        Returns:
            Optional[str]: Alternative file path if available, None if no alternatives
        """
        self.log_warning(f"File {operation} failed for {file_path}: {str(error)}")
        
        # Try alternative paths
        alternative_paths = self._get_alternative_file_paths(file_path)
        
        for alt_path in alternative_paths:
            try:
                # Test if alternative path is accessible
                if operation == "write":
                    os.makedirs(os.path.dirname(alt_path), exist_ok=True)
                    # Test write access
                    test_file = alt_path + ".test"
                    with open(test_file, 'w') as f:
                        f.write("test")
                    os.remove(test_file)
                elif operation == "read":
                    # Test read access
                    if os.path.exists(alt_path):
                        with open(alt_path, 'r') as f:
                            f.read(1)
                
                self.log_info(f"Using alternative path: {alt_path}")
                self._mark_fallback_used(f"file_path_{operation}")
                return alt_path
                
            except Exception as alt_error:
                self.log_warning(f"Alternative path {alt_path} also failed: {str(alt_error)}")
                continue
        
        self.log_error(f"No alternative paths available for {operation} operation", 
                      error, ErrorCategory.FILE_ERROR)
        return None
    
    def _mark_degradation_used(self):
        """Mark that graceful degradation was used"""
        self._degradation_used = True
        if not hasattr(self, '_fallback_methods'):
            self._fallback_methods = []
    
    def _mark_fallback_used(self, fallback_method: str):
        """Mark that a fallback method was used"""
        if not hasattr(self, '_fallback_methods'):
            self._fallback_methods = []
        self._fallback_methods.append(fallback_method)
    
    def _get_tool_installation_instructions(self, tool_name: str) -> str:
        """Get installation instructions for a tool"""
        instructions = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'gobuster': 'go install github.com/OJ/gobuster/v3@latest',
            'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
            'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
            'unfurl': 'go install github.com/tomnomnom/unfurl@latest',
            'gf': 'go install github.com/tomnomnom/gf@latest',
            'uro': 'pip3 install uro',
            'whatweb': 'apt-get install whatweb',
            'paramspider': 'pip3 install paramspider'
        }
        
        return instructions.get(tool_name, f'Please install {tool_name} manually')
    
    def _can_continue_without_tool(self, tool_name: str) -> bool:
        """Check if operation can continue without a specific tool"""
        # Tools that have alternatives or are optional
        optional_tools = ['assetfinder', 'gau', 'waybackurls', 'whatweb', 'gobuster', 'uro']
        return tool_name in optional_tools
    
    def _has_fallback_for_network_operation(self, operation: str) -> bool:
        """Check if there's a fallback for a network operation"""
        # Operations that might have cached data or alternative methods
        fallback_operations = ['subdomain_enum', 'url_collection', 'tech_detection']
        return any(op in operation.lower() for op in fallback_operations)
    
    def _get_alternative_file_paths(self, original_path: str) -> List[str]:
        """Get alternative file paths for failed operations"""
        alternatives = []
        
        try:
            from pathlib import Path
            original = Path(original_path)
            
            # Try user's home directory
            home_alt = Path.home() / "hyperrecon_output" / original.name
            alternatives.append(str(home_alt))
            
            # Try current directory
            current_alt = Path.cwd() / "hyperrecon_output" / original.name
            alternatives.append(str(current_alt))
            
            # Try temp directory
            import tempfile
            temp_alt = Path(tempfile.gettempdir()) / "hyperrecon_output" / original.name
            alternatives.append(str(temp_alt))
            
        except Exception:
            pass
        
        return alternatives


class ToolValidator:
    """Utility class for validating tool dependencies"""
    
    @staticmethod
    def check_tools(tool_list: List[str]) -> Tuple[bool, List[str]]:
        """
        Check multiple tools for availability
        
        Args:
            tool_list: List of tool names to check
            
        Returns:
            Tuple[bool, List[str]]: (all_available, missing_tools)
        """
        missing_tools = []
        
        for tool in tool_list:
            try:
                import subprocess
                result = subprocess.run(['which', tool], capture_output=True, timeout=5)
                if result.returncode != 0:
                    missing_tools.append(tool)
            except:
                missing_tools.append(tool)
        
        return len(missing_tools) == 0, missing_tools
    
    @staticmethod
    def get_installation_instructions(tool_name: str) -> str:
        """
        Get installation instructions for common tools
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            str: Installation instructions
        """
        instructions = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'gobuster': 'go install github.com/OJ/gobuster/v3@latest',
            'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
            'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
            'unfurl': 'go install github.com/tomnomnom/unfurl@latest',
            'gf': 'go install github.com/tomnomnom/gf@latest',
            'uro': 'pip3 install uro',
            'whatweb': 'apt-get install whatweb'
        }
        
        return instructions.get(tool_name, f'Please install {tool_name} manually')