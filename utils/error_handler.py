"""
Comprehensive error handling and logging system for HyperRecon Pro
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import sys
import logging
import traceback
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union
from pathlib import Path
from dataclasses import dataclass


class ErrorSeverity(Enum):
    """Error severity levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ErrorCategory(Enum):
    """Error categories for better classification"""
    TOOL_MISSING = "TOOL_MISSING"
    NETWORK_ERROR = "NETWORK_ERROR"
    FILE_ERROR = "FILE_ERROR"
    PERMISSION_ERROR = "PERMISSION_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    DEPENDENCY_ERROR = "DEPENDENCY_ERROR"
    PARSING_ERROR = "PARSING_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class ErrorContext:
    """Context information for errors"""
    utility_name: str
    operation: str
    target: Optional[str] = None
    file_path: Optional[str] = None
    command: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None


class ReconLogger:
    """
    Centralized logging system with multiple verbosity levels and output formats
    """
    
    def __init__(self, name: str = "HyperRecon", log_level: str = "INFO", 
                 output_dir: Optional[str] = None, console_output: bool = True):
        """
        Initialize the logging system
        
        Args:
            name: Logger name
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            output_dir: Directory for log files
            console_output: Whether to output to console
        """
        self.name = name
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.output_dir = output_dir
        self.console_output = console_output
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_handlers()
        
        # Error statistics
        self.error_stats = {
            'debug': 0,
            'info': 0,
            'warning': 0,
            'error': 0,
            'critical': 0,
            'total': 0
        }
        
        # Error history for analysis
        self.error_history = []
    
    def _setup_handlers(self):
        """Setup logging handlers for file and console output"""
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler
        if self.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # File handler
        if self.output_dir:
            try:
                os.makedirs(self.output_dir, exist_ok=True)
                
                # Main log file
                log_file = os.path.join(self.output_dir, f"{self.name.lower()}.log")
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)  # Always log everything to file
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
                
                # Error-only log file
                error_log_file = os.path.join(self.output_dir, f"{self.name.lower()}_errors.log")
                error_handler = logging.FileHandler(error_log_file, encoding='utf-8')
                error_handler.setLevel(logging.ERROR)
                error_handler.setFormatter(formatter)
                self.logger.addHandler(error_handler)
                
            except Exception as e:
                print(f"Warning: Could not setup file logging: {e}")
    
    def debug(self, message: str, context: Optional[ErrorContext] = None):
        """Log debug message"""
        self._log(logging.DEBUG, message, context)
        self.error_stats['debug'] += 1
    
    def info(self, message: str, context: Optional[ErrorContext] = None):
        """Log info message"""
        self._log(logging.INFO, message, context)
        self.error_stats['info'] += 1
    
    def warning(self, message: str, context: Optional[ErrorContext] = None):
        """Log warning message"""
        self._log(logging.WARNING, message, context)
        self.error_stats['warning'] += 1
    
    def error(self, message: str, context: Optional[ErrorContext] = None, 
              exception: Optional[Exception] = None):
        """Log error message"""
        if exception:
            message += f" - Exception: {str(exception)}"
            if self.log_level <= logging.DEBUG:
                message += f"\nTraceback: {traceback.format_exc()}"
        
        self._log(logging.ERROR, message, context)
        self.error_stats['error'] += 1
        
        # Add to error history for analysis
        self.error_history.append({
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'context': context,
            'exception': str(exception) if exception else None
        })
    
    def critical(self, message: str, context: Optional[ErrorContext] = None, 
                 exception: Optional[Exception] = None):
        """Log critical message"""
        if exception:
            message += f" - Exception: {str(exception)}"
            message += f"\nTraceback: {traceback.format_exc()}"
        
        self._log(logging.CRITICAL, message, context)
        self.error_stats['critical'] += 1
        
        # Add to error history
        self.error_history.append({
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'context': context,
            'exception': str(exception) if exception else None,
            'severity': 'CRITICAL'
        })
    
    def _log(self, level: int, message: str, context: Optional[ErrorContext] = None):
        """Internal logging method with context"""
        if context:
            context_str = f"[{context.utility_name}:{context.operation}]"
            if context.target:
                context_str += f"[{context.target}]"
            message = f"{context_str} {message}"
        
        self.logger.log(level, message)
        self.error_stats['total'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        return {
            'error_counts': self.error_stats.copy(),
            'recent_errors': self.error_history[-10:] if self.error_history else [],
            'total_errors': len(self.error_history)
        }
    
    def save_error_report(self, output_path: str) -> bool:
        """Save detailed error report to file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"# HyperRecon Error Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Error Statistics\n")
                for level, count in self.error_stats.items():
                    f.write(f"- {level.upper()}: {count}\n")
                f.write("\n")
                
                f.write("## Error History\n")
                for i, error in enumerate(self.error_history, 1):
                    f.write(f"### Error {i}\n")
                    f.write(f"- Timestamp: {error['timestamp']}\n")
                    f.write(f"- Message: {error['message']}\n")
                    if error.get('context'):
                        f.write(f"- Context: {error['context']}\n")
                    if error.get('exception'):
                        f.write(f"- Exception: {error['exception']}\n")
                    f.write("\n")
            
            return True
        except Exception as e:
            self.error(f"Failed to save error report: {e}")
            return False


class ErrorHandler:
    """
    Comprehensive error handling system with graceful degradation
    """
    
    def __init__(self, logger: Optional[ReconLogger] = None):
        """
        Initialize error handler
        
        Args:
            logger: ReconLogger instance for logging
        """
        self.logger = logger or ReconLogger()
        
        # Error recovery strategies
        self.recovery_strategies = {
            ErrorCategory.TOOL_MISSING: self._handle_tool_missing,
            ErrorCategory.NETWORK_ERROR: self._handle_network_error,
            ErrorCategory.FILE_ERROR: self._handle_file_error,
            ErrorCategory.PERMISSION_ERROR: self._handle_permission_error,
            ErrorCategory.TIMEOUT_ERROR: self._handle_timeout_error,
            ErrorCategory.VALIDATION_ERROR: self._handle_validation_error,
            ErrorCategory.CONFIGURATION_ERROR: self._handle_configuration_error,
            ErrorCategory.DEPENDENCY_ERROR: self._handle_dependency_error,
            ErrorCategory.PARSING_ERROR: self._handle_parsing_error,
            ErrorCategory.UNKNOWN_ERROR: self._handle_unknown_error
        }
        
        # Retry configuration
        self.retry_config = {
            ErrorCategory.NETWORK_ERROR: {'max_retries': 3, 'delay': 2},
            ErrorCategory.TIMEOUT_ERROR: {'max_retries': 2, 'delay': 5},
            ErrorCategory.FILE_ERROR: {'max_retries': 2, 'delay': 1}
        }
    
    def handle_error(self, error: Exception, category: ErrorCategory, 
                    context: ErrorContext, retry_count: int = 0) -> Dict[str, Any]:
        """
        Handle error with appropriate strategy
        
        Args:
            error: Exception that occurred
            category: Error category
            context: Error context information
            retry_count: Current retry attempt
            
        Returns:
            Dict containing error handling result
        """
        result = {
            'handled': False,
            'retry_suggested': False,
            'fallback_available': False,
            'user_action_required': False,
            'message': str(error),
            'suggestions': []
        }
        
        try:
            # Log the error
            self.logger.error(
                f"Handling {category.value} error in {context.utility_name}",
                context=context,
                exception=error
            )
            
            # Apply recovery strategy
            if category in self.recovery_strategies:
                strategy_result = self.recovery_strategies[category](error, context, retry_count)
                result.update(strategy_result)
            else:
                result.update(self._handle_unknown_error(error, context, retry_count))
            
            result['handled'] = True
            
        except Exception as handler_error:
            self.logger.critical(
                f"Error handler failed: {handler_error}",
                context=context,
                exception=handler_error
            )
            result['message'] = f"Error handler failed: {handler_error}"
        
        return result
    
    def _handle_tool_missing(self, error: Exception, context: ErrorContext, 
                           retry_count: int) -> Dict[str, Any]:
        """Handle missing tool errors"""
        tool_name = self._extract_tool_name(context)
        
        return {
            'fallback_available': True,
            'user_action_required': True,
            'suggestions': [
                f"Install {tool_name} using the provided instructions",
                f"Check if {tool_name} is in your PATH",
                "Continue with available tools (reduced functionality)",
                "Skip this utility and proceed with others"
            ],
            'installation_instructions': self._get_installation_instructions(tool_name)
        }
    
    def _handle_network_error(self, error: Exception, context: ErrorContext, 
                            retry_count: int) -> Dict[str, Any]:
        """Handle network-related errors"""
        max_retries = self.retry_config[ErrorCategory.NETWORK_ERROR]['max_retries']
        
        return {
            'retry_suggested': retry_count < max_retries,
            'fallback_available': True,
            'suggestions': [
                "Check internet connection",
                "Verify target is accessible",
                "Try with different timeout settings",
                "Use cached results if available"
            ],
            'retry_delay': self.retry_config[ErrorCategory.NETWORK_ERROR]['delay']
        }
    
    def _handle_file_error(self, error: Exception, context: ErrorContext, 
                         retry_count: int) -> Dict[str, Any]:
        """Handle file operation errors"""
        return {
            'retry_suggested': retry_count < 2,
            'fallback_available': True,
            'suggestions': [
                "Check file permissions",
                "Verify disk space availability",
                "Ensure directory exists",
                "Try alternative output location"
            ],
            'alternative_path': self._suggest_alternative_path(context.file_path)
        }
    
    def _handle_permission_error(self, error: Exception, context: ErrorContext, 
                               retry_count: int) -> Dict[str, Any]:
        """Handle permission errors"""
        return {
            'user_action_required': True,
            'suggestions': [
                "Run with appropriate permissions",
                "Check file/directory ownership",
                "Use alternative output location",
                "Modify file permissions"
            ]
        }
    
    def _handle_timeout_error(self, error: Exception, context: ErrorContext, 
                            retry_count: int) -> Dict[str, Any]:
        """Handle timeout errors"""
        max_retries = self.retry_config[ErrorCategory.TIMEOUT_ERROR]['max_retries']
        
        return {
            'retry_suggested': retry_count < max_retries,
            'suggestions': [
                "Increase timeout value",
                "Reduce number of concurrent operations",
                "Check network connectivity",
                "Skip this target and continue"
            ],
            'retry_delay': self.retry_config[ErrorCategory.TIMEOUT_ERROR]['delay']
        }
    
    def _handle_validation_error(self, error: Exception, context: ErrorContext, 
                               retry_count: int) -> Dict[str, Any]:
        """Handle validation errors"""
        return {
            'user_action_required': True,
            'suggestions': [
                "Check input format",
                "Verify target validity",
                "Review configuration settings",
                "Use default values"
            ]
        }
    
    def _handle_configuration_error(self, error: Exception, context: ErrorContext, 
                                  retry_count: int) -> Dict[str, Any]:
        """Handle configuration errors"""
        return {
            'fallback_available': True,
            'user_action_required': True,
            'suggestions': [
                "Check configuration file syntax",
                "Verify configuration paths",
                "Use default configuration",
                "Regenerate configuration files"
            ]
        }
    
    def _handle_dependency_error(self, error: Exception, context: ErrorContext, 
                               retry_count: int) -> Dict[str, Any]:
        """Handle dependency errors"""
        return {
            'user_action_required': True,
            'suggestions': [
                "Install missing dependencies",
                "Check Python environment",
                "Verify package versions",
                "Use virtual environment"
            ]
        }
    
    def _handle_parsing_error(self, error: Exception, context: ErrorContext, 
                            retry_count: int) -> Dict[str, Any]:
        """Handle parsing errors"""
        return {
            'fallback_available': True,
            'suggestions': [
                "Check input data format",
                "Verify file encoding",
                "Use alternative parser",
                "Skip malformed data"
            ]
        }
    
    def _handle_unknown_error(self, error: Exception, context: ErrorContext, 
                            retry_count: int) -> Dict[str, Any]:
        """Handle unknown errors"""
        return {
            'suggestions': [
                "Check logs for more details",
                "Verify system requirements",
                "Try with verbose mode",
                "Report issue if persistent"
            ]
        }
    
    def _extract_tool_name(self, context: ErrorContext) -> str:
        """Extract tool name from context"""
        if context.command:
            return context.command.split()[0]
        return "unknown_tool"
    
    def _get_installation_instructions(self, tool_name: str) -> str:
        """Get installation instructions for tools"""
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
    
    def _suggest_alternative_path(self, original_path: Optional[str]) -> Optional[str]:
        """Suggest alternative file path"""
        if not original_path:
            return None
        
        # Try user's home directory
        home_dir = Path.home()
        filename = Path(original_path).name
        return str(home_dir / "hyperrecon_output" / filename)


def with_error_handling(category: ErrorCategory, logger: Optional[ReconLogger] = None):
    """
    Decorator for adding comprehensive error handling to functions
    
    Args:
        category: Error category for this function
        logger: Optional logger instance
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            error_handler = ErrorHandler(logger)
            context = ErrorContext(
                utility_name=func.__module__.split('.')[-1],
                operation=func.__name__
            )
            
            retry_count = 0
            max_retries = 3
            
            while retry_count <= max_retries:
                try:
                    return func(*args, **kwargs)
                
                except Exception as e:
                    result = error_handler.handle_error(e, category, context, retry_count)
                    
                    if result.get('retry_suggested') and retry_count < max_retries:
                        retry_count += 1
                        if 'retry_delay' in result:
                            import time
                            time.sleep(result['retry_delay'])
                        continue
                    
                    # If no retry or max retries reached, handle gracefully
                    if result.get('fallback_available'):
                        # Return empty result or default value
                        return None
                    else:
                        # Re-raise if no fallback available
                        raise e
            
            return None
        
        return wrapper
    return decorator