"""
Logging configuration system with multiple verbosity levels
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import sys
import logging
import logging.handlers
from datetime import datetime
from typing import Dict, Optional, Any
from pathlib import Path
from enum import Enum


class VerbosityLevel(Enum):
    """Verbosity levels for different types of output"""
    SILENT = 0      # Only critical errors
    MINIMAL = 1     # Errors and warnings
    NORMAL = 2      # Errors, warnings, and basic info
    VERBOSE = 3     # Detailed information
    DEBUG = 4       # All debug information


class LoggingConfig:
    """
    Centralized logging configuration with multiple output formats and verbosity levels
    """
    
    def __init__(self, verbosity: VerbosityLevel = VerbosityLevel.NORMAL,
                 output_dir: Optional[str] = None, 
                 console_output: bool = True,
                 file_output: bool = True):
        """
        Initialize logging configuration
        
        Args:
            verbosity: Verbosity level for logging
            output_dir: Directory for log files
            console_output: Whether to output to console
            file_output: Whether to output to files
        """
        self.verbosity = verbosity
        self.output_dir = output_dir
        self.console_output = console_output
        self.file_output = file_output
        
        # Logging level mapping
        self.level_mapping = {
            VerbosityLevel.SILENT: logging.CRITICAL,
            VerbosityLevel.MINIMAL: logging.ERROR,
            VerbosityLevel.NORMAL: logging.WARNING,
            VerbosityLevel.VERBOSE: logging.INFO,
            VerbosityLevel.DEBUG: logging.DEBUG
        }
        
        # Console level mapping (might be different from file logging)
        self.console_level_mapping = {
            VerbosityLevel.SILENT: logging.CRITICAL,
            VerbosityLevel.MINIMAL: logging.ERROR,
            VerbosityLevel.NORMAL: logging.INFO,
            VerbosityLevel.VERBOSE: logging.INFO,
            VerbosityLevel.DEBUG: logging.DEBUG
        }
        
        # Initialize logging directory
        if self.file_output and self.output_dir:
            self._setup_logging_directory()
    
    def _setup_logging_directory(self):
        """Setup logging directory structure"""
        try:
            log_dir = Path(self.output_dir) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories for different log types
            (log_dir / "utilities").mkdir(exist_ok=True)
            (log_dir / "errors").mkdir(exist_ok=True)
            (log_dir / "debug").mkdir(exist_ok=True)
            
        except Exception as e:
            print(f"Warning: Could not setup logging directory: {e}")
    
    def setup_logger(self, name: str, utility_name: Optional[str] = None) -> logging.Logger:
        """
        Setup a logger with the configured settings
        
        Args:
            name: Logger name
            utility_name: Optional utility name for specialized logging
            
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)  # Set to lowest level, handlers will filter
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Setup console handler
        if self.console_output:
            console_handler = self._create_console_handler()
            logger.addHandler(console_handler)
        
        # Setup file handlers
        if self.file_output and self.output_dir:
            file_handlers = self._create_file_handlers(name, utility_name)
            for handler in file_handlers:
                logger.addHandler(handler)
        
        # Prevent propagation to root logger
        logger.propagate = False
        
        return logger
    
    def _create_console_handler(self) -> logging.StreamHandler:
        """Create console handler with appropriate formatting"""
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(self.console_level_mapping[self.verbosity])
        
        # Different formatters based on verbosity
        if self.verbosity == VerbosityLevel.DEBUG:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                datefmt='%H:%M:%S'
            )
        elif self.verbosity in [VerbosityLevel.VERBOSE, VerbosityLevel.NORMAL]:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S'
            )
        else:
            formatter = logging.Formatter('%(levelname)s - %(message)s')
        
        handler.setFormatter(formatter)
        return handler
    
    def _create_file_handlers(self, name: str, utility_name: Optional[str] = None) -> list:
        """Create file handlers for different log types"""
        handlers = []
        
        try:
            log_dir = Path(self.output_dir) / "logs"
            timestamp = datetime.now().strftime('%Y%m%d')
            
            # Main log file (all messages)
            main_log_file = log_dir / f"hyperrecon_{timestamp}.log"
            main_handler = logging.FileHandler(main_log_file, encoding='utf-8')
            main_handler.setLevel(self.level_mapping[self.verbosity])
            main_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            handlers.append(main_handler)
            
            # Error log file (errors and critical only)
            error_log_file = log_dir / "errors" / f"errors_{timestamp}.log"
            error_handler = logging.FileHandler(error_log_file, encoding='utf-8')
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            handlers.append(error_handler)
            
            # Utility-specific log file
            if utility_name:
                utility_log_file = log_dir / "utilities" / f"{utility_name}_{timestamp}.log"
                utility_handler = logging.FileHandler(utility_log_file, encoding='utf-8')
                utility_handler.setLevel(logging.DEBUG)
                utility_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                handlers.append(utility_handler)
            
            # Debug log file (if debug level)
            if self.verbosity == VerbosityLevel.DEBUG:
                debug_log_file = log_dir / "debug" / f"debug_{timestamp}.log"
                debug_handler = logging.FileHandler(debug_log_file, encoding='utf-8')
                debug_handler.setLevel(logging.DEBUG)
                debug_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                handlers.append(debug_handler)
            
            # Rotating log handler for long-running operations
            rotating_log_file = log_dir / "hyperrecon_rotating.log"
            rotating_handler = logging.handlers.RotatingFileHandler(
                rotating_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
            )
            rotating_handler.setLevel(self.level_mapping[self.verbosity])
            rotating_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            handlers.append(rotating_handler)
            
        except Exception as e:
            print(f"Warning: Could not setup file handlers: {e}")
        
        return handlers
    
    def get_verbosity_description(self) -> str:
        """Get description of current verbosity level"""
        descriptions = {
            VerbosityLevel.SILENT: "Silent - Only critical errors",
            VerbosityLevel.MINIMAL: "Minimal - Errors and warnings only",
            VerbosityLevel.NORMAL: "Normal - Standard information",
            VerbosityLevel.VERBOSE: "Verbose - Detailed information",
            VerbosityLevel.DEBUG: "Debug - All debug information"
        }
        return descriptions[self.verbosity]
    
    def update_verbosity(self, new_verbosity: VerbosityLevel):
        """
        Update verbosity level for existing loggers
        
        Args:
            new_verbosity: New verbosity level
        """
        self.verbosity = new_verbosity
        
        # Update all existing loggers
        for logger_name in logging.Logger.manager.loggerDict:
            if logger_name.startswith('HyperRecon'):
                logger = logging.getLogger(logger_name)
                
                # Update console handlers
                for handler in logger.handlers:
                    if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                        handler.setLevel(self.console_level_mapping[new_verbosity])
                    elif isinstance(handler, logging.FileHandler):
                        # Update main file handlers (not error-only handlers)
                        if 'error' not in str(handler.baseFilename):
                            handler.setLevel(self.level_mapping[new_verbosity])
    
    def create_performance_logger(self, name: str) -> logging.Logger:
        """
        Create a specialized logger for performance metrics
        
        Args:
            name: Logger name
            
        Returns:
            Performance logger instance
        """
        logger = logging.getLogger(f"{name}.performance")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        
        if self.file_output and self.output_dir:
            try:
                log_dir = Path(self.output_dir) / "logs"
                perf_log_file = log_dir / "performance.log"
                
                handler = logging.FileHandler(perf_log_file, encoding='utf-8')
                handler.setLevel(logging.INFO)
                handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                logger.addHandler(handler)
                
            except Exception as e:
                print(f"Warning: Could not setup performance logger: {e}")
        
        logger.propagate = False
        return logger
    
    def create_audit_logger(self, name: str) -> logging.Logger:
        """
        Create a specialized logger for audit trail
        
        Args:
            name: Logger name
            
        Returns:
            Audit logger instance
        """
        logger = logging.getLogger(f"{name}.audit")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        
        if self.file_output and self.output_dir:
            try:
                log_dir = Path(self.output_dir) / "logs"
                audit_log_file = log_dir / "audit.log"
                
                handler = logging.FileHandler(audit_log_file, encoding='utf-8')
                handler.setLevel(logging.INFO)
                handler.setFormatter(logging.Formatter(
                    '%(asctime)s - AUDIT - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                logger.addHandler(handler)
                
            except Exception as e:
                print(f"Warning: Could not setup audit logger: {e}")
        
        logger.propagate = False
        return logger
    
    def cleanup_old_logs(self, days_to_keep: int = 7):
        """
        Clean up old log files
        
        Args:
            days_to_keep: Number of days of logs to keep
        """
        if not self.output_dir:
            return
        
        try:
            log_dir = Path(self.output_dir) / "logs"
            if not log_dir.exists():
                return
            
            cutoff_time = datetime.now().timestamp() - (days_to_keep * 24 * 60 * 60)
            
            for log_file in log_dir.rglob("*.log"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    print(f"Cleaned up old log file: {log_file}")
            
        except Exception as e:
            print(f"Warning: Could not cleanup old logs: {e}")
    
    def get_log_summary(self) -> Dict[str, Any]:
        """
        Get summary of logging configuration and statistics
        
        Returns:
            Dict containing logging summary
        """
        summary = {
            'verbosity_level': self.verbosity.name,
            'verbosity_description': self.get_verbosity_description(),
            'console_output': self.console_output,
            'file_output': self.file_output,
            'output_directory': self.output_dir,
            'active_loggers': []
        }
        
        # Get information about active loggers
        for logger_name in logging.Logger.manager.loggerDict:
            if logger_name.startswith('HyperRecon'):
                logger = logging.getLogger(logger_name)
                summary['active_loggers'].append({
                    'name': logger_name,
                    'level': logging.getLevelName(logger.level),
                    'handlers': len(logger.handlers)
                })
        
        return summary


def setup_global_logging(verbosity: VerbosityLevel = VerbosityLevel.NORMAL,
                        output_dir: Optional[str] = None) -> LoggingConfig:
    """
    Setup global logging configuration for HyperRecon
    
    Args:
        verbosity: Verbosity level
        output_dir: Output directory for logs
        
    Returns:
        LoggingConfig instance
    """
    config = LoggingConfig(
        verbosity=verbosity,
        output_dir=output_dir,
        console_output=True,
        file_output=output_dir is not None
    )
    
    # Setup root logger
    root_logger = config.setup_logger("HyperRecon")
    root_logger.info(f"Logging initialized - {config.get_verbosity_description()}")
    
    return config