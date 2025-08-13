"""
Logging utilities for forensic analysis
Ensures proper audit trail and forensic integrity
"""

import os
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
from typing import Optional


def setup_logger(log_level: int = logging.INFO, log_file: str = "forensic_extraction.log") -> logging.Logger:
    """
    Setup forensic logging with proper formatting and rotation
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Path to log file
        
    Returns:
        Configured logger instance
    """
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    log_path = log_dir / log_file
    
    # Create logger
    logger = logging.getLogger("forensic_extractor")
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log initial forensic session information
    logger.info("=" * 80)
    logger.info("FORENSIC EXTRACTION SESSION STARTED")
    logger.info(f"Session ID: {datetime.now().strftime('%Y%m%d_%H%M%S')}")
    logger.info(f"Log Level: {logging.getLevelName(log_level)}")
    logger.info(f"Log File: {log_path.absolute()}")
    logger.info("=" * 80)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module
    
    Args:
        name: Module name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(f"forensic_extractor.{name}")


def log_forensic_event(logger: logging.Logger, event_type: str, description: str, 
                      evidence_path: Optional[str] = None, hash_value: Optional[str] = None):
    """
    Log a forensic event with proper formatting
    
    Args:
        logger: Logger instance
        event_type: Type of forensic event
        description: Description of the event
        evidence_path: Path to evidence file (optional)
        hash_value: Hash value of evidence (optional)
    """
    
    event_data = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'description': description
    }
    
    if evidence_path:
        event_data['evidence_path'] = evidence_path
    
    if hash_value:
        event_data['hash_value'] = hash_value
    
    logger.info(f"FORENSIC_EVENT: {event_data}")


def log_chain_of_custody(logger: logging.Logger, action: str, evidence_id: str, 
                        location: str, handler: str, notes: str = ""):
    """
    Log chain of custody information
    
    Args:
        logger: Logger instance
        action: Action performed (e.g., "EXTRACTED", "COPIED", "ANALYZED")
        evidence_id: Unique identifier for evidence
        location: Location of evidence
        handler: Person/system handling evidence
        notes: Additional notes
    """
    
    custody_data = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'evidence_id': evidence_id,
        'location': location,
        'handler': handler,
        'notes': notes
    }
    
    logger.info(f"CHAIN_OF_CUSTODY: {custody_data}")


def log_hash_verification(logger: logging.Logger, file_path: str, expected_hash: str, 
                         actual_hash: str, verification_result: bool):
    """
    Log hash verification results
    
    Args:
        logger: Logger instance
        file_path: Path to file being verified
        expected_hash: Expected hash value
        actual_hash: Actual hash value
        verification_result: Whether verification passed
    """
    
    verification_data = {
        'timestamp': datetime.now().isoformat(),
        'file_path': file_path,
        'expected_hash': expected_hash,
        'actual_hash': actual_hash,
        'verification_result': verification_result
    }
    
    if verification_result:
        logger.info(f"HASH_VERIFICATION_PASSED: {verification_data}")
    else:
        logger.error(f"HASH_VERIFICATION_FAILED: {verification_data}")


def log_error_with_context(logger: logging.Logger, error: Exception, context: str, 
                          additional_info: Optional[dict] = None):
    """
    Log error with forensic context
    
    Args:
        logger: Logger instance
        error: Exception that occurred
        context: Context where error occurred
        additional_info: Additional information about the error
    """
    
    error_data = {
        'timestamp': datetime.now().isoformat(),
        'error_type': type(error).__name__,
        'error_message': str(error),
        'context': context
    }
    
    if additional_info:
        error_data.update(additional_info)
    
    logger.error(f"FORENSIC_ERROR: {error_data}")


def create_forensic_summary(logger: logging.Logger, extraction_results: dict) -> str:
    """
    Create a forensic extraction summary
    
    Args:
        logger: Logger instance
        extraction_results: Results from forensic extraction
        
    Returns:
        Summary string
    """
    
    summary_lines = [
        "=" * 80,
        "FORENSIC EXTRACTION SUMMARY",
        "=" * 80,
        f"Extraction Time: {extraction_results.get('metadata', {}).get('extraction_time', 'Unknown')}",
        f"Extractor Version: {extraction_results.get('metadata', {}).get('extractor_version', 'Unknown')}",
        "",
        "ARTIFACTS EXTRACTED:"
    ]
    
    artifacts = extraction_results.get('artifacts', {})
    for artifact_type, artifact_data in artifacts.items():
        if isinstance(artifact_data, dict):
            summary_lines.append(f"  - {artifact_type}: {len(artifact_data)} items")
        else:
            summary_lines.append(f"  - {artifact_type}: Extracted")
    
    summary_lines.extend([
        "",
        "=" * 80,
        "FORENSIC EXTRACTION COMPLETED",
        "=" * 80
    ])
    
    summary = "\n".join(summary_lines)
    logger.info(summary)
    
    return summary
