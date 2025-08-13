"""
File utilities for forensic analysis
Provides safe file operations and forensic integrity
"""

import os
import shutil
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

from .logger import get_logger


def copy_file_safe(source: Path, destination: Path, preserve_metadata: bool = True) -> Tuple[bool, str]:
    """
    Safely copy a file with forensic integrity
    
    Args:
        source: Source file path
        destination: Destination file path
        preserve_metadata: Whether to preserve file metadata
        
    Returns:
        Tuple of (success, message)
    """
    
    logger = get_logger(__name__)
    
    try:
        # Ensure source exists
        if not source.exists():
            return False, f"Source file does not exist: {source}"
        
        # Create destination directory if it doesn't exist
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        if preserve_metadata:
            shutil.copy2(source, destination)
        else:
            shutil.copy(source, destination)
        
        logger.info(f"File copied successfully: {source} -> {destination}")
        return True, "File copied successfully"
        
    except PermissionError:
        error_msg = f"Permission denied copying file: {source}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error copying file {source}: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def create_directory_safe(directory: Path, create_parents: bool = True) -> Tuple[bool, str]:
    """
    Safely create a directory
    
    Args:
        directory: Directory path to create
        create_parents: Whether to create parent directories
        
    Returns:
        Tuple of (success, message)
    """
    
    logger = get_logger(__name__)
    
    try:
        if create_parents:
            directory.mkdir(parents=True, exist_ok=True)
        else:
            directory.mkdir(exist_ok=True)
        
        logger.info(f"Directory created successfully: {directory}")
        return True, "Directory created successfully"
        
    except PermissionError:
        error_msg = f"Permission denied creating directory: {directory}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error creating directory {directory}: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def get_file_metadata(file_path: Path) -> dict:
    """
    Get comprehensive file metadata
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary containing file metadata
    """
    
    try:
        stat = file_path.stat()
        
        metadata = {
            'file_path': str(file_path),
            'file_name': file_path.name,
            'file_size': stat.st_size,
            'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed_time': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'file_extension': file_path.suffix,
            'is_file': file_path.is_file(),
            'is_directory': file_path.is_dir(),
            'is_symlink': file_path.is_symlink(),
            'exists': file_path.exists()
        }
        
        return metadata
        
    except Exception as e:
        logger = get_logger(__name__)
        logger.error(f"Error getting file metadata for {file_path}: {str(e)}")
        return {'error': str(e)}


def safe_file_operation(operation_func, *args, **kwargs):
    """
    Decorator for safe file operations with error handling
    
    Args:
        operation_func: Function to execute
        *args: Function arguments
        **kwargs: Function keyword arguments
        
    Returns:
        Tuple of (success, result, error_message)
    """
    
    logger = get_logger(__name__)
    
    try:
        result = operation_func(*args, **kwargs)
        return True, result, None
        
    except PermissionError as e:
        error_msg = f"Permission denied: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg
    except FileNotFoundError as e:
        error_msg = f"File not found: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg


def verify_file_integrity(source: Path, destination: Path) -> Tuple[bool, str]:
    """
    Verify file integrity after copying
    
    Args:
        source: Original file path
        destination: Copied file path
        
    Returns:
        Tuple of (integrity_verified, message)
    """
    
    logger = get_logger(__name__)
    
    try:
        # Check if both files exist
        if not source.exists():
            return False, f"Source file does not exist: {source}"
        
        if not destination.exists():
            return False, f"Destination file does not exist: {destination}"
        
        # Compare file sizes
        source_size = source.stat().st_size
        dest_size = destination.stat().st_size
        
        if source_size != dest_size:
            return False, f"File size mismatch: source={source_size}, destination={dest_size}"
        
        # Compare file modification times (if using copy2)
        source_mtime = source.stat().st_mtime
        dest_mtime = destination.stat().st_mtime
        
        if abs(source_mtime - dest_mtime) > 1:  # Allow 1 second difference
            logger.warning(f"File modification time mismatch: source={source_mtime}, destination={dest_mtime}")
        
        logger.info(f"File integrity verified: {source} -> {destination}")
        return True, "File integrity verified"
        
    except Exception as e:
        error_msg = f"Error verifying file integrity: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def create_forensic_copy(source: Path, destination: Path) -> Tuple[bool, str, dict]:
    """
    Create a forensic copy with integrity verification
    
    Args:
        source: Source file path
        destination: Destination file path
        
    Returns:
        Tuple of (success, message, metadata)
    """
    
    logger = get_logger(__name__)
    
    try:
        # Get source metadata
        source_metadata = get_file_metadata(source)
        
        # Create destination directory
        success, message = create_directory_safe(destination.parent)
        if not success:
            return False, message, {}
        
        # Copy file with metadata preservation
        success, message = copy_file_safe(source, destination, preserve_metadata=True)
        if not success:
            return False, message, source_metadata
        
        # Verify integrity
        integrity_verified, integrity_message = verify_file_integrity(source, destination)
        if not integrity_verified:
            return False, integrity_message, source_metadata
        
        # Get destination metadata
        dest_metadata = get_file_metadata(destination)
        
        # Create forensic copy metadata
        forensic_metadata = {
            'source_metadata': source_metadata,
            'destination_metadata': dest_metadata,
            'copy_timestamp': datetime.now().isoformat(),
            'integrity_verified': integrity_verified
        }
        
        logger.info(f"Forensic copy completed successfully: {source} -> {destination}")
        return True, "Forensic copy completed successfully", forensic_metadata
        
    except Exception as e:
        error_msg = f"Error creating forensic copy: {str(e)}"
        logger.error(error_msg)
        return False, error_msg, {}


def list_directory_contents(directory: Path, recursive: bool = False) -> list:
    """
    List directory contents with metadata
    
    Args:
        directory: Directory to list
        recursive: Whether to list recursively
        
    Returns:
        List of file metadata dictionaries
    """
    
    logger = get_logger(__name__)
    contents = []
    
    try:
        if not directory.exists():
            logger.warning(f"Directory does not exist: {directory}")
            return contents
        
        if recursive:
            files = directory.rglob("*")
        else:
            files = directory.iterdir()
        
        for file_path in files:
            try:
                metadata = get_file_metadata(file_path)
                contents.append(metadata)
            except Exception as e:
                logger.warning(f"Error getting metadata for {file_path}: {str(e)}")
                contents.append({
                    'file_path': str(file_path),
                    'error': str(e)
                })
        
        return contents
        
    except Exception as e:
        logger.error(f"Error listing directory contents: {str(e)}")
        return contents


def calculate_directory_size(directory: Path) -> int:
    """
    Calculate total size of directory contents
    
    Args:
        directory: Directory to calculate size for
        
    Returns:
        Total size in bytes
    """
    
    total_size = 0
    
    try:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                try:
                    total_size += file_path.stat().st_size
                except (OSError, IOError):
                    continue
        
        return total_size
        
    except Exception as e:
        logger = get_logger(__name__)
        logger.error(f"Error calculating directory size: {str(e)}")
        return 0
