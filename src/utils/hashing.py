"""
Hashing utilities for forensic analysis
Provides hash calculation and verification for forensic integrity
"""

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional, Tuple


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        Hexadecimal hash string or "PERMISSION_DENIED" for access issues
    """
    
    hash_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_obj = hash_algorithms[algorithm]()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    except (PermissionError, OSError) as e:
        # Return a special value for permission errors instead of raising
        return "PERMISSION_DENIED"
    except Exception as e:
        return f"ERROR: {str(e)}"


def calculate_string_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a string
    
    Args:
        data: String data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        Hexadecimal hash string
    """
    
    hash_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_obj = hash_algorithms[algorithm]()
    hash_obj.update(data.encode('utf-8'))
    
    return hash_obj.hexdigest()


def calculate_multiple_hashes(file_path: Path) -> Dict[str, str]:
    """
    Calculate multiple hash algorithms for a file
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary of hash algorithms and their values
    """
    
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    hashes = {}
    
    for algorithm in algorithms:
        try:
            hashes[algorithm] = calculate_file_hash(file_path, algorithm)
        except Exception as e:
            hashes[algorithm] = f"ERROR: {str(e)}"
    
    return hashes


def verify_file_hash(file_path: Path, expected_hash: str, algorithm: str = "sha256") -> Tuple[bool, str]:
    """
    Verify file hash against expected value
    
    Args:
        file_path: Path to the file
        expected_hash: Expected hash value
        algorithm: Hash algorithm used
        
    Returns:
        Tuple of (verification_result, actual_hash)
    """
    
    try:
        actual_hash = calculate_file_hash(file_path, algorithm)
        verification_result = actual_hash.lower() == expected_hash.lower()
        return verification_result, actual_hash
    
    except Exception as e:
        return False, f"ERROR: {str(e)}"


def create_hash_manifest(directory: Path, algorithm: str = "sha256") -> Dict[str, str]:
    """
    Create a hash manifest for all files in a directory
    
    Args:
        directory: Directory to create manifest for
        algorithm: Hash algorithm to use
        
    Returns:
        Dictionary mapping file paths to their hashes
    """
    
    manifest = {}
    
    try:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                try:
                    relative_path = file_path.relative_to(directory)
                    hash_value = calculate_file_hash(file_path, algorithm)
                    manifest[str(relative_path)] = hash_value
                except Exception as e:
                    manifest[str(relative_path)] = f"ERROR: {str(e)}"
    
    except Exception as e:
        raise Exception(f"Error creating hash manifest: {str(e)}")
    
    return manifest


def verify_hash_manifest(directory: Path, manifest: Dict[str, str], algorithm: str = "sha256") -> Dict[str, bool]:
    """
    Verify files against a hash manifest
    
    Args:
        directory: Directory containing files
        manifest: Hash manifest dictionary
        algorithm: Hash algorithm used
        
    Returns:
        Dictionary mapping file paths to verification results
    """
    
    verification_results = {}
    
    for file_path_str, expected_hash in manifest.items():
        file_path = directory / file_path_str
        
        if file_path.exists():
            try:
                verification_result, actual_hash = verify_file_hash(file_path, expected_hash, algorithm)
                verification_results[file_path_str] = verification_result
            except Exception as e:
                verification_results[file_path_str] = False
        else:
            verification_results[file_path_str] = False
    
    return verification_results


def calculate_directory_hash(directory: Path, algorithm: str = "sha256") -> str:
    """
    Calculate a hash representing the entire directory structure
    
    Args:
        directory: Directory to hash
        algorithm: Hash algorithm to use
        
    Returns:
        Hexadecimal hash string
    """
    
    hash_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_obj = hash_algorithms[algorithm]()
    
    try:
        # Sort files for consistent hashing
        files = sorted(directory.rglob("*"))
        
        for file_path in files:
            if file_path.is_file():
                # Add file path and content to hash
                relative_path = file_path.relative_to(directory)
                hash_obj.update(str(relative_path).encode('utf-8'))
                
                # Add file content hash
                file_hash = calculate_file_hash(file_path, algorithm)
                hash_obj.update(file_hash.encode('utf-8'))
        
        return hash_obj.hexdigest()
    
    except Exception as e:
        raise Exception(f"Error calculating directory hash: {str(e)}")


def create_forensic_hash_report(directory: Path) -> Dict[str, any]:
    """
    Create a comprehensive hash report for forensic analysis
    
    Args:
        directory: Directory to analyze
        
    Returns:
        Dictionary containing hash report
    """
    
    report = {
        'timestamp': None,  # Will be set by caller
        'directory': str(directory.absolute()),
        'hash_manifest': {},
        'directory_hash': None,
        'file_count': 0,
        'total_size': 0,
        'errors': []
    }
    
    try:
        # Count files and calculate total size
        files = list(directory.rglob("*"))
        report['file_count'] = len([f for f in files if f.is_file()])
        report['total_size'] = sum(f.stat().st_size for f in files if f.is_file())
        
        # Create hash manifest
        report['hash_manifest'] = create_hash_manifest(directory)
        
        # Calculate directory hash
        report['directory_hash'] = calculate_directory_hash(directory)
        
    except Exception as e:
        report['errors'].append(str(e))
    
    return report


def verify_forensic_integrity(original_directory: Path, copied_directory: Path) -> Dict[str, any]:
    """
    Verify forensic integrity between original and copied directories
    
    Args:
        original_directory: Original directory
        copied_directory: Copied directory to verify
        
    Returns:
        Dictionary containing verification results
    """
    
    verification_report = {
        'timestamp': None,  # Will be set by caller
        'original_directory': str(original_directory.absolute()),
        'copied_directory': str(copied_directory.absolute()),
        'integrity_verified': False,
        'file_verifications': {},
        'directory_hash_match': False,
        'errors': []
    }
    
    try:
        # Verify directory hashes
        original_hash = calculate_directory_hash(original_directory)
        copied_hash = calculate_directory_hash(copied_directory)
        
        verification_report['directory_hash_match'] = (original_hash == copied_hash)
        
        # Verify individual files
        original_manifest = create_hash_manifest(original_directory)
        copied_manifest = create_hash_manifest(copied_directory)
        
        for file_path, original_hash in original_manifest.items():
            if file_path in copied_manifest:
                copied_hash = copied_manifest[file_path]
                verification_report['file_verifications'][file_path] = (original_hash == copied_hash)
            else:
                verification_report['file_verifications'][file_path] = False
        
        # Overall integrity
        all_files_verified = all(verification_report['file_verifications'].values())
        verification_report['integrity_verified'] = (
            verification_report['directory_hash_match'] and all_files_verified
        )
        
    except Exception as e:
        verification_report['errors'].append(str(e))
    
    return verification_report
