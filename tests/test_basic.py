"""
Basic tests for the forensic application
"""

import pytest
from pathlib import Path
import tempfile
import shutil

# Add src to path for imports
import sys
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from core.extractor import ForensicExtractor
from utils.hashing import calculate_file_hash, calculate_string_hash
from utils.logger import setup_logger


class TestForensicExtractor:
    """Test cases for the forensic extractor"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.extractor = ForensicExtractor()
    
    def teardown_method(self):
        """Cleanup test environment"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_extractor_initialization(self):
        """Test that the extractor initializes correctly"""
        assert self.extractor is not None
        assert hasattr(self.extractor, 'registry_parser')
        assert hasattr(self.extractor, 'filesystem_analyzer')
        assert hasattr(self.extractor, 'memory_dumper')
        assert hasattr(self.extractor, 'network_analyzer')
    
    def test_system_info_extraction(self):
        """Test system information extraction"""
        system_info = self.extractor._get_system_info()
        assert isinstance(system_info, dict)
        assert 'hostname' in system_info or 'error' in system_info


class TestHashing:
    """Test cases for hashing utilities"""
    
    def test_string_hashing(self):
        """Test string hashing functionality"""
        test_string = "Hello, World!"
        hash_value = calculate_string_hash(test_string)
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA256 hash length
    
    def test_file_hashing(self):
        """Test file hashing functionality"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Test content for hashing")
            temp_file = Path(f.name)
        
        try:
            hash_value = calculate_file_hash(temp_file)
            assert isinstance(hash_value, str)
            assert len(hash_value) == 64  # SHA256 hash length
        finally:
            temp_file.unlink()
    
    def test_multiple_hash_algorithms(self):
        """Test multiple hash algorithms"""
        test_string = "Test string"
        
        # Test different algorithms
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        for algorithm in algorithms:
            hash_value = calculate_string_hash(test_string, algorithm)
            assert isinstance(hash_value, str)
            
            # Verify expected lengths
            expected_lengths = {
                'md5': 32,
                'sha1': 40,
                'sha256': 64,
                'sha512': 128
            }
            assert len(hash_value) == expected_lengths[algorithm]


class TestLogging:
    """Test cases for logging utilities"""
    
    def test_logger_setup(self):
        """Test logger setup"""
        logger = setup_logger()
        assert logger is not None
        assert logger.level <= 20  # INFO level or lower
    
    def test_logger_with_file(self):
        """Test logger with file output"""
        log_file = "test_log.log"
        logger = setup_logger(log_file=log_file)
        assert logger is not None
        
        # Clean up
        if Path(log_file).exists():
            Path(log_file).unlink()


class TestFileUtils:
    """Test cases for file utilities"""
    
    def test_directory_creation(self):
        """Test safe directory creation"""
        from utils.file_utils import create_directory_safe
        
        test_dir = Path(tempfile.mkdtemp()) / "test_subdir"
        success, message = create_directory_safe(test_dir)
        
        assert success
        assert test_dir.exists()
        
        # Cleanup
        shutil.rmtree(test_dir.parent)
    
    def test_file_metadata(self):
        """Test file metadata extraction"""
        from utils.file_utils import get_file_metadata
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Test content")
            temp_file = Path(f.name)
        
        try:
            metadata = get_file_metadata(temp_file)
            assert isinstance(metadata, dict)
            assert 'file_path' in metadata
            assert 'file_size' in metadata
            assert 'created_time' in metadata
            assert 'modified_time' in metadata
        finally:
            temp_file.unlink()


if __name__ == "__main__":
    pytest.main([__file__])
