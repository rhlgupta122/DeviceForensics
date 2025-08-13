"""
Tests for EVTX Analyzer functionality
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch

from src.core.evtx_analyzer import EVTXAnalyzer


class TestEVTXAnalyzer:
    """Test cases for EVTX Analyzer"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.analyzer = EVTXAnalyzer()
    
    def teardown_method(self):
        """Clean up test fixtures"""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_analyzer_initialization(self):
        """Test EVTX analyzer initialization"""
        assert self.analyzer is not None
        assert hasattr(self.analyzer, 'SECURITY_EVENT_IDS')
        assert hasattr(self.analyzer, 'SEVERITY_LEVELS')
        assert isinstance(self.analyzer.SECURITY_EVENT_IDS, dict)
        assert isinstance(self.analyzer.SEVERITY_LEVELS, dict)
    
    def test_security_event_ids_containment(self):
        """Test that important security event IDs are defined"""
        important_events = [4624, 4625, 4634, 4720, 4728, 4688, 5152, 5153]
        for event_id in important_events:
            assert event_id in self.analyzer.SECURITY_EVENT_IDS
    
    def test_severity_levels_containment(self):
        """Test that severity levels are properly defined"""
        expected_levels = [0, 1, 2, 3, 4]
        for level in expected_levels:
            assert level in self.analyzer.SEVERITY_LEVELS
    
    def test_analyze_evtx_directory_no_files(self):
        """Test analyzing directory with no EVTX files"""
        result = self.analyzer.analyze_evtx_directory(self.temp_dir, self.temp_dir)
        assert isinstance(result, dict)
        assert 'metadata' in result
        assert 'summary' in result
    
    @patch('src.core.evtx_analyzer.evtx')
    def test_analyze_evtx_file_mock(self, mock_evtx):
        """Test analyzing EVTX file with mocked library"""
        # Mock the evtx library
        mock_evtx.PyEvtxParser.return_value.records.return_value = []
        
        # Create a dummy EVTX file
        evtx_file = self.temp_dir / "test.evtx"
        evtx_file.write_bytes(b"dummy evtx content")
        
        result = self.analyzer.analyze_evtx_file(evtx_file)
        assert isinstance(result, dict)
        assert 'file_info' in result
        assert 'events' in result
        assert 'security_events' in result
        assert 'anomalies' in result
    
    def test_detect_anomalies_empty_events(self):
        """Test anomaly detection with empty events"""
        anomalies = self.analyzer._detect_anomalies([])
        assert isinstance(anomalies, list)
        assert len(anomalies) == 0
    
    def test_detect_anomalies_high_frequency(self):
        """Test detection of high-frequency events"""
        # Create mock events with high frequency
        events = []
        for i in range(150):  # More than threshold of 100
            events.append({
                'timestamp': f'2023-01-01T12:00:00+00:00',
                'event_id': 1000,
                'description': 'Test event'
            })
        
        anomalies = self.analyzer._detect_anomalies(events)
        assert len(anomalies) > 0
        assert any(a['type'] == 'high_frequency_events' for a in anomalies)
    
    def test_detect_anomalies_failed_logons(self):
        """Test detection of multiple failed logons"""
        events = []
        for i in range(15):  # More than threshold of 10
            events.append({
                'event_id': 4625,  # Failed logon
                'timestamp': f'2023-01-01T12:00:00+00:00',
                'description': 'Failed logon'
            })
        
        anomalies = self.analyzer._detect_anomalies(events)
        assert len(anomalies) > 0
        assert any(a['type'] == 'multiple_failed_logons' for a in anomalies)
    
    def test_generate_risk_assessment(self):
        """Test risk assessment generation"""
        analysis_results = {
            'security_findings': [
                {'severity': 'high'},
                {'severity': 'medium'},
                {'severity': 'low'}
            ],
            'anomalies': [{'type': 'test'}]
        }
        
        risk_assessment = self.analyzer._generate_risk_assessment(analysis_results)
        assert isinstance(risk_assessment, dict)
        assert 'risk_level' in risk_assessment
        assert 'risk_score' in risk_assessment
        assert 'total_findings' in risk_assessment
        assert 'total_anomalies' in risk_assessment
    
    def test_generate_investigation_recommendations(self):
        """Test investigation recommendations generation"""
        analysis_results = {
            'security_findings': [
                {'type': 'security_event'},
                {'type': 'suspicious_run_key'}
            ],
            'risk_assessment': {'risk_level': 'high'}
        }
        
        recommendations = self.analyzer._generate_investigation_recommendations(analysis_results)
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
    
    def test_save_analysis_results(self):
        """Test saving analysis results to files"""
        results = {
            'metadata': {'test': 'data'},
            'security_events': [],
            'timeline': [],
            'anomalies': []
        }
        
        self.analyzer._save_analysis_results(results, self.temp_dir)
        
        # Check that files were created
        assert (self.temp_dir / "evtx_analysis.json").exists()
        assert (self.temp_dir / "security_summary.json").exists()
        assert (self.temp_dir / "event_timeline.json").exists()
        assert (self.temp_dir / "anomalies.json").exists()
    
    def test_generate_security_report(self):
        """Test security report generation"""
        analysis_results = {
            'metadata': {'analysis_time': '2023-01-01T12:00:00'},
            'summary': {
                'total_events': 100,
                'security_events': 10,
                'event_types': {4625: 5, 4720: 3},
                'anomalies': 2
            },
            'security_events': [],
            'anomalies': []
        }
        
        report_path = self.analyzer.generate_security_report(analysis_results, self.temp_dir)
        assert isinstance(report_path, str)
        assert Path(report_path).exists()
        assert report_path.endswith('.html')
