# 🔍 Windows Forensic Artifact Extractor

A comprehensive Python-based forensic application for extracting, analyzing, and reporting on Windows artifacts to support digital forensics and incident response investigations.

## 🎯 Features

### Core Artifacts
- **Registry Analysis**: Extract and analyze Windows Registry hives and keys
- **File System Timeline**: Create comprehensive timeline of file system activities
- **Memory Acquisition**: RAM dump and analysis capabilities
- **Network Artifacts**: Browser history, network connections, and DNS cache
- **User Activity**: Recent files, run history, and user profiles
- **Windows Event Logs (EVTX)**: Comprehensive analysis of security events and system logs

### Advanced Execution Artifacts (Based on Native Logs)
- **Prefetch Files**: Application execution history and dependencies
- **ShimCache (AppCompatCache)**: Registry-based execution evidence
- **Amcache**: Application compatibility database with file metadata
- **PCA (Program Compatibility Assistant)**: Windows 11 compatibility tracking
- **MUICache**: Multilingual User Interface cache for GUI applications
- **UserAssist**: User interaction with GUI applications
- **SRUM**: System Resource Usage Monitor for detailed activity tracking
- **Registry ASEP**: Auto-Start Extensibility Points for persistence analysis
- **Volume Shadow Copies**: System snapshots for deleted file recovery
- **Windows Crash Dumps**: WER (Windows Error Reporting) data analysis

### Analysis & Reporting
- **Automatic Analysis**: AI-powered security analysis and anomaly detection
- **Risk Assessment**: Automated risk scoring and threat level classification
- **Investigation Recommendations**: Actionable guidance for investigators
- **Comprehensive Reporting**: HTML and JSON reports with detailed findings
- **Security Investigation Reports**: Specialized reports for security incidents

### User Interfaces
- **Graphical User Interface (GUI)**: Modern, intuitive interface with real-time command line display
- **Command Line Interface (CLI)**: Full-featured CLI with granular control
- **KAPE-like Command Display**: Real-time command line equivalent for GUI selections

### Forensic Integrity
- **Chain of Custody**: Comprehensive audit trail and evidence tracking
- **Hash Verification**: MD5, SHA1, SHA256, SHA512 integrity checking
- **Logging**: Forensic-grade logging with detailed audit trails
- **Evidence Preservation**: Write-blocking and evidence integrity protection

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/DeviceForensics.git
cd DeviceForensics

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

### Basic Usage

```bash
# Extract all artifacts
python main.py --extract-all --output-dir ./forensic_output

# Extract specific artifacts
python main.py --registry --filesystem --memory --evtx --output-dir ./output

# Extract and analyze EVTX files only
python main.py --evtx --output-dir ./evtx_analysis

# Extract advanced execution artifacts
python main.py --prefetch --shimcache --amcache --userassist --output-dir ./execution_analysis

# Generate report only
python main.py --report --input-dir ./forensic_output --output-report ./report.html

# Launch GUI
python main.py --gui
```

## 📋 System Requirements

- **OS**: Windows 10/11, Windows Server 2016+
- **Python**: 3.8 or higher
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: 2GB free space for tool + extraction space
- **Permissions**: Administrator privileges required

## 🔧 Advanced Usage

### Command Line Options

```bash
# Artifact Selection
--extract-all              # Extract all available artifacts
--registry                 # Extract registry artifacts
--filesystem               # Extract file system artifacts
--memory                   # Extract memory artifacts
--network                  # Extract network artifacts
--user-activity            # Extract user activity artifacts
--evtx                     # Extract and analyze Windows Event Log (EVTX) artifacts

# Advanced Artifacts (Based on Native Logs)
--prefetch                 # Extract Prefetch files (execution history)
--shimcache                # Extract ShimCache/AppCompatCache registry data
--amcache                  # Extract Amcache.hve application compatibility data
--pca                      # Extract PCA (Program Compatibility Assistant) logs
--muicache                 # Extract MUICache from user registry hives
--userassist               # Extract UserAssist execution history
--srum                     # Extract SRUM (System Resource Usage Monitor) data
--registry-asep            # Extract Registry ASEP (Auto-Start Extensibility Points)
--volume-shadow-copies     # Extract Volume Shadow Copies (advanced)
--crash-dumps              # Extract Windows Crash Dumps/WER data (advanced)

# Output Options
--output-dir PATH          # Output directory for extracted artifacts
--output-report PATH       # Output path for generated report
--report                   # Generate report from existing artifacts
--input-dir PATH           # Input directory for report generation

# Configuration
--hash-algorithm [md5|sha1|sha256|sha512]  # Hash algorithm for integrity
--log-level [DEBUG|INFO|WARNING|ERROR]     # Logging level
--enable-analysis          # Enable automatic security analysis
--config-file PATH         # Custom configuration file

# Advanced Options
--max-files INTEGER        # Maximum files to process (default: 10000)
--date-from DATE           # Start date for filtering (YYYY-MM-DD)
--date-to DATE             # End date for filtering (YYYY-MM-DD)
--include-pattern TEXT     # File pattern to include
--exclude-pattern TEXT     # File pattern to exclude
```

### GUI Features

The graphical user interface provides:

- **Artifact Selection**: Checkboxes for all artifact types with basic/advanced categorization
- **Configuration Options**: Output directory, hash algorithms, logging levels
- **Real-time Command Display**: KAPE-like command line equivalent for GUI selections
- **Progress Monitoring**: Real-time progress bar and detailed logging
- **Report Generation**: Integrated report generation with multiple formats
- **Output Management**: Direct access to output folders and generated reports

## 📊 Output Structure

```
forensic_output/
├── registry/              # Registry artifacts
├── filesystem/            # File system artifacts
├── memory/                # Memory artifacts
├── network/               # Network artifacts
├── user_activity/         # User activity artifacts
├── evtx/                  # Windows Event Logs
├── prefetch/              # Prefetch files
├── shimcache/             # ShimCache data
├── amcache/               # Amcache data
├── pca/                   # PCA logs
├── muicache/              # MUICache data
├── userassist/            # UserAssist data
├── srum/                  # SRUM data
├── registry_asep/         # Registry ASEP data
├── volume_shadow_copies/  # Volume Shadow Copies
├── crash_dumps/           # Windows Crash Dumps
├── Analysis/              # Automatic analysis results
│   ├── automatic_analysis.json
│   ├── security_findings.json
│   ├── anomalies.json
│   ├── risk_assessment.json
│   ├── timeline_events.json
│   ├── investigation_recommendations.txt
│   └── evtx_analysis/
│       ├── evtx_analysis.json
│       ├── security_summary.json
│       ├── event_timeline.json
│       ├── anomalies.json
│       └── security_report.html
├── forensic_report.html   # Main forensic report
├── forensic_report.json   # JSON format report
└── extraction_metadata.json # Extraction metadata and hashes
```

## 🔍 Supported Artifacts

### Registry Artifacts
- **Registry Hives**: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, NTUSER.DAT, UsrClass.dat
- **Run Keys**: Startup programs and persistence mechanisms
- **Uninstall Information**: Installed software details
- **Network Settings**: Network configuration and connections
- **System Configuration**: Hardware and software settings
- **User Activity**: User interaction patterns and preferences

### File System Artifacts
- **Timeline Analysis**: File creation, modification, and access times
- **Metadata Extraction**: File attributes and properties
- **Recent Files**: Recently accessed files and documents
- **Startup Items**: Programs that start automatically
- **Temporary Files**: System and user temporary files
- **User Documents**: User document folders and contents

### Memory Artifacts
- **Process List**: Currently running processes with details
- **Network Connections**: Active network connections and ports
- **Loaded Modules**: DLLs and loaded libraries
- **Memory Dumps**: Full memory acquisition (if enabled)
- **Handle Information**: Open file handles and system objects

### Network Artifacts
- **Browser History**: Chrome, Firefox, Edge, Internet Explorer
- **Browser Cookies**: Session and tracking cookies
- **Browser Downloads**: Download history and file information
- **DNS Cache**: System DNS resolution cache
- **ARP Cache**: Network address resolution cache
- **Network Shares**: Shared folders and access information

### Windows Event Logs (EVTX)
- **Security Events**: Authentication, authorization, and security events
- **System Events**: System services and hardware events
- **Application Events**: Application errors and warnings
- **PowerShell Events**: PowerShell execution and script logging
- **Task Scheduler Events**: Scheduled task creation and execution
- **Windows Defender Events**: Antimalware detection and actions
- **Remote Desktop Events**: RDP connection and session events

### Advanced Execution Artifacts
- **Prefetch Files**: Application execution history and dependencies
- **ShimCache**: Registry-based execution evidence
- **Amcache**: Application compatibility database
- **PCA**: Program Compatibility Assistant logs
- **MUICache**: GUI application execution tracking
- **UserAssist**: User interaction with GUI applications
- **SRUM**: Detailed system resource usage and activity
- **Registry ASEP**: Auto-start extensibility points
- **Volume Shadow Copies**: System snapshots for deleted files
- **Windows Crash Dumps**: Application crash and error reporting

## 📈 Analysis Capabilities

### Automatic Security Analysis
- **Anomaly Detection**: High-frequency events, failed logons, unusual process creation
- **Risk Assessment**: Automated risk scoring (0-100) and threat level classification
- **Cross-Artifact Correlation**: Correlate findings across multiple artifact types
- **Timeline Analysis**: Chronological event timeline construction
- **Investigation Recommendations**: Actionable guidance for investigators

### Security Investigation Reports
- **Executive Summary**: High-level findings and risk assessment
- **Critical Events**: Important security events and their significance
- **Anomaly Detection**: Unusual patterns and behaviors
- **Timeline Events**: Chronological security event timeline
- **Investigation Recommendations**: Specific actions for investigators

## 🛡️ Forensic Best Practices

### Pre-Extraction
- **Documentation**: Record system state, time, and extraction parameters
- **Write Protection**: Use write-blocking when possible
- **Hash Verification**: Calculate and verify file hashes before and after extraction
- **Backup**: Create system backups if possible
- **Legal Authorization**: Ensure proper authorization for extraction

### During Extraction
- **Minimal Impact**: Use read-only operations when possible
- **Logging**: Enable comprehensive logging for audit trail
- **Monitoring**: Monitor system resources and extraction progress
- **Validation**: Verify extracted data integrity
- **Documentation**: Record any errors or anomalies

### Post-Extraction
- **Hash Verification**: Verify all extracted files
- **Report Generation**: Create comprehensive documentation
- **Evidence Preservation**: Secure and protect extracted data
- **Analysis**: Perform thorough analysis of findings
- **Documentation**: Document all findings and conclusions

## 📚 Documentation

- **[User Guide](docs/user_guide.html)**: Comprehensive HTML user guide with GUI snapshots
- **[Artifacts Reference](docs/ARTIFACTS_REFERENCE.md)**: Detailed artifact reference guide
- **[EVTX Analysis Features](EVTX_ANALYSIS_FEATURES.md)**: EVTX analysis capabilities
- **[Native Logs Integration](Native%20Logs/)**: Original artifact documentation

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/test_evtx_analyzer.py
pytest tests/test_registry_parser.py
pytest tests/test_filesystem_analyzer.py

# Run with coverage
pytest --cov=src tests/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Notice

This tool is designed for legitimate forensic and security investigations. Users must ensure they have proper authorization before conducting any forensic analysis. Always comply with local laws, regulations, and organizational policies.

## 🆘 Support

- **Documentation**: Check the [docs/](docs/) folder for comprehensive documentation
- **Issues**: Report bugs and issues on the project repository
- **Community**: Join the forensic analysis community forums
- **Training**: Attend digital forensics training courses

## 🔄 Version History

- **v2.0**: Enhanced GUI with KAPE-like command display, advanced artifacts from Native Logs, comprehensive documentation
- **v1.0**: Initial release with basic artifact extraction and analysis

---

**Windows Forensic Artifact Extractor v2.0** | For forensic and security professionals

Always follow proper forensic procedures and maintain chain of custody.
