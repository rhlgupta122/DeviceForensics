# EVTX Analysis Features - Windows Forensic Artifact Extractor

## Overview

This document describes the new Windows Event Log (EVTX) analysis capabilities added to the Windows Forensic Artifact Extractor. These features provide comprehensive analysis of Windows Event Logs for security investigation purposes.

## New Features

### 1. EVTX File Analysis
- **Automatic Discovery**: Automatically finds EVTX files in standard Windows locations:
  - `C:\Windows\System32\winevt\Logs`
  - `C:\Windows\System32\config`
  - `C:\Windows\System32\winevt\Logs\Archive`

- **File Processing**: 
  - Copies EVTX files to output directory for preservation
  - Calculates SHA256 hashes for integrity verification
  - Extracts metadata (size, modification time, etc.)

### 2. Security Event Analysis
The analyzer focuses on critical security event IDs:

#### Authentication Events
- **4624**: Successful logon
- **4625**: Failed logon (critical for brute force detection)
- **4634**: Account logoff
- **4647**: User initiated logoff
- **4648**: Explicit credential logon
- **4778**: Session reconnected
- **4779**: Session disconnected

#### Account Management
- **4720**: Account created
- **4722**: Account enabled
- **4723**: Account disabled
- **4724**: Password change attempt
- **4725**: Account locked out
- **4726**: Account deleted
- **4728**: Member added to security group
- **4729**: Member removed from security group
- **4738**: User account changed
- **4740**: User account locked out
- **4767**: User account unlocked

#### Process and Service Events
- **4688**: Process creation
- **4697**: Service installation
- **4698**: Scheduled task created
- **4699**: Scheduled task deleted
- **4700**: Scheduled task enabled
- **4701**: Scheduled task disabled
- **4702**: Scheduled task updated

#### Network and Firewall Events
- **5152**: Windows Filtering Platform blocked a packet
- **5153**: Windows Filtering Platform blocked a connection
- **5154**: Windows Filtering Platform permitted an application to listen on a port
- **5155**: Windows Filtering Platform blocked an application from listening on a port
- **5156**: Windows Filtering Platform allowed a connection
- **5157**: Windows Filtering Platform blocked a connection

#### PowerShell Events
- **4103**: PowerShell command executed
- **4104**: PowerShell script executed
- **4105**: PowerShell script block executed
- **4106**: PowerShell script block logged
- **4107**: PowerShell script block execution started
- **4108**: PowerShell script block execution finished

#### Windows Defender Events
- **1116**: Windows Defender threat detected
- **1117**: Windows Defender threat quarantined
- **1118**: Windows Defender threat removed
- **1119**: Windows Defender threat restored
- **1120**: Windows Defender threat allowed
- **1121**: Windows Defender threat blocked

### 3. Anomaly Detection
The system automatically detects various anomalies:

#### High-Frequency Events
- Detects when more than 100 events occur in a single hour
- Identifies potential system stress or attack patterns

#### Failed Logon Attempts
- Flags when more than 10 failed logon attempts are detected
- Indicates potential brute force attacks

#### Unusual Process Creation
- Identifies processes that are created unusually frequently
- Threshold: More than 50 instances of the same process

### 4. Analysis Output Structure
All analysis results are organized in the "Analysis" folder:

```
Analysis/
├── evtx_analysis.json              # Complete analysis results
├── security_summary.json           # Security events summary
├── event_timeline.json             # Chronological event timeline
├── anomalies.json                  # Detected anomalies
└── security_investigation_report.html  # Security-focused report
```

### 5. Security Investigation Report
Generates a comprehensive HTML report including:

#### Executive Summary
- Total events analyzed
- Number of security-relevant events
- Number of anomalies detected

#### Critical Security Events
- Table of important event IDs with counts
- Risk level assessment (HIGH/MEDIUM/LOW)

#### Detected Anomalies
- List of all detected anomalies
- Detailed descriptions and counts

#### Recent Security Events
- Events from the last 24 hours
- Focused on recent activity

#### Investigation Recommendations
- Specific recommendations based on findings
- Actionable guidance for investigators

### 6. Integration with Main Application

#### Command Line Usage
```bash
# Extract and analyze EVTX files only
python main.py --evtx --output-dir ./evtx_analysis

# Extract all artifacts including EVTX
python main.py --extract-all --output-dir ./forensic_output

# Extract specific artifacts with EVTX
python main.py --registry --filesystem --evtx --output-dir ./output
```

#### GUI Integration
- New checkbox for "Windows Event Log (EVTX) Artifacts"
- Integrated into the main extraction workflow
- Results appear in the comprehensive report

### 7. Automatic Analysis Integration
The EVTX analysis is integrated into the automatic analysis system:

#### Cross-Artifact Analysis
- EVTX data is combined with registry, network, and user activity analysis
- Provides comprehensive security assessment

#### Risk Assessment
- Calculates overall risk score based on all findings
- Assigns risk levels (LOW/MEDIUM/HIGH)

#### Investigation Recommendations
- Generates specific recommendations based on EVTX findings
- Provides actionable guidance for security investigators

## Technical Implementation

### Dependencies
- `evtx>=0.8.0`: Core EVTX parsing library
- `python-evtx>=0.7.4`: Alternative EVTX parser

### Key Classes
- `EVTXAnalyzer`: Main analysis engine
- Integrated into `ForensicExtractor` for seamless operation

### Error Handling
- Graceful handling of missing EVTX files
- Robust error recovery for corrupted files
- Comprehensive logging of all operations

## Usage Examples

### Basic EVTX Analysis
```python
from src.core.evtx_analyzer import EVTXAnalyzer

analyzer = EVTXAnalyzer()
results = analyzer.analyze_evtx_directory(
    evtx_dir=Path("C:/Windows/System32/winevt/Logs"),
    output_dir=Path("./output")
)
```

### Security Report Generation
```python
report_path = analyzer.generate_security_report(results, Path("./output"))
print(f"Security report generated: {report_path}")
```

## Forensic Best Practices

1. **Evidence Preservation**: EVTX files are copied to preserve original evidence
2. **Hash Verification**: SHA256 hashes calculated for integrity
3. **Comprehensive Logging**: All operations logged for audit trail
4. **Analysis Documentation**: All findings documented in structured format
5. **Timeline Analysis**: Events organized chronologically for investigation

## Future Enhancements

1. **Machine Learning**: Advanced anomaly detection using ML models
2. **Threat Intelligence**: Integration with threat intelligence feeds
3. **Real-time Analysis**: Live monitoring capabilities
4. **Advanced Correlation**: Cross-system event correlation
5. **Custom Event Rules**: User-defined event analysis rules

## Conclusion

The EVTX analysis features provide investigators with powerful tools for analyzing Windows Event Logs. The automatic detection of security events, anomalies, and generation of investigation recommendations significantly enhances the forensic analysis capabilities of the tool.

The integration with the existing forensic framework ensures that EVTX analysis is part of a comprehensive investigation workflow, providing investigators with a complete picture of system activity and security events.
