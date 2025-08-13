#!/usr/bin/env python3
"""
Windows Forensic Artifact Extractor
Main entry point for the forensic application
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.extractor import ForensicExtractor
from src.gui.main_window import MainWindow
from src.utils.logger import get_logger


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Windows Forensic Artifact Extractor - Extract and analyze Windows artifacts for forensic investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
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

Advanced Artifacts (based on Native Logs):
  --prefetch              Extract Prefetch files (C:\\Windows\\Prefetch\\*.pf)
  --shimcache             Extract ShimCache/AppCompatCache registry data
  --amcache               Extract Amcache.hve application compatibility data
  --pca                   Extract PCA (Program Compatibility Assistant) logs
  --muicache              Extract MUICache from user registry hives
  --userassist            Extract UserAssist execution history
  --srum                  Extract SRUM (System Resource Usage Monitor) data
  --registry-asep         Extract Registry ASEP (Auto-Start Extensibility Points)
  --volume-shadow-copies  Extract Volume Shadow Copies (advanced)
  --crash-dumps           Extract Windows Crash Dumps/WER data (advanced)
        """
    )

    # Artifact selection arguments
    parser.add_argument('--extract-all', action='store_true',
                       help='Extract all available artifacts')
    parser.add_argument('--registry', action='store_true',
                       help='Extract registry artifacts')
    parser.add_argument('--filesystem', action='store_true',
                       help='Extract file system artifacts')
    parser.add_argument('--memory', action='store_true',
                       help='Extract memory artifacts')
    parser.add_argument('--network', action='store_true',
                       help='Extract network artifacts')
    parser.add_argument('--user-activity', action='store_true',
                       help='Extract user activity artifacts')
    parser.add_argument('--evtx', action='store_true',
                       help='Extract and analyze Windows Event Log (EVTX) artifacts')

    # Advanced artifact arguments (based on Native Logs)
    parser.add_argument('--prefetch', action='store_true',
                       help='Extract Prefetch files (execution history)')
    parser.add_argument('--shimcache', action='store_true',
                       help='Extract ShimCache/AppCompatCache registry data')
    parser.add_argument('--amcache', action='store_true',
                       help='Extract Amcache.hve application compatibility data')
    parser.add_argument('--pca', action='store_true',
                       help='Extract PCA (Program Compatibility Assistant) logs')
    parser.add_argument('--muicache', action='store_true',
                       help='Extract MUICache from user registry hives')
    parser.add_argument('--userassist', action='store_true',
                       help='Extract UserAssist execution history')
    parser.add_argument('--srum', action='store_true',
                       help='Extract SRUM (System Resource Usage Monitor) data')
    parser.add_argument('--registry-asep', action='store_true',
                       help='Extract Registry ASEP (Auto-Start Extensibility Points)')
    parser.add_argument('--volume-shadow-copies', action='store_true',
                       help='Extract Volume Shadow Copies (advanced)')
    parser.add_argument('--crash-dumps', action='store_true',
                       help='Extract Windows Crash Dumps/WER data (advanced)')

    # Output options
    parser.add_argument('--output-dir', type=str, default='./forensic_output',
                       help='Output directory for extracted artifacts')
    parser.add_argument('--output-report', type=str, default='./forensic_report.html',
                       help='Output path for generated report')
    parser.add_argument('--report', action='store_true',
                       help='Generate report from existing artifacts')
    parser.add_argument('--input-dir', type=str,
                       help='Input directory for report generation')

    # Configuration options
    parser.add_argument('--hash-algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'],
                       default='sha256', help='Hash algorithm for integrity verification')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level')
    parser.add_argument('--enable-analysis', action='store_true',
                       help='Enable automatic security analysis')
    parser.add_argument('--export-csv', action='store_true',
                       help='Export artifacts to CSV format for analyst readability')
    parser.add_argument('--config-file', type=str,
                       help='Custom configuration file path')

    # Advanced options
    parser.add_argument('--max-files', type=int, default=10000,
                       help='Maximum number of files to process')
    parser.add_argument('--date-from', type=str,
                       help='Start date for filtering (YYYY-MM-DD)')
    parser.add_argument('--date-to', type=str,
                       help='End date for filtering (YYYY-MM-DD)')
    parser.add_argument('--include-pattern', type=str,
                       help='File pattern to include')
    parser.add_argument('--exclude-pattern', type=str,
                       help='File pattern to exclude')

    # Interface options
    parser.add_argument('--gui', action='store_true',
                       help='Launch graphical user interface')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    # Setup logging
    logger = get_logger(__name__)
    import logging
    logger.setLevel(getattr(logging, args.log_level))

    # Launch GUI if requested
    if args.gui:
        logger.info("Launching GUI...")
        app = MainWindow()
        app.run()
        return

    # Validate arguments
    if not any([
        args.extract_all, args.registry, args.filesystem, args.memory,
        args.network, args.user_activity, args.evtx, args.prefetch,
        args.shimcache, args.amcache, args.pca, args.muicache,
        args.userassist, args.srum, args.registry_asep,
        args.volume_shadow_copies, args.crash_dumps, args.report
    ]):
        logger.error("No action specified. Use --help for usage information.")
        parser.print_help()
        sys.exit(1)

    try:
        # Initialize extractor
        extractor = ForensicExtractor()
        
        if args.report:
            # Generate report only
            if not args.input_dir:
                logger.error("--input-dir is required when using --report")
                sys.exit(1)
            
            logger.info("Generating forensic report")
            extractor.generate_report(Path(args.input_dir), args.output_report)
            logger.info(f"Report generated: {args.output_report}")
            
        else:
            # Extract artifacts
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting forensic extraction to: {output_dir}")
            
            # Extract based on arguments
            if args.extract_all:
                logger.info("Extracting all artifacts")
                extractor.extract_all_artifacts(output_dir)
                
                # Export to CSV if requested
                if args.export_csv:
                    logger.info("Exporting artifacts to CSV format...")
                    extractor.export_artifacts_to_csv(output_dir)
            else:
                # Extract individual artifacts
                if args.registry:
                    logger.info("Extracting registry artifacts")
                    extractor.extract_registry_artifacts(output_dir)
                
                if args.filesystem:
                    logger.info("Extracting file system artifacts")
                    extractor.extract_filesystem_artifacts(output_dir)
                
                if args.memory:
                    logger.info("Extracting memory artifacts")
                    extractor.extract_memory_artifacts(output_dir)
                
                if args.network:
                    logger.info("Extracting network artifacts")
                    extractor.extract_network_artifacts(output_dir)
                
                if args.user_activity:
                    logger.info("Extracting user activity artifacts")
                    extractor.extract_user_activity_artifacts(output_dir)
                
                if args.evtx:
                    logger.info("Extracting EVTX artifacts")
                    extractor.extract_evtx_artifacts(output_dir)
                
                # Extract advanced artifacts (based on Native Logs)
                if args.prefetch:
                    logger.info("Extracting Prefetch files")
                    extractor.extract_prefetch_artifacts(output_dir)
                
                if args.shimcache:
                    logger.info("Extracting ShimCache/AppCompatCache data")
                    extractor.extract_shimcache_artifacts(output_dir)
                
                if args.amcache:
                    logger.info("Extracting Amcache data")
                    extractor.extract_amcache_artifacts(output_dir)
                
                if args.pca:
                    logger.info("Extracting PCA (Program Compatibility Assistant) data")
                    extractor.extract_pca_artifacts(output_dir)
                
                if args.muicache:
                    logger.info("Extracting MUICache data")
                    extractor.extract_muicache_artifacts(output_dir)
                
                if args.userassist:
                    logger.info("Extracting UserAssist data")
                    extractor.extract_userassist_artifacts(output_dir)
                
                if args.srum:
                    logger.info("Extracting SRUM data")
                    extractor.extract_srum_artifacts(output_dir)
                
                if args.registry_asep:
                    logger.info("Extracting Registry ASEP data")
                    extractor.extract_registry_asep_artifacts(output_dir)
                
                if args.volume_shadow_copies:
                    logger.info("Extracting Volume Shadow Copies")
                    extractor.extract_volume_shadow_copies(output_dir)
                
                if args.crash_dumps:
                    logger.info("Extracting Windows Crash Dumps")
                    extractor.extract_crash_dumps(output_dir)
            
            # Generate report
            logger.info("Generating forensic report")
            extractor.generate_report(output_dir, args.output_report)
            logger.info(f"Report generated: {args.output_report}")
            
            logger.info("Forensic extraction completed successfully!")
            
    except KeyboardInterrupt:
        logger.info("Extraction interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during extraction: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
