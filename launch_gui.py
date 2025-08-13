#!/usr/bin/env python3
"""
Windows Forensic Artifact Extractor - GUI Launcher
Simple script to launch the graphical user interface
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Launch the GUI application"""
    try:
        from src.gui.main_window import MainWindow
        
        print("🔍 Windows Forensic Artifact Extractor v2.0")
        print("Launching GUI...")
        print("=" * 50)
        
        # Launch GUI
        app = MainWindow()
        app.run()
        
    except ImportError as e:
        print(f"❌ Error importing required modules: {e}")
        print("Please ensure all dependencies are installed:")
        print("pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error launching GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
