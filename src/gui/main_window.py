"""
Main GUI Window for Windows Forensic Artifact Extractor
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path
import json
import os

from ..core.extractor import ForensicExtractor
from ..utils.logger import get_logger


class MainWindow:
    """Main application window with KAPE-like command line display"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Windows Forensic Artifact Extractor v2.0")
        self.root.geometry("1200x900")
        self.root.configure(bg='#f0f0f0')
        
        # Make window resizable
        self.root.minsize(1000, 700)
        
        # Initialize components
        self.extractor = ForensicExtractor()
        self.logger = get_logger(__name__)
        
        # Variables for artifact selection
        self.registry_var = tk.BooleanVar(value=True)
        self.filesystem_var = tk.BooleanVar(value=True)
        self.memory_var = tk.BooleanVar(value=True)
        self.network_var = tk.BooleanVar(value=True)
        self.user_activity_var = tk.BooleanVar(value=True)
        self.evtx_var = tk.BooleanVar(value=True)
        
        # Advanced artifact variables (based on Native Logs)
        self.prefetch_var = tk.BooleanVar(value=True)
        self.shimcache_var = tk.BooleanVar(value=True)
        self.amcache_var = tk.BooleanVar(value=True)
        self.pca_var = tk.BooleanVar(value=True)
        self.muicache_var = tk.BooleanVar(value=True)
        self.userassist_var = tk.BooleanVar(value=True)
        self.srum_var = tk.BooleanVar(value=True)
        self.vsc_var = tk.BooleanVar(value=False)
        self.crash_dumps_var = tk.BooleanVar(value=False)
        self.registry_asep_var = tk.BooleanVar(value=True)
        
        # Configuration variables
        self.output_dir_var = tk.StringVar(value="./forensic_output")
        self.hash_algorithm_var = tk.StringVar(value="sha256")
        self.log_level_var = tk.StringVar(value="INFO")
        self.enable_analysis_var = tk.BooleanVar(value=True)
        self.export_csv_var = tk.BooleanVar(value=True)
        self.max_files_var = tk.IntVar(value=10000)
        
        # Command line display
        self.cli_display_var = tk.StringVar()
        
        self._setup_ui()
        self._update_cli_display()
        
    def _setup_ui(self):
        """Setup the user interface with scrollable canvas"""
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Create main canvas with scrollbar
        canvas = tk.Canvas(self.root, bg='#f0f0f0')
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Configure grid weights for scrollable frame
        scrollable_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(scrollable_frame, text="🔍 Windows Forensic Artifact Extractor", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Artifacts selection frame
        self._create_artifacts_frame(scrollable_frame)
        
        # Configuration frame
        self._create_config_frame(scrollable_frame)
        
        # Export options frame
        self._create_export_frame(scrollable_frame)
        
        # Command line display frame (KAPE-like)
        self._create_cli_display_frame(scrollable_frame)
        
        # Control buttons frame
        self._create_control_frame(scrollable_frame)
        
        # Progress and log frame
        self._create_progress_frame(scrollable_frame)
        
        # Bind mouse wheel to canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
    def _create_artifacts_frame(self, parent):
        """Create artifacts selection frame"""
        artifacts_frame = ttk.LabelFrame(parent, text="📁 Artifact Selection", padding="15")
        artifacts_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        artifacts_frame.columnconfigure(1, weight=1)
        artifacts_frame.columnconfigure(2, weight=1)
        artifacts_frame.columnconfigure(3, weight=1)
        
        # Basic artifacts
        basic_label = ttk.Label(artifacts_frame, text="Basic Artifacts:", font=('Arial', 11, 'bold'))
        basic_label.grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 15))
        
        self.registry_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Registry Artifacts", 
            variable=self.registry_var,
            command=self._update_cli_display
        )
        self.registry_check.grid(row=1, column=0, sticky=tk.W, padx=(20, 10))
        
        self.filesystem_check = ttk.Checkbutton(
            artifacts_frame, 
            text="File System Artifacts", 
            variable=self.filesystem_var,
            command=self._update_cli_display
        )
        self.filesystem_check.grid(row=1, column=1, sticky=tk.W, padx=(10, 10))
        
        self.memory_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Memory Artifacts", 
            variable=self.memory_var,
            command=self._update_cli_display
        )
        self.memory_check.grid(row=1, column=2, sticky=tk.W, padx=(10, 10))
        
        self.network_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Network Artifacts", 
            variable=self.network_var,
            command=self._update_cli_display
        )
        self.network_check.grid(row=1, column=3, sticky=tk.W, padx=(10, 10))
        
        self.user_activity_check = ttk.Checkbutton(
            artifacts_frame, 
            text="User Activity Artifacts", 
            variable=self.user_activity_var,
            command=self._update_cli_display
        )
        self.user_activity_check.grid(row=2, column=0, sticky=tk.W, padx=(20, 10))
        
        self.evtx_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Windows Event Log (EVTX) Artifacts", 
            variable=self.evtx_var,
            command=self._update_cli_display
        )
        self.evtx_check.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=(10, 10))
        
        # Advanced artifacts (based on Native Logs)
        advanced_label = ttk.Label(artifacts_frame, text="Advanced Execution Artifacts:", font=('Arial', 11, 'bold'))
        advanced_label.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=(25, 15))
        
        # Row 1 of advanced artifacts
        self.prefetch_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Prefetch Files", 
            variable=self.prefetch_var,
            command=self._update_cli_display
        )
        self.prefetch_check.grid(row=4, column=0, sticky=tk.W, padx=(20, 10))
        
        self.shimcache_check = ttk.Checkbutton(
            artifacts_frame, 
            text="ShimCache (AppCompatCache)", 
            variable=self.shimcache_var,
            command=self._update_cli_display
        )
        self.shimcache_check.grid(row=4, column=1, sticky=tk.W, padx=(10, 10))
        
        self.amcache_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Amcache", 
            variable=self.amcache_var,
            command=self._update_cli_display
        )
        self.amcache_check.grid(row=4, column=2, sticky=tk.W, padx=(10, 10))
        
        self.pca_check = ttk.Checkbutton(
            artifacts_frame, 
            text="PCA (Program Compatibility Assistant)", 
            variable=self.pca_var,
            command=self._update_cli_display
        )
        self.pca_check.grid(row=4, column=3, sticky=tk.W, padx=(10, 10))
        
        # Row 2 of advanced artifacts
        self.muicache_check = ttk.Checkbutton(
            artifacts_frame, 
            text="MUICache", 
            variable=self.muicache_var,
            command=self._update_cli_display
        )
        self.muicache_check.grid(row=5, column=0, sticky=tk.W, padx=(20, 10))
        
        self.userassist_check = ttk.Checkbutton(
            artifacts_frame, 
            text="UserAssist", 
            variable=self.userassist_var,
            command=self._update_cli_display
        )
        self.userassist_check.grid(row=5, column=1, sticky=tk.W, padx=(10, 10))
        
        self.srum_check = ttk.Checkbutton(
            artifacts_frame, 
            text="SRUM (System Resource Usage Monitor)", 
            variable=self.srum_var,
            command=self._update_cli_display
        )
        self.srum_check.grid(row=5, column=2, sticky=tk.W, padx=(10, 10))
        
        self.registry_asep_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Registry ASEP (Auto-Start Extensibility Points)", 
            variable=self.registry_asep_var,
            command=self._update_cli_display
        )
        self.registry_asep_check.grid(row=5, column=3, sticky=tk.W, padx=(10, 10))
        
        # Row 3 of advanced artifacts (optional/advanced)
        self.vsc_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Volume Shadow Copies (Advanced)", 
            variable=self.vsc_var,
            command=self._update_cli_display
        )
        self.vsc_check.grid(row=6, column=0, sticky=tk.W, padx=(20, 10))
        
        self.crash_dumps_check = ttk.Checkbutton(
            artifacts_frame, 
            text="Windows Crash Dumps (Advanced)", 
            variable=self.crash_dumps_var,
            command=self._update_cli_display
        )
        self.crash_dumps_check.grid(row=6, column=1, sticky=tk.W, padx=(10, 10))
        
        # Select all/none buttons
        select_frame = ttk.Frame(artifacts_frame)
        select_frame.grid(row=7, column=0, columnspan=4, pady=(25, 0))
        
        select_all_btn = ttk.Button(select_frame, text="Select All", command=self._select_all_artifacts)
        select_all_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        select_none_btn = ttk.Button(select_frame, text="Select None", command=self._select_none_artifacts)
        select_none_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        select_basic_btn = ttk.Button(select_frame, text="Select Basic Only", command=self._select_basic_artifacts)
        select_basic_btn.pack(side=tk.LEFT)
        
    def _create_config_frame(self, parent):
        """Create configuration frame"""
        config_frame = ttk.LabelFrame(parent, text="⚙️ Configuration", padding="15")
        config_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))
        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(3, weight=1)
        
        # Output directory
        ttk.Label(config_frame, text="Output Directory:", font=('Arial', 9, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        output_entry = ttk.Entry(config_frame, textvariable=self.output_dir_var, width=60)
        output_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=(0, 10))
        output_btn = ttk.Button(config_frame, text="Browse", command=self._browse_output_dir)
        output_btn.grid(row=0, column=3)
        
        # Row 2: Hash algorithm and Log level
        ttk.Label(config_frame, text="Hash Algorithm:", font=('Arial', 9, 'bold')).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(15, 0))
        hash_combo = ttk.Combobox(config_frame, textvariable=self.hash_algorithm_var, 
                                 values=["md5", "sha1", "sha256", "sha512"], state="readonly", width=20)
        hash_combo.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(15, 0))
        hash_combo.bind('<<ComboboxSelected>>', lambda e: self._update_cli_display())
        
        ttk.Label(config_frame, text="Log Level:", font=('Arial', 9, 'bold')).grid(row=1, column=2, sticky=tk.W, padx=(0, 10), pady=(15, 0))
        log_combo = ttk.Combobox(config_frame, textvariable=self.log_level_var, 
                                values=["DEBUG", "INFO", "WARNING", "ERROR"], state="readonly", width=20)
        log_combo.grid(row=1, column=3, sticky=tk.W, pady=(15, 0))
        log_combo.bind('<<ComboboxSelected>>', lambda e: self._update_cli_display())
        
        # Row 3: Max Files and Analysis
        ttk.Label(config_frame, text="Max Files:", font=('Arial', 9, 'bold')).grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(15, 0))
        max_files_spin = ttk.Spinbox(config_frame, from_=1000, to=100000, increment=1000, 
                                   textvariable=self.max_files_var, width=20)
        max_files_spin.grid(row=2, column=1, sticky=tk.W, padx=(0, 20), pady=(15, 0))
        max_files_spin.bind('<KeyRelease>', lambda e: self._update_cli_display())
        
        # Enable analysis
        analysis_check = ttk.Checkbutton(
            config_frame, 
            text="Enable Automatic Analysis", 
            variable=self.enable_analysis_var,
            command=self._update_cli_display
        )
        analysis_check.grid(row=2, column=2, columnspan=2, sticky=tk.W, padx=(0, 0), pady=(15, 0))
    
    def _create_export_frame(self, parent):
        """Create export options frame"""
        export_frame = ttk.LabelFrame(parent, text="📊 Export Options", padding="10")
        export_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # CSV export checkbox
        csv_check = ttk.Checkbutton(
            export_frame, 
            text="Export to CSV Format (for analyst readability)", 
            variable=self.export_csv_var,
            command=self._update_cli_display
        )
        csv_check.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        # Export format info
        format_info = ttk.Label(export_frame, text="CSV files will be created in a 'csv_exports' subdirectory", 
                               font=('Arial', 8), foreground='gray')
        format_info.grid(row=1, column=0, sticky=tk.W, padx=(20, 0), pady=(5, 0))
        
    def _create_cli_display_frame(self, parent):
        """Create KAPE-like command line display frame"""
        cli_frame = ttk.LabelFrame(parent, text="💻 Command Line Equivalent (KAPE-style)", padding="10")
        cli_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        cli_frame.columnconfigure(0, weight=1)
        
        # Command display
        cli_display = tk.Text(cli_frame, height=6, bg='#1e1e1e', fg='#00ff00', 
                             font=('Consolas', 10), wrap=tk.WORD, state=tk.DISABLED)
        cli_display.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Scrollbar for command display
        cli_scrollbar = ttk.Scrollbar(cli_frame, orient=tk.VERTICAL, command=cli_display.yview)
        cli_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        cli_display.configure(yscrollcommand=cli_scrollbar.set)
        
        # Copy command button
        copy_btn = ttk.Button(cli_frame, text="📋 Copy Command", command=self._copy_cli_command)
        copy_btn.grid(row=1, column=0, sticky=tk.W)
        
        # Save command to file button
        save_btn = ttk.Button(cli_frame, text="💾 Save Command to File", command=self._save_cli_command)
        save_btn.grid(row=1, column=0, sticky=tk.E)
        
        self.cli_display = cli_display
        
    def _create_control_frame(self, parent):
        """Create control buttons frame"""
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=5, column=0, columnspan=3, pady=(0, 10))
        
        # Extract button
        extract_btn = ttk.Button(control_frame, text="🚀 Start Extraction", 
                                command=self._start_extraction, style='Accent.TButton')
        extract_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Stop button
        stop_btn = ttk.Button(control_frame, text="⏹️ Stop", command=self._stop_extraction)
        stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Open output folder button
        open_btn = ttk.Button(control_frame, text="📁 Open Output Folder", command=self._open_output_folder)
        open_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Generate report only button
        report_btn = ttk.Button(control_frame, text="📊 Generate Report Only", command=self._generate_report_only)
        report_btn.pack(side=tk.LEFT)
        
    def _create_progress_frame(self, parent):
        """Create progress and log frame"""
        progress_frame = ttk.LabelFrame(parent, text="📈 Progress & Logs", padding="10")
        progress_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        progress_frame.rowconfigure(1, weight=1)
        parent.rowconfigure(5, weight=1)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Progress label
        self.progress_label = ttk.Label(progress_frame, text="Ready to start extraction...")
        self.progress_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 10))
        
        # Log display
        log_frame = ttk.Frame(progress_frame)
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_display = scrolledtext.ScrolledText(log_frame, height=10, bg='#f8f9fa', 
                                                   font=('Consolas', 9), wrap=tk.WORD)
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Log control buttons
        log_control_frame = ttk.Frame(progress_frame)
        log_control_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        clear_log_btn = ttk.Button(log_control_frame, text="Clear Log", command=self._clear_log)
        clear_log_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        save_log_btn = ttk.Button(log_control_frame, text="Save Log", command=self._save_log)
        save_log_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        auto_scroll_var = tk.BooleanVar(value=True)
        auto_scroll_check = ttk.Checkbutton(log_control_frame, text="Auto-scroll", variable=auto_scroll_var)
        auto_scroll_check.pack(side=tk.LEFT)
        
        self.auto_scroll_var = auto_scroll_var
        
    def _update_cli_display(self):
        """Update the command line display based on current selections"""
        cmd_parts = ["python main.py"]
        
        # Add artifact flags
        if self.registry_var.get():
            cmd_parts.append("--registry")
        if self.filesystem_var.get():
            cmd_parts.append("--filesystem")
        if self.memory_var.get():
            cmd_parts.append("--memory")
        if self.network_var.get():
            cmd_parts.append("--network")
        if self.user_activity_var.get():
            cmd_parts.append("--user-activity")
        if self.evtx_var.get():
            cmd_parts.append("--evtx")
        
        # Add advanced artifact flags
        if self.prefetch_var.get():
            cmd_parts.append("--prefetch")
        if self.shimcache_var.get():
            cmd_parts.append("--shimcache")
        if self.amcache_var.get():
            cmd_parts.append("--amcache")
        if self.pca_var.get():
            cmd_parts.append("--pca")
        if self.muicache_var.get():
            cmd_parts.append("--muicache")
        if self.userassist_var.get():
            cmd_parts.append("--userassist")
        if self.srum_var.get():
            cmd_parts.append("--srum")
        if self.registry_asep_var.get():
            cmd_parts.append("--registry-asep")
        if self.vsc_var.get():
            cmd_parts.append("--volume-shadow-copies")
        if self.crash_dumps_var.get():
            cmd_parts.append("--crash-dumps")
        
        # Add output directory
        output_dir = self.output_dir_var.get()
        if output_dir:
            cmd_parts.append(f'--output-dir "{output_dir}"')
        
        # Add configuration options
        cmd_parts.append(f"--hash-algorithm {self.hash_algorithm_var.get()}")
        cmd_parts.append(f"--log-level {self.log_level_var.get()}")
        
        if self.enable_analysis_var.get():
            cmd_parts.append("--enable-analysis")
        
        if self.export_csv_var.get():
            cmd_parts.append("--export-csv")
        
        if self.max_files_var.get() != 10000:
            cmd_parts.append(f"--max-files {self.max_files_var.get()}")
        
        # Format command
        command = " ".join(cmd_parts)
        
        # Update display
        self.cli_display.config(state=tk.NORMAL)
        self.cli_display.delete(1.0, tk.END)
        self.cli_display.insert(1.0, f"# Command Line Equivalent for Current GUI Selection:\n{command}")
        self.cli_display.config(state=tk.DISABLED)
        
    def _select_all_artifacts(self):
        """Select all artifacts"""
        self.registry_var.set(True)
        self.filesystem_var.set(True)
        self.memory_var.set(True)
        self.network_var.set(True)
        self.user_activity_var.set(True)
        self.evtx_var.set(True)
        self.prefetch_var.set(True)
        self.shimcache_var.set(True)
        self.amcache_var.set(True)
        self.pca_var.set(True)
        self.muicache_var.set(True)
        self.userassist_var.set(True)
        self.srum_var.set(True)
        self.registry_asep_var.set(True)
        self.vsc_var.set(True)
        self.crash_dumps_var.set(True)
        self._update_cli_display()
        
    def _select_none_artifacts(self):
        """Select no artifacts"""
        self.registry_var.set(False)
        self.filesystem_var.set(False)
        self.memory_var.set(False)
        self.network_var.set(False)
        self.user_activity_var.set(False)
        self.evtx_var.set(False)
        self.prefetch_var.set(False)
        self.shimcache_var.set(False)
        self.amcache_var.set(False)
        self.pca_var.set(False)
        self.muicache_var.set(False)
        self.userassist_var.set(False)
        self.srum_var.set(False)
        self.registry_asep_var.set(False)
        self.vsc_var.set(False)
        self.crash_dumps_var.set(False)
        self._update_cli_display()
        
    def _select_basic_artifacts(self):
        """Select only basic artifacts"""
        self.registry_var.set(True)
        self.filesystem_var.set(True)
        self.memory_var.set(True)
        self.network_var.set(True)
        self.user_activity_var.set(True)
        self.evtx_var.set(True)
        # Unselect advanced artifacts
        self.prefetch_var.set(False)
        self.shimcache_var.set(False)
        self.amcache_var.set(False)
        self.pca_var.set(False)
        self.muicache_var.set(False)
        self.userassist_var.set(False)
        self.srum_var.set(False)
        self.registry_asep_var.set(False)
        self.vsc_var.set(False)
        self.crash_dumps_var.set(False)
        self._update_cli_display()
        
    def _browse_output_dir(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(initialdir=self.output_dir_var.get())
        if directory:
            self.output_dir_var.set(directory)
            self._update_cli_display()
            
    def _copy_cli_command(self):
        """Copy command line to clipboard"""
        command = self.cli_display.get(1.0, tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(command)
        messagebox.showinfo("Copied", "Command copied to clipboard!")
        
    def _save_cli_command(self):
        """Save command line to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".bat",
            filetypes=[("Batch files", "*.bat"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            command = self.cli_display.get(1.0, tk.END).strip()
            with open(filename, 'w') as f:
                f.write(command)
            messagebox.showinfo("Saved", f"Command saved to {filename}")
            
    def _start_extraction(self):
        """Start the extraction process"""
        # Validate selections
        if not any([
            self.registry_var.get(),
            self.filesystem_var.get(),
            self.memory_var.get(),
            self.network_var.get(),
            self.user_activity_var.get(),
            self.evtx_var.get(),
            self.prefetch_var.get(),
            self.shimcache_var.get(),
            self.amcache_var.get(),
            self.pca_var.get(),
            self.muicache_var.get(),
            self.userassist_var.get(),
            self.srum_var.get(),
            self.registry_asep_var.get(),
            self.vsc_var.get(),
            self.crash_dumps_var.get()
        ]):
            messagebox.showwarning("Warning", "Please select at least one artifact type!")
            return
            
        # Validate output directory
        output_path = Path(self.output_dir_var.get())
        if not output_path.parent.exists():
            messagebox.showerror("Error", "Invalid output directory!")
            return
            
        # Start extraction in separate thread
        self.extraction_thread = threading.Thread(target=self._extraction_worker, daemon=True)
        self.extraction_thread.start()
        
    def _extraction_worker(self):
        """Worker thread for extraction"""
        try:
            output_path = Path(self.output_dir_var.get())
            output_path.mkdir(exist_ok=True)
            
            # Update progress
            self.progress_var.set(0)
            self.progress_label.config(text="Starting extraction...")
            self._log_message("🚀 Starting forensic artifact extraction...")
            
            # Extract artifacts based on selection
            extract_all = all([
                self.registry_var.get(),
                self.filesystem_var.get(),
                self.memory_var.get(),
                self.network_var.get(),
                self.user_activity_var.get(),
                self.evtx_var.get()
            ])
            
            if extract_all:
                self._log_message("📁 Extracting all artifacts...")
                self.extractor.extract_all_artifacts(output_path)
            else:
                # Extract individual artifacts
                if self.registry_var.get():
                    self._log_message("🔧 Extracting registry artifacts...")
                    self.extractor.extract_registry_artifacts(output_path)
                    self.progress_var.set(20)
                    
                if self.filesystem_var.get():
                    self._log_message("📂 Extracting file system artifacts...")
                    self.extractor.extract_filesystem_artifacts(output_path)
                    self.progress_var.set(40)
                    
                if self.memory_var.get():
                    self._log_message("🧠 Extracting memory artifacts...")
                    self.extractor.extract_memory_artifacts(output_path)
                    self.progress_var.set(60)
                    
                if self.network_var.get():
                    self._log_message("🌐 Extracting network artifacts...")
                    self.extractor.extract_network_artifacts(output_path)
                    self.progress_var.set(80)
                    
                if self.user_activity_var.get():
                    self._log_message("👤 Extracting user activity artifacts...")
                    self.extractor.extract_user_activity_artifacts(output_path)
                    self.progress_var.set(90)
                
                if self.evtx_var.get():
                    self._log_message("📋 Extracting EVTX artifacts...")
                    self.extractor.extract_evtx_artifacts(output_path)
                    self.progress_var.set(95)
            
            # Generate report
            self._log_message("📊 Generating forensic report...")
            report_path = output_path / "forensic_report.html"
            self.extractor.generate_report(output_path, str(report_path))
            
            # Export to CSV if requested
            if self.export_csv_var.get():
                self._log_message("📊 Exporting artifacts to CSV format...")
                self.extractor.export_artifacts_to_csv(output_path)
            
            self.progress_var.set(100)
            self.progress_label.config(text="Extraction completed successfully!")
            self._log_message("✅ Extraction completed successfully!")
            self._log_message(f"📁 Output directory: {output_path}")
            self._log_message(f"📊 Report generated: {report_path}")
            
            messagebox.showinfo("Success", f"Extraction completed!\nOutput: {output_path}\nReport: {report_path}")
            
        except Exception as e:
            self._log_message(f"❌ Error during extraction: {str(e)}")
            self.progress_label.config(text="Extraction failed!")
            messagebox.showerror("Error", f"Extraction failed: {str(e)}")
            
    def _stop_extraction(self):
        """Stop the extraction process"""
        # This would need to be implemented with proper thread control
        self._log_message("⏹️ Stop requested (not yet implemented)")
        
    def _open_output_folder(self):
        """Open the output folder in file explorer"""
        output_path = Path(self.output_dir_var.get())
        if output_path.exists():
            os.startfile(str(output_path))
        else:
            messagebox.showwarning("Warning", "Output directory does not exist yet!")
            
    def _generate_report_only(self):
        """Generate report from existing artifacts"""
        input_dir = filedialog.askdirectory(title="Select artifacts directory")
        if input_dir:
            output_report = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
                title="Save report as"
            )
            if output_report:
                try:
                    self.extractor.generate_report(Path(input_dir), output_report)
                    messagebox.showinfo("Success", f"Report generated: {output_report}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
                    
    def _log_message(self, message):
        """Add message to log display"""
        self.log_display.insert(tk.END, f"{message}\n")
        if self.auto_scroll_var.get():
            self.log_display.see(tk.END)
            
    def _clear_log(self):
        """Clear the log display"""
        self.log_display.delete(1.0, tk.END)
        
    def _save_log(self):
        """Save log to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            log_content = self.log_display.get(1.0, tk.END)
            with open(filename, 'w') as f:
                f.write(log_content)
            messagebox.showinfo("Saved", f"Log saved to {filename}")
            
    def run(self):
        """Run the GUI application"""
        self.root.mainloop()
