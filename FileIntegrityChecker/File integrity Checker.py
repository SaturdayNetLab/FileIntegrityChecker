import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import hashlib
import os
import threading
import queue

# --- Configuration & Hashing Logic ---

THEMES = {
    "light": {
        "bg": "#f0f0f0", "fg": "#333333", "accent": "#0078D4", "entry_bg": "white", "entry_fg": "black",
        "hash_fg": "#006400", "match_fg": "#28a744", "mismatch_fg": "#dc3545", "default_path_fg": "gray",
        "separator": "#cccccc", "frame_bg": "#ffffff"
    },
    "dark": {
        "bg": "#2e2e2e", "fg": "#e0e0e0", "accent": "#4a90e2", "entry_bg": "#444444", "entry_fg": "white",
        "hash_fg": "#00FF00", "match_fg": "#00FF00", "mismatch_fg": "#FF6666", "default_path_fg": "#AAAAAA",
        "separator": "#555555", "frame_bg": "#3c3c3c"
    },
}

result_queue = queue.Queue()

# --- Worker Functions ---

def calculate_single_file_hashes(filepath, algorithms):
    """Calculates hashes for a single file and sends progress updates."""
    hasher = {alg: hashlib.new(alg) for alg in algorithms}
    
    # Handle files that might be deleted during calculation
    try:
        file_size = os.path.getsize(filepath)
    except FileNotFoundError:
        return {"Error": "File not found or inaccessible."}
        
    bytes_read = 0
    
    try:
        with open(filepath, "rb") as f:
            while True:
                # Read chunks efficiently (64 KB)
                chunk = f.read(4096 * 16)
                if not chunk: break
                for h in hasher.values(): h.update(chunk)
                bytes_read += len(chunk)
                
                # Only send progress updates for files larger than 5 MB to prevent UI lag
                if file_size > 1024 * 1024 * 5:
                    result_queue.put({"status": "progress", "value": bytes_read, "maximum": file_size})
    except Exception as e:
         return {"Error": f"Reading file failed: {str(e)}"}

    return {alg: h.hexdigest() for alg, h in hasher.items()}

def worker_calculate_hashes(path, algorithms, mode):
    """Main worker function that runs in a separate thread."""
    try:
        if mode == "file":
            result_queue.put({"status": "start_file"})
            hashes = calculate_single_file_hashes(path, algorithms)
            result_queue.put({"status": "complete", "hashes": hashes})
            
        elif mode == "dir":
            result_queue.put({"status": "start_dir"})
            manifest = {}
            # Calculate total files for accurate progress bar
            total_files = sum([len(files) for _, _, files in os.walk(path)])
            file_count = 0
            
            for root, _, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    relative_path = os.path.relpath(filepath, path)
                    
                    # Calculate hashes and handle errors per file
                    hashes = calculate_single_file_hashes(filepath, algorithms)
                    manifest[relative_path] = hashes
                    
                    file_count += 1
                    # Send directory progress update
                    result_queue.put({"status": "progress_dir", "count": file_count, "total": total_files, "path": relative_path})
            
            result_queue.put({"status": "complete", "hashes": manifest})
            
    except Exception as e:
        result_queue.put({"status": "error", "message": str(e)})


# --- GUI Class (OOP Approach) ---

class HashCalculatorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Integrity Checker (V13)")
        self.current_theme = "dark" 
        self.calculated_results = {}
        self.current_filepath = ""
        self.mode = tk.StringVar(value="file") 
        self.supported_algs = ["md5", "sha256", "sha512", "sha3_256", "blake2b"]
        self.calculation_thread = None 
        
        self.style = ttk.Style()
        self.style.theme_use('clam') 
        
        # --- Main Frame ---
        self.main_frame = ttk.Frame(master, padding="20")
        self.main_frame.pack(padx=10, pady=10, fill='both', expand=True)

        # 1. Title and Theme Toggle (Top Row)
        ttk.Label(self.main_frame, text="File Integrity Checker", font=("Arial", 18, "bold")).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 15))
        
        self.theme_var = tk.StringVar(value="Dark")
        self.theme_toggle = ttk.Checkbutton(self.main_frame, textvariable=self.theme_var, style='ThemeToggle.TCheckbutton', command=self.toggle_theme)
        self.theme_toggle.grid(row=0, column=2, sticky='e', padx=5, pady=(0, 15))
        
        # --- Main Structure: Three vertical sections (Columns) ---
        
        # 2. INPUT SECTION (Column 0)
        self.input_frame = self.create_section_frame(self.main_frame, "Source & Algorithm", 1, 0)
        self.build_input_section(self.input_frame)

        # Vertical Separator 1
        self.sep1 = ttk.Separator(self.main_frame, orient='vertical')
        self.sep1.grid(row=1, column=1, sticky='ns', padx=10, pady=5)
        
        # 3. ACTION & STATUS SECTION (Column 2)
        self.action_frame = self.create_section_frame(self.main_frame, "Calculation & Status", 1, 2)
        self.build_action_section(self.action_frame)
        
        # Horizontal Separator (Separates top and bottom halves)
        self.sep_h = ttk.Separator(self.main_frame, orient='horizontal')
        self.sep_h.grid(row=2, column=0, columnspan=3, sticky='ew', pady=15)

        # 4. OUTPUT & VERIFY SECTION (Bottom, Column 0-2)
        self.output_frame = self.create_section_frame(self.main_frame, "Result & Verification", 3, 0, columnspan=3)
        self.build_output_section(self.output_frame)


        # Grid configuration for responsive columns
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(2, weight=1)
        
        self.update_theme_styles()
        # Ensure cleanup when window is closed
        master.protocol("WM_DELETE_WINDOW", self.on_closing) 

    # --- Section Builder Methods ---
    
    def create_section_frame(self, parent, title, row, column, columnspan=1):
        """Creates a LabelFrame for a section."""
        frame = ttk.LabelFrame(parent, text=f" {title} ", padding="10 10 10 10")
        frame.grid(row=row, column=column, columnspan=columnspan, sticky='nsew')
        frame.columnconfigure(0, weight=0) 
        frame.columnconfigure(1, weight=1)
        return frame

    def build_input_section(self, frame):
        # 1. Mode Selection
        ttk.Label(frame, text="Mode:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky='w', pady=(0, 5))
        mode_frame = ttk.Frame(frame)
        mode_frame.grid(row=1, column=0, columnspan=2, sticky='w', pady=(0, 10))
        ttk.Radiobutton(mode_frame, text="File", variable=self.mode, value="file", command=self.reset_ui).pack(side='left', padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="Folder", variable=self.mode, value="dir", command=self.reset_ui).pack(side='left')
        
        # 2. Path Selection
        ttk.Label(frame, text="Source Path:", font=("Arial", 10, "bold")).grid(row=2, column=0, columnspan=2, sticky='w', pady=(5, 5))
        
        # Row for Button and Label
        path_group = ttk.Frame(frame)
        path_group.grid(row=3, column=0, columnspan=2, sticky='ew')
        path_group.columnconfigure(0, weight=1)
        
        self.file_path_label = ttk.Label(path_group, text="No Path Selected", wraplength=350, foreground=THEMES[self.current_theme]['default_path_fg'])
        self.file_path_label.pack(side='left', fill='x', expand=True, padx=(0, 5))
        
        self.select_button = ttk.Button(path_group, text="Browse...", command=self.select_path, width=12)
        self.select_button.pack(side='right')

        # 3. Algorithm Selection
        ttk.Label(frame, text="Algorithm:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky='w', pady=(15, 5))
        self.alg_combobox = ttk.Combobox(frame, values=self.supported_algs, state="readonly", width=15)
        self.alg_combobox.set(self.supported_algs[1]) # Default to sha256
        self.alg_combobox.grid(row=5, column=0, sticky='w')
        
        ttk.Label(frame, text="(All Algs used in Folder Mode)", font=("Arial", 8, "italic")).grid(row=6, column=0, sticky='w', pady=(2, 0))


    def build_action_section(self, frame):
        # GO Button
        self.go_button = ttk.Button(frame, text="▶️ START CALCULATION", command=self.start_calculation, state='disabled', style='Accent.TButton')
        self.go_button.grid(row=0, column=0, columnspan=2, pady=(0, 15), sticky='ew')
        
        # Status
        ttk.Label(frame, text="Current Status:", font=("Arial", 10, "bold")).grid(row=1, column=0, columnspan=2, sticky='w', pady=(5, 5))
        self.match_status = ttk.Label(frame, text="Waiting for path selection...", font=("Arial", 10))
        self.match_status.grid(row=2, column=0, columnspan=2, pady=(0, 10), sticky='w')

        # Progress Bar
        ttk.Label(frame, text="Progress:", font=("Arial", 10, "bold")).grid(row=3, column=0, columnspan=2, sticky='w', pady=(5, 5))
        self.progress_bar = ttk.Progressbar(frame, orient='horizontal', mode='determinate', length=400)
        self.progress_bar.grid(row=4, column=0, columnspan=2, sticky='ew', pady=(0, 5))

    def build_output_section(self, frame):
        # 1. Hash Display / Result
        ttk.Label(frame, text="Calculated Hash / Manifest Info:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky='w', pady=(5, 5))
        
        # Hash Name and Value Labels
        self.result_label_name = ttk.Label(frame, text="---", font=("Courier", 10, "bold")) 
        self.result_label_name.grid(row=1, column=0, sticky='w', pady=2, padx=(0, 10))
        self.result_label_value = ttk.Label(frame, text="---", font=("Courier", 10)) 
        self.result_label_value.grid(row=1, column=1, sticky='w', pady=2)
        
        self.save_button = ttk.Button(frame, text="Save Result/Manifest", command=self.save_results, state='disabled')
        self.save_button.grid(row=1, column=2, pady=(0, 5), sticky='e', padx=(20, 0))
        
        # Separator
        ttk.Separator(frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky='ew', pady=15)

        # 2. Verification
        ttk.Label(frame, text="Enter Hash for Verification:", font=("Arial", 10, "bold")).grid(row=3, column=0, columnspan=2, sticky='w', pady=(0, 5))
        self.verify_entry = tk.Entry(frame, width=40)
        self.verify_entry.grid(row=4, column=0, columnspan=2, sticky='ew', padx=(0, 5), pady=(0, 5))
        
        self.compare_button = ttk.Button(frame, text="Compare", command=self.compare_hash)
        self.compare_button.grid(row=4, column=2, sticky='e', pady=(0, 5))
        
        frame.columnconfigure(1, weight=1) 


    # --- Theme / Style Logic ---

    def update_theme_styles(self):
        """Updates the appearance of all widgets based on the current theme."""
        theme_config = THEMES[self.current_theme]
        bg, fg, accent, entry_bg, entry_fg, hash_fg, sep_col, frame_bg = (
            theme_config['bg'], theme_config['fg'], theme_config['accent'], theme_config['entry_bg'], 
            theme_config['entry_fg'], theme_config['hash_fg'], theme_config['separator'], theme_config['frame_bg']
        )

        # Root and Main Frame
        self.master.config(bg=bg)
        self.style.configure('TFrame', background=bg)
        self.main_frame.config(style='TFrame')
        
        # Global Label Styling (for ttk.Label)
        self.style.configure('TLabel', background=bg, foreground=fg)
        
        # Checkbuttons/Radiobuttons (ttk)
        self.style.configure('TCheckbutton', background=bg, foreground=fg)
        self.style.configure('TRadiobutton', background=bg, foreground=fg)

        # LabelFrame Styling
        self.style.configure('TLabelframe', background=bg, foreground=fg, bordercolor=sep_col)
        self.style.configure('TLabelframe.Label', background=bg, foreground=fg)
        
        # Separators
        self.style.configure('TSeparator', background=sep_col)
        
        # ProgressBar
        self.style.configure('TProgressbar', background=accent, troughcolor=frame_bg)
        
        # Button Styling
        self.style.configure('TButton', background=accent, foreground='white', font=('Arial', 10, 'bold'))
        self.style.map('TButton', background=[('active', accent), ('disabled', sep_col)], foreground=[('disabled', fg)])
        self.style.configure('Accent.TButton', background=accent, foreground='white', font=('Arial', 11, 'bold'))
        self.style.map('Accent.TButton', background=[('active', accent)])
        
        # Entry Field (is a pure tk.Entry)
        self.verify_entry.config(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)

        # Apply TFrame style to sub-frames if they are ttk.Frame/LabelFrame
        for frame in [self.input_frame, self.action_frame, self.output_frame]:
             for widget in frame.winfo_children():
                if isinstance(widget, ttk.Frame) or isinstance(widget, ttk.LabelFrame):
                    widget.config(style='TFrame')
                
        # Specific color corrections for result labels
        self.result_label_name.config(foreground=hash_fg)
        self.result_label_value.config(foreground=hash_fg) 

        # Status Label Color
        current_text = self.match_status.cget('text')
        if "MATCH" in current_text or "Complete" in current_text:
            self.match_status.config(foreground=theme_config['match_fg'])
        elif "NO MATCH" in current_text or "Error" in current_text or "Failed" in current_text:
            self.match_status.config(foreground=theme_config['mismatch_fg'])
        else:
            self.match_status.config(foreground=fg)
            
        # Path Label Color 
        current_path_text = self.file_path_label.cget('text')
        if "No Path" in current_path_text:
            self.file_path_label.config(foreground=theme_config['default_path_fg'])
        else:
            self.file_path_label.config(foreground=fg) 
            
    # --- Functionality Methods ---
    
    def toggle_theme(self):
        """Toggles the theme and sets the toggle text."""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.theme_var.set("Light" if self.current_theme == "light" else "Dark")
        self.update_theme_styles()
    
    def reset_ui(self):
        """Resets all UI elements and internal state."""
        self.current_filepath = ""
        self.calculated_results = {}
        self.file_path_label.config(text="No Path Selected", foreground=THEMES[self.current_theme]['default_path_fg'])
        self.go_button.config(state='disabled')
        self.save_button.config(state='disabled')
        self.select_button.config(state='normal')
        self.match_status.config(text="Ready for path selection...")
        self.progress_bar.stop()
        self.progress_bar['value'] = 0
        self.result_label_name.config(text="---")
        self.result_label_value.config(text="---")
        self.verify_entry.delete(0, tk.END)

    def select_path(self):
        """Opens a dialog to select a file or folder based on the current mode."""
        if self.mode.get() == "file":
            path = filedialog.askopenfilename(title="Select File to Hash")
        else:
            path = filedialog.askdirectory(title="Select Folder to Hash")
            
        if path:
            self.current_filepath = path
            name = os.path.basename(path)
            self.file_path_label.config(text=f"{'Folder' if self.mode.get() == 'dir' else 'File'}: {name} ({path})", foreground=THEMES[self.current_theme]['fg'])
            self.go_button.config(state='normal')
            self.match_status.config(text="Path selected. Ready to start.")
            self.progress_bar['value'] = 0
            self.save_button.config(state='disabled')

    def start_calculation(self):
        """Starts the hash calculation in a dedicated worker thread."""
        if not self.current_filepath or self.calculation_thread and self.calculation_thread.is_alive():
            return

        selected_algs = [self.alg_combobox.get()] if self.mode.get() == "file" else self.supported_algs
        
        self.calculated_results = {}
        self.match_status.config(text="Starting Calculation...", foreground=THEMES[self.current_theme]['accent'])
        self.go_button.config(state='disabled')
        self.select_button.config(state='disabled')
        self.save_button.config(state='disabled')
        self.progress_bar['value'] = 0
        
        self.calculation_thread = threading.Thread(target=worker_calculate_hashes, 
                                                 args=(self.current_filepath, selected_algs, self.mode.get()))
        self.calculation_thread.start()
        
        # Start checking the queue for results on the main thread
        self.master.after(100, self.check_thread)

    def check_thread(self):
        """Periodically checks the result queue for updates from the worker thread."""
        try:
            while True:
                result = result_queue.get_nowait()
                self.process_update(result)
        except queue.Empty:
            pass 

        if self.calculation_thread and self.calculation_thread.is_alive():
            self.master.after(100, self.check_thread)
        else:
            self.finish_calculation()

    def process_update(self, result):
        """Processes status updates from the worker thread and updates the UI."""
        theme_config = THEMES[self.current_theme]
        status = result['status']

        if status == "start_file":
            self.progress_bar['mode'] = 'indeterminate'
            self.progress_bar.start(10)
        
        elif status == "start_dir":
            self.progress_bar['mode'] = 'determinate'
            self.progress_bar['value'] = 0

        elif status == "progress":
            self.progress_bar['mode'] = 'determinate'
            self.progress_bar['maximum'] = result['maximum']
            self.progress_bar['value'] = result['value']
            # Convert bytes to MB for display
            self.match_status.config(text=f"Hashing File ({result['value'] // (1024*1024)} MB / {result['maximum'] // (1024*1024)} MB)")

        elif status == "progress_dir":
            self.progress_bar['maximum'] = result['total']
            self.progress_bar['value'] = result['count']
            self.match_status.config(text=f"Hashing: {result['count']}/{result['total']} - {os.path.basename(result['path'])}")

        elif status == "complete":
            self.calculated_results = result['hashes']
            self.match_status.config(text="Calculation Complete", foreground=theme_config['match_fg'])
        
        elif status == "error":
            self.match_status.config(text=f"Calculation Error: {result['message']}", foreground=theme_config['mismatch_fg'])
            self.finish_calculation()

    def finish_calculation(self):
        """Finalizes the UI after the thread finishes."""
        self.progress_bar.stop()
        self.progress_bar['value'] = 100
        self.go_button.config(state='normal')
        self.select_button.config(state='normal')
        self.save_button.config(state='normal' if self.calculated_results else 'disabled')

        theme_config = THEMES[self.current_theme]

        if self.mode.get() == "file" and self.calculated_results:
            selected_alg = self.alg_combobox.get()
            final_hash = self.calculated_results.get(selected_alg, "N/A")
            
            # Check if there was a file error
            if "Error" in final_hash:
                 self.result_label_name.config(text=f"ERROR:")
                 self.result_label_value.config(text=final_hash["Error"])
                 self.match_status.config(text=f"File Hashing Failed: {final_hash['Error']}", foreground=theme_config['mismatch_fg'])
            else:
                self.result_label_name.config(text=f"{selected_alg.upper()}:")
                self.result_label_value.config(text=final_hash)
                self.compare_hash() # Auto-compare if input exists

        elif self.mode.get() == "dir" and self.calculated_results:
            file_count = len(self.calculated_results)
            self.result_label_name.config(text="MANIFEST CREATED:")
            self.result_label_value.config(text=f"{file_count} files hashed.")
            self.match_status.config(text="Folder Hashing Complete", foreground=theme_config['match_fg'])
        else:
             self.result_label_name.config(text="---")
             self.result_label_value.config(text="---")
             
    def compare_hash(self):
        """Compares the calculated hash with the user-entered verification hash."""
        input_hash = self.verify_entry.get().strip().lower()
        theme_config = THEMES[self.current_theme]
        
        if not self.calculated_results or self.mode.get() == "dir":
            return
        if not input_hash:
            return

        selected_alg = self.alg_combobox.get()
        calculated_hash = self.calculated_results.get(selected_alg, "").lower()
        match = calculated_hash == input_hash

        if match:
            self.match_status.config(text=f"✅ HASH MATCH!", foreground=theme_config['match_fg'])
        else:
            self.match_status.config(text=f"❌ HASH NO MATCH", foreground=theme_config['mismatch_fg'])
            
    def save_results(self):
        """Saves the calculated hash or manifest to a text file."""
        if not self.calculated_results:
            self.match_status.config(text="No results to save.", foreground=THEMES[self.current_theme]['mismatch_fg'])
            return

        initial_file = os.path.basename(self.current_filepath)
        default_filename = f"{initial_file}_manifest.txt" if self.mode.get() == "dir" else f"{initial_file}_{self.alg_combobox.get()}.txt"
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_filename,
            title="Save Hash Results"
        )
        
        if not save_path:
            return

        try:
            with open(save_path, 'w') as f:
                if self.mode.get() == "dir":
                    f.write(f"# Hash Manifest for Directory: {self.current_filepath}\n")
                    f.write("# Format: <Algorithm>:<Hash> <RelativePath>\n\n")
                    for rel_path, hashes in self.calculated_results.items():
                        for alg, hash_val in hashes.items():
                             # Check for errors saved in the manifest
                             if alg == "Error":
                                 f.write(f"Error: {hash_val} {rel_path}\n")
                             else:
                                 f.write(f"{alg}: {hash_val} {rel_path}\n")
                else:
                    alg = self.alg_combobox.get()
                    hash_val = self.calculated_results.get(alg, "ERROR")
                    f.write(f"{alg}: {hash_val}\n")
                    f.write(f"File: {self.current_filepath}\n")
            
            self.match_status.config(text=f"Results saved: {os.path.basename(save_path)}", foreground=THEMES[self.current_theme]['match_fg'])

        except Exception as e:
            self.match_status.config(text=f"Save Error: {e}", foreground=THEMES[self.current_theme]['mismatch_fg'])

    def on_closing(self):
        """Handles closing the window, especially important to let the thread finish/stop."""
        # Note: Tkinter threads cannot be forcefully stopped (except by process kill), 
        # but the queue mechanism ensures smooth communication until completion.
        if self.calculation_thread and self.calculation_thread.is_alive():
            # In a real app, you might try to set a flag to signal the worker to exit gracefully
            # For simplicity here, we just allow the main app to close.
            pass 
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalculatorApp(root)
    root.mainloop()