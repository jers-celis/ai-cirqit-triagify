import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
from datetime import datetime
import re
import json
import matplotlib
import requests
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from PIL import Image, ImageDraw, ImageTk
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Use the TkAgg backend for embedding Matplotlib in Tkinter
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class CaseAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Triagify")
        self.root.geometry("1600x900")
        self.root.configure(bg="#F1F5F9")

        # Color palette
        self.colors = {
            "primary": "#1E293B",
            "secondary": "#334155",
            "accent": "#14B8A6",
            "background": "#F1F5F9",
            "card_bg": "#FFFFFF",
            "green": "#22C55E",
            "yellow": "#FACC15",
            "red": "#EF4444",
            "blue": "#444FEF",
            "text_primary": "#1E293B",
            "text_secondary": "#64748B",
        }

        # SLO Icons "OnTrack", "AtRisk", "Breached"
        self.slo_icons = {
            "OnTrack": self._create_circle_icon("#22C55E"),  # green
            "AtRisk": self._create_circle_icon("#EAB308"),   # yellow
            "Breached": self._create_circle_icon("#DC2626")  # red
        }

        # Data containers
        self.cases_data = None
        self.severity_data = None
        self.pdf_severity_content = None
        self.analysis_results = []

        # Concurrent processing configuration
        self.max_workers = 10  # Configurable number of concurrent API calls
        self.batch_size = 20   # Process cases in batches
        self.cancel_analysis = False  # Flag for early termination
        self.session = None    # Reusable session for connection pooling

        # Search functionality
        self.all_tree_items = []  # Keep track of all tree items for search

        # API configuration
        self.api_base_url = "https://api.rdsec.trendmicro.com/prod/aiendpoint/"
        self.api_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQUktMTc1OTExNDExMTAxNCIsInJvbGVzIjpbIjM1Il0sInVzZXJfaWQiOjI2MjIsInVzZXJuYW1lIjoiamVyc29uYyIsInJvbGVfbmFtZXMiOlsiUk9QLWFpZW5kcG9pbnQtVXNlciJdLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzY2ODkwMTEyLCJqdGkiOiJjOGRlNDgyYS05Y2RlLTExZjAtYmNmYS04NjZjOGQ1OTVmMGUiLCJ2ZXJzaW9uIjoiMjAyNC0xMS0wMSJ9.YHb-8ft8EyXgxBbXz35v6QsfwI2oJ-OvTLjlfeL_HJg"
        self.model_name = "claude-4-sonnet"
        # self.model_version = "anthropic.claude-sonnet-4-20250514-v1:0"

        # Default severity definitions (fallback)
        self.severity_definitions = {
            "P1": {
                "name": "Critical",
                "description": "Core product components are rendered inoperable. Critical impact. No workaround.",
                "slo": "Within 30 minutes",
            },
            "P2": {
                "name": "High",
                "description": "Severe impairment/degradation creating significant business impact.",
                "slo": "Within 2 hours",
            },
            "P3": {
                "name": "Medium",
                "description": "Functionality impaired but operational. Workaround available.",
                "slo": "Within 12 hours",
            },
            "P4": {
                "name": "Low",
                "description": "Cosmetic issues or enhancement requests. Little or no business impact.",
                "slo": "Within 24 hours",
            },
        }

        self.setup_styles()
        self.create_widgets()
        self.setup_session()

    # ---------------- Session setup ----------------
    def setup_session(self):
        """Initialize HTTP session with connection pooling and retry strategy"""
        try:
            self.session = requests.Session()

            # Configure retry strategy
            retry_strategy = Retry(
                total=3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "POST"],
                backoff_factor=1
            )

            # Configure adapter with connection pooling
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=20,
                pool_maxsize=50
            )

            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

        # Set default headers
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            })

        except Exception as e:
            # Fallback to basic session if advanced configuration fails
            print(f"Warning: Failed to setup advanced session configuration: {e}")
            print("Falling back to basic session without connection pooling.")
            self.session = requests.Session()
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            })

    # ---------------- UI setup ----------------
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Card.TFrame",
            background=self.colors["card_bg"],
            relief="flat",
            borderwidth=1,
        )
        style.configure(
            "Title.TLabel",
            background=self.colors["card_bg"],
            font=("Inter", 16, "bold"),
            foreground=self.colors["text_primary"],
        )
    
    def _create_circle_icon(self, color, size=20):
        """Generate a circular colored icon and return as PhotoImage"""
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        r = size // 3
        center = size // 2
        draw.ellipse((center-r, center-r, center+r, center+r), fill=color)
        return ImageTk.PhotoImage(img)
    
    #def _create_circle_icon(self, color, size=14):
    #    """Generate a circular colored icon and return as PhotoImage"""
    #    img = Image.new("RGBA", (size, size), (255, 255, 255, 0))  # transparent background
    #   draw = ImageDraw.Draw(img)
    #    draw.ellipse((2, 2, size-2, size-2), fill=color)
    #    return ImageTk.PhotoImage(img)

    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors["primary"], height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        tk.Label(
            header_frame,
            text="Triagify",
            font=("Inter", 24, "bold"),
            fg="white",
            bg=self.colors["primary"],
        ).pack(expand=True)

        # Main container
        main_container = tk.Frame(self.root, bg=self.colors["background"])
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Top section (controls + summary/charts)
        top_section = tk.Frame(main_container, bg=self.colors["background"])
        top_section.pack(fill="x", pady=(0, 20), anchor="n")

        # Controls card (left)
        controls_card = tk.Frame(
            top_section, bg=self.colors["card_bg"], relief="flat", bd=1
        )
        controls_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        controls_inner = tk.Frame(controls_card, bg=self.colors["card_bg"])
        controls_inner.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(
            controls_inner,
            text="File Selection",
            font=("Inter", 14, "bold"),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
        ).pack(anchor="w")

        btn_frame = tk.Frame(controls_inner, bg=self.colors["card_bg"])
        btn_frame.pack(fill="x", pady=(10, 0))

        self.load_cases_btn = tk.Button(
            btn_frame,
            text="Load Cases",
            bg=self.colors["accent"],
            fg="white",
            font=("Inter", 10, "bold"),
            relief="flat",
            command=self.load_cases_file,
            padx=20,
            pady=8,
        )
        self.load_cases_btn.pack(side="left", padx=(0, 10))

        self.load_severity_btn = tk.Button(
            btn_frame,
            text="Load Severity",
            bg=self.colors["secondary"],
            fg="white",
            font=("Inter", 10, "bold"),
            relief="flat",
            command=self.load_severity_file,
            padx=20,
            pady=8,
        )
        self.load_severity_btn.pack(side="left", padx=(0, 10))

        self.analyze_btn = tk.Button(
            btn_frame,
            text="Analyze Priority",
            bg=self.colors["green"],
            fg="white",
            font=("Inter", 10, "bold"),
            relief="flat",
            command=self.analyze_cases,
            padx=20,
            pady=8,
        )
        self.analyze_btn.pack(side="left", padx=(0, 10))

        self.clear_btn = tk.Button(
            btn_frame,
            text="Clear",
            bg=self.colors["red"],
            fg="white",
            font=("Inter", 10, "bold"),
            relief="flat",
            command=self.clear_analysis,
            padx=20,
            pady=8,
        )
        self.clear_btn.pack(side="left")

        # Add Cancel button for stopping analysis
        self.cancel_btn = tk.Button(
            btn_frame,
            text="Cancel",
            bg=self.colors["yellow"],
            fg="white",
            font=("Inter", 10, "bold"),
            relief="flat",
            command=self.cancel_analysis_process,
            padx=20,
            pady=8,
            state="disabled"
        )
        self.cancel_btn.pack(side="left", padx=(10, 0))

        # Summary + charts (right)
        summary_card = tk.Frame(
            top_section, bg=self.colors["card_bg"], relief="flat", bd=1
        )
        summary_card.pack(side="right", padx=(10, 0), fill="both", expand=True)

        summary_inner = tk.Frame(summary_card, bg=self.colors["card_bg"])
        summary_inner.pack(fill="both", expand=True, padx=15, pady=15)
        tk.Label(
            summary_inner,
            text="Analysis Summary",
            font=("Inter", 14, "bold"),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
        ).pack(anchor="w")
        self.summary_text = tk.Label(
            summary_inner,
            text="No analysis performed yet",
            font=("Inter", 10),
            bg=self.colors["card_bg"],
            fg=self.colors["text_secondary"],
            justify="left",
        )
        self.summary_text.pack(anchor="w", pady=(10, 0))

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            summary_inner,
            variable=self.progress_var,
            maximum=100,
            length=300
        )
        self.progress_bar.pack(anchor="w", pady=(5, 0))
        self.progress_bar.pack_forget()  # Initially hidden

        # Chart container inside summary
        self.charts_container = tk.Frame(summary_inner, bg=self.colors["card_bg"])
        self.charts_container.pack(fill="both", expand=True, pady=(10, 0))

        # Results section (below)
        results_frame = tk.Frame(main_container, bg=self.colors["card_bg"], relief="flat", bd=1)
        results_frame.pack(fill="both", expand=True)
        results_inner = tk.Frame(results_frame, bg=self.colors["card_bg"])
        results_inner.pack(fill="both", expand=True, padx=15, pady=15)
        # Results header with search
        results_header_frame = tk.Frame(results_inner, bg=self.colors["card_bg"])
        results_header_frame.pack(fill="x", pady=(0, 10))

        tk.Label(
            results_header_frame,
            text="Analysis Results",
            font=("Inter", 16, "bold"),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
        ).pack(side="left")

        # Search functionality
        search_frame = tk.Frame(results_header_frame, bg=self.colors["card_bg"])
        search_frame.pack(side="right")

        tk.Label(
            search_frame,
            text="Search Case ID:",
            font=("Inter", 10),
            bg=self.colors["card_bg"],
            fg=self.colors["text_secondary"],
        ).pack(side="left", padx=(0, 5))

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.on_search_change)
        self.search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=("Inter", 10),
            width=15,
            relief="flat",
            bd=1,
            highlightthickness=1,
            highlightcolor=self.colors["accent"]
        )
        self.search_entry.pack(side="left", padx=(0, 5))

        # Clear search button
        self.clear_search_btn = tk.Button(
            search_frame,
            text="Clear",
            bg=self.colors["secondary"],
            fg="white",
            font=("Inter", 9),
            relief="flat",
            command=self.clear_search,
            padx=8,
            pady=2,
        )
        self.clear_search_btn.pack(side="left")

        # Search results counter
        self.search_results_label = tk.Label(
            search_frame,
            text="",
            font=("Inter", 9),
            bg=self.colors["card_bg"],
            fg=self.colors["text_secondary"],
        )
        self.search_results_label.pack(side="left", padx=(10, 0))

        self.create_results_table(results_inner)

    def create_results_table(self, parent):
        tree_frame = tk.Frame(parent, bg=self.colors["card_bg"])
        tree_frame.pack(fill="both", expand=True)
        columns = ("CaseID", "Title", "Submitted", "Recommended", "ARR-Matrix", "CreatedOn")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", height=16)
        
        # Configure #0 column (SLO Status)
        self.tree.heading("#0", text="SLO Status")   # give #0 a heading
        self.tree.column("#0", width=70, minwidth=30, stretch=False, anchor="center")

        for col in columns:
            self.tree.heading(col, text=col)
            # set nice widths
            if col == "Title":
                self.tree.column(col, width=360)
            elif col == "CaseID":
                self.tree.column(col, width=50, anchor="center")
            elif col == "Submitted":
                self.tree.column(col, width=80, anchor="center")
            elif col == "Recommended":
                self.tree.column(col, width=80, anchor="center")
            elif col == "ARR-Matrix":
                self.tree.column(col, width=50, anchor="center")
            elif col == "CreatedOn":
                self.tree.column(col, width=60, anchor="center")
            else:
                self.tree.column(col, width=140)
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")

        # Color tags
        #self.tree.tag_configure("Green", foreground="#22C55E")
        #self.tree.tag_configure("Yellow", foreground="#EAB308")
        #self.tree.tag_configure("Red", foreground="#DC2626")
        self.tree.tag_configure("Black", foreground="#000000")
        self.tree.bind("<Double-1>", self.on_case_double_click)

    # ---------------- Search functionality ----------------
    def on_search_change(self, *args):
        """Handle search text changes and filter the table"""
        search_term = self.search_var.get().strip().lower()

        if not search_term:
            # Show all items if search is empty
            self.show_all_results()
            return

        # Clear the tree first
        for item in self.all_tree_items:
            self.tree.detach(item)

        # Show only matching items and count them
        matching_count = 0
        for item in self.all_tree_items:
            values = self.tree.item(item)["values"]
            if values and len(values) > 0:
                case_id = str(values[0]).lower()  # Case ID is first column
                if search_term in case_id:
                    self.tree.reattach(item, "", "end")
                    matching_count += 1

        # Update the results counter
        total_count = len(self.all_tree_items)
        if hasattr(self, 'search_results_label'):
            self.search_results_label.configure(
                text=f"({matching_count} of {total_count} results)"
            )

    def clear_search(self):
        """Clear the search field and show all results"""
        self.search_var.set("")
        self.show_all_results()

    def show_all_results(self):
        """Show all results in the table"""
        # Clear tree first
        for item in self.all_tree_items:
            self.tree.detach(item)

        # Reattach all items in their original order
        for item in self.all_tree_items:
            self.tree.reattach(item, "", "end")

        # Clear the results counter
        if hasattr(self, 'search_results_label'):
            self.search_results_label.configure(text="")

    # ---------------- CSV loading with encoding fallback ----------------
    def _read_csv_with_fallback(self, path: str) -> pd.DataFrame:
        """Try common encodings to read CSV robustly."""
        encodings = ["utf-8", "utf-8-sig", "cp1252", "latin1"]
        last_exc = None
        for enc in encodings:
            try:
                return pd.read_csv(path, encoding=enc)
            except Exception as e:
                last_exc = e
                continue
        # If all failed, raise the last exception
        raise last_exc

    def load_cases_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not file_path:
            return
        try:
            self.cases_data = self._read_csv_with_fallback(file_path)
            # Ensure expected columns exist (case-insensitive mapping)
            expected = ["CaseID", "Priority", "ARR-Matrix", "CaseTitle", "CaseDescription", "CreatedOn"]
            # map columns ignoring case and whitespace
            cols_map = {c.lower().strip(): c for c in self.cases_data.columns}
            missing = [col for col in expected if col.lower() not in cols_map]
            if missing:
                messagebox.showwarning("Warning", f"Loaded file but missing columns: {', '.join(missing)}. Make sure it has CaseID, Priority, ARR-Matrix, CaseTitle, CaseDescription, CreatedOn.")
            messagebox.showinfo("Success", f"Loaded {len(self.cases_data)} cases")
            self.load_cases_btn.configure(bg=self.colors["green"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load cases: {e}")

    def load_severity_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf"), ("CSV files", "*.csv"), ("All files", "*.*")])
        if not file_path:
            return

        try:
            if file_path.lower().endswith('.pdf'):
                # Handle PDF file
                messagebox.showinfo("Processing", "Processing PDF file. This may take a few moments...")
                self.root.update()  # Update UI to show the message

                pdf_base64 = self.read_pdf_content(file_path)
                self.pdf_severity_content = self.call_api_for_pdf_analysis(pdf_base64)

                if self.pdf_severity_content:
                    messagebox.showinfo("Success", "PDF severity definitions loaded successfully")
                    self.load_severity_btn.configure(bg=self.colors["green"])
                    # Store a summary for display
                    summary = self.pdf_severity_content[:200] + "..." if len(self.pdf_severity_content) > 200 else self.pdf_severity_content
                    self.severity_data = pd.DataFrame([{"Source": "PDF", "Content": summary}])
                else:
                    messagebox.showerror("Error", "Failed to extract content from PDF")

            else:
                # Handle CSV file (existing functionality)
                df = self._read_csv_with_fallback(file_path)
                # Attempt to map rows to severity_definitions
                mapping = {}
                # possible column names for the key
                key_cols = [c for c in df.columns if c.lower() in ("priority", "level", "severity")]
                name_cols = [c for c in df.columns if c.lower() in ("name", "severity name", "title")]
                desc_cols = [c for c in df.columns if c.lower() in ("description", "desc")]
                slo_cols = [c for c in df.columns if "slo" in c.lower() or "hours" in c.lower()]

                for _, row in df.iterrows():
                    # find priority key
                    if key_cols:
                        raw_key = str(row[key_cols[0]]).strip()
                    else:
                        # fallback: try first column
                        raw_key = str(row[df.columns[0]]).strip()
                    key = raw_key.upper()
                    name = row[name_cols[0]] if name_cols else ""
                    description = row[desc_cols[0]] if desc_cols else ""
                    slo = row[slo_cols[0]] if slo_cols else ""
                    mapping[key] = {
                        "name": str(name) if not pd.isna(name) else "",
                        "description": str(description) if not pd.isna(description) else "",
                        "slo": str(slo) if not pd.isna(slo) else "",
                    }
                # Merge mapping into severity_definitions (only keys present)
                for k, v in mapping.items():
                    self.severity_definitions[k] = v
                self.severity_data = df
                self.pdf_severity_content = None  # Clear PDF content when CSV is loaded
                messagebox.showinfo("Success", "Loaded severity definitions from CSV")
                self.load_severity_btn.configure(bg=self.colors["green"])

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load severity file: {e}")

    # ---------------- Date parsing ----------------
    def parse_date(self, date_str: str):
        if pd.isna(date_str):
            return None
        if isinstance(date_str, (datetime, pd.Timestamp)):
            return pd.to_datetime(date_str).to_pydatetime()
        # Try multiple formats
        fmts = [
            "%m/%d/%y %I:%M %p",
            "%m/%d/%Y %I:%M %p",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
        ]
        for fmt in fmts:
            try:
                return datetime.strptime(str(date_str), fmt)
            except Exception:
                continue
        # Try pandas parser as last resort
        try:
            return pd.to_datetime(date_str, errors="coerce").to_pydatetime()
        except Exception:
            return None

    # ---------------- API integration ----------------
    def read_pdf_content(self, pdf_path: str):
        """Read PDF file and convert to base64 for API processing"""
        try:
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            return base64.b64encode(pdf_data).decode('utf-8')
        except Exception as e:
            raise Exception(f"Failed to read PDF file: {e}")

    def call_api_for_pdf_analysis(self, pdf_base64: str):
        """Call API to extract content from PDF"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            payload = {
                "model": self.model_name,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Please extract and return the severity level definitions from this PDF document. Focus on priority levels like P1, P2, P3, P4 and their descriptions, SLO requirements, and criteria."
                            },
                            {
                                "type": "document",
                                "source": {
                                    "type": "base64",
                                    "media_type": "application/pdf",
                                    "data": pdf_base64
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 4000
            }

            url = f"{self.api_base_url}v1/messages"
            response = requests.post(url, json=payload, headers=headers, timeout=30)

            # Better error handling
            if response.status_code == 401:
                raise Exception(f"Authentication failed. Please check your API key. Status: {response.status_code}, Response: {response.text}")
        
            response.raise_for_status()

            result = response.json()
            return result.get('content', [{}])[0].get('text', '')

        except requests.exceptions.RequestException as e:
            # More detailed error message
            error_msg = f"API call failed: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f"\nStatus Code: {e.response.status_code}"
                error_msg += f"\nResponse: {e.response.text[:500]}"  # First 500 chars
            raise Exception(error_msg)
#            response.raise_for_status()

#            result = response.json()
#            return result.get('content', [{}])[0].get('text', '')
#        except Exception as e:
#            raise Exception(f"API call failed: {e}")

    def call_api_for_priority_analysis(self, title: str, description: str, severity_definitions: str):
        """Call API to analyze case priority using severity definitions"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            case_content = f"Case Title: {title}\nCase Description: {description}"

            prompt = f"""Based on the following severity definitions:

{severity_definitions}

Please analyze this support case and determine the most appropriate priority level:

{case_content}

Provide your response in the following format:
Priority: [P1/P2/P3/P4]
Reasoning: [Detailed explanation only of why this priority was recommended based on the severity definitions.]"""

            payload = {
                "model": self.model_name,
                "messages": [
                    #{"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 1000
            }

            response = requests.post(f"{self.api_base_url}v1/messages", json=payload, headers=headers, timeout=30)
            response.raise_for_status()

            result = response.json()
            ai_response = result.get('content', [{}])[0].get('text', '')

            # Parse the response to extract priority and reasoning
            priority_match = re.search(r'Priority:\s*([P][1-4])', ai_response, re.IGNORECASE)
            reasoning_match = re.search(r'Reasoning:\s*(.+)', ai_response, re.DOTALL | re.IGNORECASE)

            priority = priority_match.group(1).upper() if priority_match else "P3"
            reasoning = reasoning_match.group(1).strip() if reasoning_match else ai_response

            return priority, reasoning, ai_response
        except Exception as e:
            # Fallback to rule-based analysis if API fails
            return self.analyze_priority_fallback(title, description)
    
    def analyze_single_case(self, case_data):
        """Analyze a single case - designed for concurrent execution"""
        if self.cancel_analysis:
            return None

        try:
            case_id, title, desc, submitted, arr, created_str = case_data
            created_on = self.parse_date(created_str)

            # Get analysis from API or fallback
            recommended, reasoning, full_ai_response = self.analyze_priority(title, desc)

            # Augment reasoning with severity definition text if available (for fallback only)
            if not self.pdf_severity_content:
                sev_def = self.severity_definitions.get(recommended, {})
                if sev_def:
                    reasoning += f" | Severity ref: {sev_def.get('description','')[:200]}"

            slo_status = self.calculate_slo_status(recommended, created_on)

            ai_analysis = {
                "recommended_priority": recommended,
                "is_correct": (str(submitted).strip().upper() == recommended),
                "confidence": "High" if self.pdf_severity_content else "Medium",
                "reasoning": reasoning,
                "full_ai_statement": full_ai_response,
                "analysis_method": "AI API" if self.pdf_severity_content else "Rule-based",
            }

            result = {
                "CaseID": str(case_id),
                "Submitted Priority": str(submitted),
                "CaseTitle": str(title),
                "Recommended Priority": recommended,
                "ARR-Matrix": str(arr),
                "CreatedOn": created_str,
                "SLO Status": slo_status,
                "ai_analysis": ai_analysis,
            }

            return result

        except Exception as e:
            # Return error result for failed cases
            return {
                "CaseID": str(case_data[0]) if case_data else "Unknown",
                "Submitted Priority": str(case_data[3]) if len(case_data) > 3 else "Unknown",
                "CaseTitle": str(case_data[1]) if len(case_data) > 1 else "Error",
                "Recommended Priority": "P3",
                "ARR-Matrix": str(case_data[4]) if len(case_data) > 4 else "Unknown",
                "CreatedOn": str(case_data[5]) if len(case_data) > 5 else "Unknown",
                "SLO Status": "Unknown",
                "ai_analysis": {
                    "recommended_priority": "P3",
                    "is_correct": False,
                    "confidence": "Low",
                    "reasoning": f"Analysis failed: {str(e)}",
                    "full_ai_statement": f"Error occurred during analysis: {str(e)}",
                    "analysis_method": "Error",
                },
            }

    def cancel_analysis_process(self):
        """Cancel the current analysis process"""
        self.cancel_analysis = True
        self.cancel_btn.configure(state="disabled")
        self.analyze_btn.configure(state="normal")
        self.summary_text.configure(text="Analysis cancelled by user")
        self.progress_bar.pack_forget()

    # ---------------- Rule-based NLP (fallback) ----------------
    def analyze_priority_fallback(self, title: str, description: str):
        """Fallback rule-based analysis when API is unavailable"""
        title_text = str(title or "")
        desc_text = str(description or "")
        combined = (title_text + " " + desc_text).lower()

        # Priority matching rules (regex-based)
        # P1 indicators (critical)
        p1_patterns = [
            r"\bcrash\b",
            r"system down",
            r"inoperable",
            r"\bcritical\b",
            r"blue screen",
            r"cannot boot",
            r"cannot connect",
            r"\btotal failure\b",
            r"\bno workaround\b",
            r"\bdata loss\b",
        ]
        for pat in p1_patterns:
            if re.search(pat, combined):
                reason = f"Matched P1 pattern: '{pat}' (fallback analysis)"
                return "P1", reason, reason

        # P2 indicators (high)
        p2_patterns = [
            r"severe",
            r"degrad",
            r"performance.*slow",
            r"engine offline",
            r"security.*failed",
            r"partial outage",
            r"significant impact",
            r"service degraded",
        ]
        for pat in p2_patterns:
            if re.search(pat, combined):
                reason = f"Matched P2 pattern: '{pat}' (fallback analysis)"
                return "P2", reason, reason

        # P3 indicators (medium)
        p3_patterns = [
            r"workaround",
            r"partial",
            r"limited",
            r"upgrade failure",
            r"functionality.*impaired",
            r"\bmoderate\b",
        ]
        for pat in p3_patterns:
            if re.search(pat, combined):
                reason = f"Matched P3 pattern: '{pat}' (fallback analysis)"
                return "P3", reason, reason

        # P4 indicators (low)
        p4_patterns = [
            r"inquiry",
            r"request.*information",
            r"documentation",
            r"cosmetic",
            r"enhancement",
            r"feature request",
            r"how to",
        ]
        for pat in p4_patterns:
            if re.search(pat, combined):
                reason = f"Matched P4 pattern: '{pat}' (fallback analysis)"
                return "P4", reason, reason

        # Default
        reason = "No specific keywords matched — defaulting to P3 (fallback analysis)"
        return "P3", reason, reason

    def analyze_priority(self, title: str, description: str):
        """Return (recommended_priority, reasoning_text, full_ai_response)"""
        if self.pdf_severity_content:
            return self.call_api_for_priority_analysis(title, description, self.pdf_severity_content)
        else:
            return self.analyze_priority_fallback(title, description)

    # ---------------- SLO calculation ----------------
    def calculate_slo_status(self, recommended_priority: str, created_on):
        """Return SLO status string: OnTrack / AtRisk / Breached / Unknown"""
        if created_on is None:
            return "Unknown"
        now = datetime.now()
        elapsed_seconds = (now - created_on).total_seconds()
        elapsed_minutes = elapsed_seconds / 60.0
        elapsed_hours = elapsed_seconds / 3600.0

        # P1 thresholds (minutes)
        if recommended_priority == "P1":
            if elapsed_minutes < 30:
                return "OnTrack"
            elif elapsed_minutes < 60:
                return "AtRisk"
            else:
                return "Breached"
        # P2 thresholds (hours)
        if recommended_priority == "P2":
            if elapsed_hours < 2:
                return "OnTrack"
            elif elapsed_hours < 4:
                return "AtRisk"
            else:
                return "Breached"
        # P3 thresholds
        if recommended_priority == "P3":
            if elapsed_hours < 12:
                return "OnTrack"
            elif elapsed_hours < 24:
                return "AtRisk"
            else:
                return "Breached"
        # P4 thresholds
        if recommended_priority == "P4":
            if elapsed_hours < 24:
                return "OnTrack"
            elif elapsed_hours < 48:
                return "AtRisk"
            else:
                return "Breached"

        return "Unknown"

    # ---------------- Analysis flow ----------------
    def analyze_cases(self):
        """Optimized analysis with concurrent processing, batching, and progress tracking"""
        if self.cases_data is None:
            messagebox.showerror("Error", "Please load the cases CSV first")
            return

        # Reset cancellation flag
        self.cancel_analysis = False

        # Clear prior results
        self.analysis_results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Prepare case data for processing
        total_cases = len(self.cases_data)
        case_data_list = []

        # Tolerant column access (case-insensitive)
        row_map = {c.lower().strip(): c for c in self.cases_data.columns}
        getcol = lambda row, name: row.get(row_map.get(name.lower()), "")

        for _, row in self.cases_data.iterrows():
            case_id = getcol(row, "caseid") or getcol(row, "case id") or ""
            title = getcol(row, "casetitle") or getcol(row, "case title") or ""
            desc = getcol(row, "casedescription") or getcol(row, "case description") or ""
            submitted = getcol(row, "priority") or ""
            arr = getcol(row, "arr-matrix") or getcol(row, "arr_matrix") or ""
            created_str = getcol(row, "createdon") or getcol(row, "created on") or ""

            case_data_list.append((case_id, title, desc, submitted, arr, created_str))

        # Update UI for processing
        self.analyze_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress_bar.pack(anchor="w", pady=(5, 0))
        self.progress_var.set(0)

        # Run analysis in separate thread to keep UI responsive
        analysis_thread = threading.Thread(
            target=self._run_concurrent_analysis,
            args=(case_data_list, total_cases),
            daemon=True
        )
        analysis_thread.start()

    def _run_concurrent_analysis(self, case_data_list, total_cases):
        """Run the concurrent analysis in a separate thread"""
        try:
            processed_count = 0
            failed_count = 0

            # Process in batches with concurrent execution
            for batch_start in range(0, total_cases, self.batch_size):
                if self.cancel_analysis:
                    break

                batch_end = min(batch_start + self.batch_size, total_cases)
                batch_data = case_data_list[batch_start:batch_end]
                batch_num = (batch_start // self.batch_size) + 1
                total_batches = (total_cases + self.batch_size - 1) // self.batch_size

                # Update progress
                progress_text = f"Processing batch {batch_num} of {total_batches} (concurrent API calls)"
                self.root.after(0, self._update_progress_text, progress_text)

                # Process batch concurrently
                batch_results = []
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    if self.cancel_analysis:
                        break

                    # Submit all tasks in the batch
                    future_to_case = {executor.submit(self.analyze_single_case, case_data): case_data
                                    for case_data in batch_data}

                    # Collect results as they complete
                    for future in as_completed(future_to_case):
                        if self.cancel_analysis:
                            executor.shutdown(wait=False)
                            break

                        try:
                            result = future.result(timeout=60)  # 60 second timeout per case
                            if result:
                                batch_results.append(result)
                                processed_count += 1
                            else:
                                failed_count += 1
                        except Exception as e:
                            failed_count += 1
                            print(f"Case analysis failed: {e}")

                        # Update progress
                        progress = (processed_count + failed_count) / total_cases * 100
                        self.root.after(0, self._update_progress_bar, progress)

                # Add batch results to main results and update UI
                if not self.cancel_analysis:
                    self.root.after(0, self._update_ui_with_results, batch_results)

            # Final UI update
            if not self.cancel_analysis:
                self.root.after(0, self._finalize_analysis, processed_count, failed_count)
            else:
                self.root.after(0, self._cleanup_cancelled_analysis)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed: {e}"))
            self.root.after(0, self._cleanup_cancelled_analysis)

    def _update_progress_text(self, text):
        """Thread-safe method to update progress text"""
        self.summary_text.configure(text=text)

    def _update_progress_bar(self, progress_value):
        """Thread-safe method to update progress bar"""
        self.progress_var.set(progress_value)

    def _update_ui_with_results(self, batch_results):
        """Update UI with a batch of results"""
        for result in batch_results:
            self.analysis_results.append(result)

            title_short = result["CaseTitle"][:75] + "..." if len(result["CaseTitle"]) > 75 else result["CaseTitle"]
            
            # Decide SLO status circle and color tag
            status = result["SLO Status"]
            icon = self.slo_icons.get(status, None)

            item_id = self.tree.insert(
                "",
                "end",
                text="",
                image=icon,
                values=(
                    result["CaseID"],
                    title_short,
                    result["Submitted Priority"],
                    result["Recommended Priority"],
                    result["ARR-Matrix"],
                    result["CreatedOn"]
                ),
                tags=("Black",),
            )
            # Track the item for search functionality
            self.all_tree_items.append(item_id)

    def _finalize_analysis(self, processed_count, failed_count):
        """Finalize the analysis and update UI"""
        self.analyze_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.progress_bar.pack_forget()

        self.update_summary()
        self.update_charts()

        success_msg = f"Analyzed {processed_count} cases successfully"
        if failed_count > 0:
            success_msg += f" ({failed_count} failed)"

        messagebox.showinfo("Analysis Complete", success_msg)

    def _cleanup_cancelled_analysis(self):
        """Clean up UI after cancelled analysis"""
        self.analyze_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.progress_bar.pack_forget()
        self.summary_text.configure(text="Analysis cancelled")

    def clear_analysis(self):
        """Clear all analysis results, table data, and charts"""
        # Clear results data
        self.analysis_results.clear()

        # Clear table
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Clear search tracking
        self.all_tree_items.clear()
        if hasattr(self, 'search_var'):
            self.search_var.set("")

        # Clear charts
        for w in self.charts_container.winfo_children():
            w.destroy()

        # Reset chart data
        if hasattr(self, 'chart_data'):
            delattr(self, 'chart_data')

        # Reset summary
        self.summary_text.configure(text="No analysis performed yet")

        # Cancel any running analysis
        self.cancel_analysis = True

        # Reset button colors (optional - keeps loaded files indicators)
        # Note: We don't clear the loaded data (cases_data, severity_data, pdf_severity_content)
        # so users can run analysis again without reloading files

        messagebox.showinfo("Cleared", "Analysis results cleared. You can now load new cases for analysis.")

    # ---------------- Summary & Charts ----------------
    def update_summary(self):
        if not self.analysis_results:
            self.summary_text.configure(text="No analysis performed yet")
            return
        total = len(self.analysis_results)
        misaligned = sum(1 for r in self.analysis_results if r["Submitted Priority"].strip().upper() != r["Recommended Priority"])
        greens = sum(1 for r in self.analysis_results if r["SLO Status"] == "OnTrack")
        yellows = sum(1 for r in self.analysis_results if r["SLO Status"] == "AtRisk")
        reds = sum(1 for r in self.analysis_results if r["SLO Status"] == "Breached")

        summary = (
            f"Total Cases: {total}\n"
            f"Misaligned Priorities: {misaligned} ({misaligned/total*100:.1f}%)\n"
            f"SLO → OnTrack: {greens}, AtRisk: {yellows}, Breached: {reds}"
        )
        self.summary_text.configure(text=summary)

    def update_charts(self):
        # clear chart container
        for w in self.charts_container.winfo_children():
            w.destroy()

        if not self.analysis_results:
            return

        # Prepare data for clickable charts
        incorrect_cases = [r for r in self.analysis_results if r["Submitted Priority"].strip().upper() != r["Recommended Priority"]]
        correct_cases = [r for r in self.analysis_results if r["Submitted Priority"].strip().upper() == r["Recommended Priority"]]

        slo_cases = {
            "OnTrack": [r for r in self.analysis_results if r["SLO Status"] == "OnTrack"],
            "AtRisk": [r for r in self.analysis_results if r["SLO Status"] == "AtRisk"],
            "Breached": [r for r in self.analysis_results if r["SLO Status"] == "Breached"],
        }

        slo_counts = {k: len(v) for k, v in slo_cases.items()}

        fig, axes = plt.subplots(1, 2, figsize=(7, 3), dpi=100)

        # Pie 1 - correctness
        wedges1, texts1, autotexts1 = axes[0].pie([len(correct_cases), len(incorrect_cases)],
                                                   labels=None,
                                                   autopct=lambda pct: f"{pct:.0f}%" if pct > 0 else "",
                                                   colors=[self.colors["blue"], self.colors["red"]])
        # Hide text objects for 0%
        for autotext in autotexts1:
            if autotext.get_text() in ("0%", "0"):
                autotext.set_text("")
                autotext.set_visible(False)

        axes[0].set_title("Priority Tagging Accuracy")
        axes[0].legend(
            wedges1,
            ["Correct", "Incorrect"],
            title="Legend",
            loc="center left",
            bbox_to_anchor=(1, 0, 0.5, 1),
        )

        # Pie 2 - SLO
        wedges2, texts2, autotexts2 = axes[1].pie(list(slo_counts.values()),
                                                   labels=None,
                                                   autopct=lambda pct: f"{pct:.0f}%" if pct > 0 else "",
                                                   colors=[self.colors["green"], self.colors["yellow"], self.colors["red"]])
        for autotext in autotexts2:
            if autotext.get_text() in ("0%", "0"):
                autotext.set_text("")
                autotext.set_visible(False)

        axes[1].set_title("SLO Status")
        axes[1].legend(
            wedges2,
            list(slo_counts.keys()),
            title="Legend",
            loc="center left",
            bbox_to_anchor=(1, 0, 0.5, 1),
        )

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.charts_container)
        canvas.draw()
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill="both", expand=True)

        # Store data for click events
        self.chart_data = {
            'accuracy': {
                'wedges': wedges1,
                'data': [correct_cases, incorrect_cases],
                'labels': ['Correct', 'Incorrect']
            },
            'slo': {
                'wedges': wedges2,
                'data': [slo_cases[k] for k in slo_counts.keys()],
                'labels': list(slo_counts.keys())
            }
        }

        # Add click event handlers
        def on_accuracy_click(event):
            if event.inaxes == axes[0]:
                for i, wedge in enumerate(wedges1):
                    if wedge.contains_point([event.x, event.y]):
                        cases = self.chart_data['accuracy']['data'][i]
                        label = self.chart_data['accuracy']['labels'][i]
                        self.show_case_list(cases, f"{label} Priority Tagging")
                        break

        def on_slo_click(event):
            if event.inaxes == axes[1]:
                for i, wedge in enumerate(wedges2):
                    if wedge.contains_point([event.x, event.y]):
                        cases = self.chart_data['slo']['data'][i]
                        label = self.chart_data['slo']['labels'][i]
                        self.show_case_list(cases, f"SLO Status: {label}")
                        break

        # Connect click events
        canvas.mpl_connect('button_press_event', on_accuracy_click)
        canvas.mpl_connect('button_press_event', on_slo_click)

    def show_case_list(self, cases, title):
        """Show a popup window with case IDs"""
        popup = tk.Toplevel(self.root)
        popup.title(f"Case List - {title}")
        popup.geometry("600x400")
        popup.configure(bg=self.colors["background"])
        popup.transient(self.root)
        popup.grab_set()

        header = tk.Frame(popup, bg=self.colors["primary"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text=f"{title} ({len(cases)} cases)",
                font=("Inter", 16, "bold"), fg="white", bg=self.colors["primary"]).pack(expand=True)

        main_frame = tk.Frame(popup, bg=self.colors["background"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Create scrollable list
        list_frame = tk.Frame(main_frame, bg=self.colors["card_bg"], relief="flat", bd=1)
        list_frame.pack(fill="both", expand=True)

        # Headers
        headers_frame = tk.Frame(list_frame, bg=self.colors["card_bg"])
        headers_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(headers_frame, text="Case ID", font=("Inter", 10, "bold"),
                bg=self.colors["card_bg"], width=15, anchor="w").pack(side="left")
        tk.Label(headers_frame, text="Title", font=("Inter", 10, "bold"),
                bg=self.colors["card_bg"], anchor="w").pack(side="left", fill="x", expand=True)

        # Scrollable content
        canvas = tk.Canvas(list_frame, bg=self.colors["card_bg"])
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors["card_bg"])

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Add cases to list
        for case in cases:
            case_frame = tk.Frame(scrollable_frame, bg=self.colors["card_bg"])
            case_frame.pack(fill="x", padx=10, pady=2)

            case_id_label = tk.Label(case_frame, text=case["CaseID"],
                                   font=("Inter", 9), bg=self.colors["card_bg"],
                                   width=15, anchor="w")
            case_id_label.pack(side="left")

            title_text = case["CaseTitle"][:80] + "..." if len(case["CaseTitle"]) > 80 else case["CaseTitle"]
            title_label = tk.Label(case_frame, text=title_text,
                                 font=("Inter", 9), bg=self.colors["card_bg"],
                                 anchor="w", cursor="hand2")
            title_label.pack(side="left", fill="x", expand=True)

            # Make case clickable to show details
            def show_case_details(case_data=case):
                popup.destroy()
                self.show_detailed_analysis(case_data)

            case_id_label.bind("<Button-1>", lambda e, case_data=case: show_case_details(case_data))
            title_label.bind("<Button-1>", lambda e, case_data=case: show_case_details(case_data))

        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0))
        scrollbar.pack(side="right", fill="y")

    # ---------------- Double-click popup ----------------
    def on_case_double_click(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        case_id = item["values"][0]
        analysis_result = next((r for r in self.analysis_results if r["CaseID"] == str(case_id)), None)
        if analysis_result:
            self.show_detailed_analysis(analysis_result)

    def show_detailed_analysis(self, analysis_result):
        popup = tk.Toplevel(self.root)
        popup.title(f"Detailed Analysis - Case {analysis_result['CaseID']}")
        popup.geometry("800x600")
        popup.configure(bg=self.colors["background"])
        popup.transient(self.root)
        popup.grab_set()

        header = tk.Frame(popup, bg=self.colors["primary"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text=f"Case Analysis: {analysis_result['CaseID']}", font=("Inter", 18, "bold"), fg="white", bg=self.colors["primary"]).pack(expand=True)

        main_frame = tk.Frame(popup, bg=self.colors["background"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        details_text = (
            f"Case ID: {analysis_result['CaseID']}\n"
            f"Title: {analysis_result['CaseTitle']}\n"
            f"Submitted Priority: {analysis_result['Submitted Priority']}\n"
            f"Recommended Priority: {analysis_result['Recommended Priority']}\n"
            f"ARR-Matrix: {analysis_result['ARR-Matrix']}\n"
            f"Created On: {analysis_result['CreatedOn']}\n"
            f"SLO Status: {analysis_result['SLO Status']}\n"
        )

        tk.Label(main_frame, text=details_text, font=("Inter", 10), bg=self.colors["card_bg"], fg=self.colors["text_secondary"], justify="left").pack(fill="x", pady=(0, 10))

        ai = analysis_result.get("ai_analysis", {})
        reasoning_content = (
            #f"Analysis Method: {ai.get('analysis_method', 'Unknown')}\n"
            f"Recommended Priority: {ai.get('recommended_priority', 'N/A')}\n"
            f"Submitted Priority Correct: {'Yes' if ai.get('is_correct') else 'No'}\n"
            f"Confidence: {ai.get('confidence', 'Unknown')}\n\n"
            f"Reasoning:\n{ai.get('reasoning', '')}\n\n"
        )

        # Add full AI statement if available
        # full_statement = ai.get('full_ai_statement', '')
        # if full_statement and full_statement != ai.get('reasoning', ''):
            # reasoning_content += f"Full AI Analysis:\n{full_statement}\n\n"

        reasoning_box = tk.Text(main_frame, wrap="word", font=("Inter", 10), bg="#F8FAFC", fg=self.colors["text_primary"], relief="flat", padx=10, pady=10)
        reasoning_box.insert("1.0", reasoning_content)
        reasoning_box.configure(state="disabled")
        reasoning_box.pack(fill="both", expand=True)

    def __del__(self):
        """Cleanup when object is destroyed"""
        if hasattr(self, 'session') and self.session:
            self.session.close()

    # ---------------- Entry point ----------------
def main():
    root = tk.Tk()
    app = CaseAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()