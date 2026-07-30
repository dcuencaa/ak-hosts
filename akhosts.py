import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import json
import csv
import threading
import re
import requests
import os
from akamai.edgegrid import EdgeGridAuth, EdgeRc

class AkamaiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Akamai Hostname Tool")
        self.root.geometry("1100x700")
        
        style = ttk.Style()
        style.theme_use('clam')
        
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Authentication Overrides (Optional) ---
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication Overrides (Optional)", padding="10")
        auth_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(auth_frame, text=".edgerc Path:").grid(row=0, column=0, sticky=tk.W, pady=2, padx=(0, 5))
        self.edgerc_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.edgerc_var, width=40).grid(row=0, column=1, sticky=tk.W, pady=2, padx=(0, 5))
        ttk.Button(auth_frame, text="Browse", command=self.browse_edgerc).grid(row=0, column=2, sticky=tk.W, pady=2)
        
        ttk.Label(auth_frame, text="Section:").grid(row=1, column=0, sticky=tk.W, pady=2, padx=(0, 5))
        self.section_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.section_var, width=20).grid(row=1, column=1, sticky=tk.W, pady=2, padx=(0, 5))
        
        # --- Step 1: Search ---
        ttk.Label(main_frame, text="Step 1: Search Account", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.search_btn = ttk.Button(search_frame, text="Search", command=self.start_search_thread)
        self.search_btn.pack(side=tk.LEFT)
        
        self.account_status = ttk.Label(search_frame, text="")
        self.account_status.pack(side=tk.LEFT, padx=(10, 0))
        
        # --- Step 2: Select ---
        ttk.Label(main_frame, text="Step 2: Select Account", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        select_frame = ttk.Frame(main_frame)
        select_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.account_var = tk.StringVar()
        self.account_dropdown = ttk.Combobox(select_frame, textvariable=self.account_var, state="readonly", width=50)
        self.account_dropdown.pack(side=tk.LEFT, padx=(0, 10))
        
        self.fetch_btn = ttk.Button(select_frame, text="Get Hostnames", command=self.start_fetch_thread, state=tk.DISABLED)
        self.fetch_btn.pack(side=tk.LEFT)
        
        self.hostname_status = ttk.Label(select_frame, text="")
        self.hostname_status.pack(side=tk.LEFT, padx=(10, 0))
        
        self.account_map = {}
        
        # --- Step 3: Results Table ---
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.columns = ("Hostname", "CertType", "EdgeHostname", "PropertyName", "DNS CNAME", "Slot", "DV Challenge Hostname", "DV Challenge Target")
        self.tree = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        
        for col in self.columns:
            self.tree.heading(col, text=col)
            # Adjust column widths based on expected data length
            width = 180 if "Target" in col or "Hostname" in col else 120
            self.tree.column(col, minwidth=100, width=width)
            
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=scrollbar.set, xscroll=scrollbar_x.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # --- Enrichment & Export Buttons ---
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(15, 0))
        
        self.dns_btn = ttk.Button(action_frame, text="Fetch DNS Details", command=self.start_dns_thread, state=tk.DISABLED)
        self.dns_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.dv_btn = ttk.Button(action_frame, text="Get DV Challenges", command=self.start_dv_thread, state=tk.DISABLED)
        self.dv_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_btn = ttk.Button(action_frame, text="Export to CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.RIGHT)

    # --- UI Helpers ---
    def browse_edgerc(self):
        file_path = filedialog.askopenfilename(title="Select .edgerc File")
        if file_path:
            self.edgerc_var.set(file_path)

    def get_auth_flags(self):
        flags = ""
        edgerc = self.edgerc_var.get().strip()
        section = self.section_var.get().strip()
        if edgerc: flags += f" -Edgerc '{edgerc}'"
        if section: flags += f" -Section '{section}'"
        return flags

    # --- PowerShell Execution Helper ---
    def run_powershell(self, command):
        strict_command = f"$ErrorActionPreference = 'Stop'; {command}"
        process = subprocess.Popen(['pwsh', '-Command', strict_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise Exception(f"{stderr.strip() or stdout.strip()}")
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            raise Exception("Failed to parse PowerShell JSON output.")

    # --- Core Tool Logic: Search & Fetch Hosts ---
    def start_search_thread(self):
        self.search_btn.config(state=tk.DISABLED)
        self.account_status.config(text="Searching... please wait.", foreground="blue")
        self.account_dropdown.set('')
        self.account_dropdown['values'] = []
        self.fetch_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.search_accounts, daemon=True).start()

    def search_accounts(self):
        search_query = self.search_var.get().strip()
        ps_arg = f"'{search_query}'" if search_query else ""
        command = f"Get-AccountSwitchKey {ps_arg}{self.get_auth_flags()} | Select-Object accountName, accountSwitchKey | ConvertTo-Json"
        try:
            data = self.run_powershell(command)
            self.account_map.clear()
            options = []
            for acc in data:
                name = acc.get("accountName", acc.get("AccountName", "Unknown Account"))
                key = acc.get("accountSwitchKey", acc.get("AccountSwitchKey", "*"))
                if key != '*':
                    display_text = f"{name} ({key})"
                    self.account_map[display_text] = key
                    options.append(display_text)
            self.root.after(0, self.update_search_ui, options)
        except Exception as e:
            self.root.after(0, self.show_error, "account_status", str(e), self.search_btn)

    def update_search_ui(self, options):
        self.search_btn.config(state=tk.NORMAL)
        if not options:
            self.account_status.config(text="No matching accounts found.", foreground="red")
        else:
            self.account_status.config(text=f"Found {len(options)} accounts.", foreground="green")
            self.account_dropdown['values'] = options
            self.account_dropdown.current(0)
            self.fetch_btn.config(state=tk.NORMAL)

    def start_fetch_thread(self):
        selected = self.account_var.get()
        if not selected: return
        self.fetch_btn.config(state=tk.DISABLED)
        self.dns_btn.config(state=tk.DISABLED)
        self.dv_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        self.hostname_status.config(text="Fetching domains... please wait.", foreground="blue")
        for row in self.tree.get_children(): self.tree.delete(row)
        threading.Thread(target=self.fetch_hostnames, args=(self.account_map[selected],), daemon=True).start()

    def fetch_hostnames(self, switch_key):
        command = f"Get-PropertyHostname -AccountSwitchKey {switch_key} -Network PRODUCTION{self.get_auth_flags()} | Select-Object cnameFrom, productionCertType, productionCnameTo, propertyName | ConvertTo-Json"
        try:
            data = self.run_powershell(command)
            self.root.after(0, self.update_table_ui, data)
        except Exception as e:
            self.root.after(0, self.show_error, "hostname_status", str(e), self.fetch_btn)

    def update_table_ui(self, data):
        self.fetch_btn.config(state=tk.NORMAL)
        if not data:
            self.hostname_status.config(text="No hostnames found.", foreground="red")
            return
            
        self.hostname_status.config(text=f"Loaded {len(data)} hostnames.", foreground="green")
        for item in data:
            self.tree.insert("", tk.END, values=(
                item.get("cnameFrom", "-"), item.get("productionCertType", "-"),
                item.get("productionCnameTo", "-"), item.get("propertyName", "-"),
                "-", "-", "-", "-" # Placeholders for enrichment data
            ))
        self.export_btn.config(state=tk.NORMAL)
        self.dns_btn.config(state=tk.NORMAL)
        self.dv_btn.config(state=tk.NORMAL)

    # --- Enrichment: Fetch DNS Details ---
    def start_dns_thread(self):
        self.dns_btn.config(state=tk.DISABLED)
        self.hostname_status.config(text="Resolving DNS... please wait.", foreground="blue")
        threading.Thread(target=self.fetch_dns_details, daemon=True).start()

    def fetch_dns_details(self):
        cname_pattern = re.compile(r'^(\S+?)\.?\s+\d+\s+IN\s+CNAME\s+(\S+)', re.IGNORECASE)
        akamai_pattern = re.compile(r'^[ae](\d+)\.dsc[a-z]\.akamai(?:edge)?\.net\.?$', re.IGNORECASE)
        
        for row_id in self.tree.get_children():
            values = list(self.tree.item(row_id)['values'])
            hostname = str(values[0]).strip()
            
            if not hostname or hostname.startswith('*'):
                values[4] = "Skipped (Wildcard)"
                values[5] = "-"
            else:
                try:
                    result = subprocess.run(['dig', '+noall', '+answer', hostname], capture_output=True, text=True, check=True)
                    output_lines = result.stdout.strip().split('\n')
                    cname_map = {}
                    slot = ""
                    for line in output_lines:
                        cname_match = cname_pattern.search(line.strip())
                        if cname_match:
                            source = cname_match.group(1).lower()
                            target = cname_match.group(2)
                            cname_map[source] = target
                            akamai_match = akamai_pattern.search(target)
                            if akamai_match:
                                slot = akamai_match.group(1)
                                
                    clean_hostname = hostname.lower().rstrip('.')
                    first_cname = cname_map.get(clean_hostname, "")
                    if not first_cname and cname_map:
                        first_cname = list(cname_map.values())[0]
                        
                    values[4] = first_cname if first_cname else "No CNAME found"
                    values[5] = slot if slot else "Not Found"
                except FileNotFoundError:
                    self.root.after(0, self.show_error, "hostname_status", "'dig' command not found on OS.", self.dns_btn)
                    return
                except Exception:
                    values[4] = "Error resolving"
                    values[5] = "-"
            
            # Update the specific row
            self.root.after(0, lambda r=row_id, v=values: self.tree.item(r, values=v))
            
        self.root.after(0, lambda: self.hostname_status.config(text="DNS resolution complete.", foreground="green"))
        self.root.after(0, lambda: self.dns_btn.config(state=tk.NORMAL))

    # --- Enrichment: Fetch DV Challenges ---
    def start_dv_thread(self):
        self.dv_btn.config(state=tk.DISABLED)
        self.hostname_status.config(text="Fetching DV Challenges via API... please wait.", foreground="blue")
        threading.Thread(target=self.fetch_dv_challenges, daemon=True).start()

    def fetch_dv_challenges(self):
        try:
            # Setup Authentication via standard paths or overrides
            edgerc_path = os.path.expanduser(self.edgerc_var.get().strip() or '~/.edgerc')
            section = self.section_var.get().strip() or 'default'
            
            edgerc = EdgeRc(edgerc_path)
            base_url = 'https://%s' % edgerc.get(section, 'host')
            session = requests.Session()
            session.auth = EdgeGridAuth.from_edgerc(edgerc, section)
            
            ask = self.account_map.get(self.account_var.get())
            hostnames_to_check = []
            row_map = {}
            
            # Gather hostnames from table
            for row_id in self.tree.get_children():
                values = list(self.tree.item(row_id)['values'])
                raw_hostname = str(values[0]).strip()
                if raw_hostname and not raw_hostname.startswith('*'):
                    clean_hostname = raw_hostname.rstrip('.')
                    hostnames_to_check.append(clean_hostname)
                    row_map[clean_hostname] = row_id
                else:
                    values[6] = "Skipped (Wildcard)"
                    self.root.after(0, lambda r=row_id, v=values: self.tree.item(r, values=v))
            
            challenge_map = {}
            chunk_size = 20
            
            # Batch API requests
            for i in range(0, len(hostnames_to_check), chunk_size):
                chunk = hostnames_to_check[i:i+chunk_size]
                endpoint = f"{base_url}/papi/v1/hostnames/certificate-challenges"
                if ask: endpoint += f"?accountSwitchKey={ask}"
                
                headers = {"accept": "application/json", "content-type": "application/json"}
                response = session.post(endpoint, json={"cnamesFrom": chunk}, headers=headers)
                response.raise_for_status()
                
                items = response.json().get('hostnames', {}).get('items', [])
                for item in items:
                    cname = item.get('cnameFrom', '').strip().lower().rstrip('.')
                    val_cname = item.get('validationCname')
                    val_http = item.get('validationHttp')
                    gen_chal = item.get('challenge')
                    
                    if val_cname: challenge_map[cname] = (val_cname.get('hostname', ''), val_cname.get('target', ''))
                    elif val_http: challenge_map[cname] = ('HTTP', val_http.get('url', ''))
                    elif gen_chal: challenge_map[cname] = ('OTHER', json.dumps(gen_chal))

            # Apply mapping back to table
            for clean_hostname, row_id in row_map.items():
                values = list(self.tree.item(row_id)['values'])
                if clean_hostname in challenge_map:
                    values[6], values[7] = challenge_map[clean_hostname]
                else:
                    values[6], values[7] = ("Not Found", "-")
                self.root.after(0, lambda r=row_id, v=values: self.tree.item(r, values=v))

            self.root.after(0, lambda: self.hostname_status.config(text=f"Fetched challenges for {len(challenge_map)} items.", foreground="green"))
            
        except requests.exceptions.RequestException as e:
            self.root.after(0, self.show_error, "hostname_status", f"API Error: {e}", self.dv_btn)
        except Exception as e:
            self.root.after(0, self.show_error, "hostname_status", f"Auth/Setup Error: {e}", self.dv_btn)
        finally:
            self.root.after(0, lambda: self.dv_btn.config(state=tk.NORMAL))

    # --- Export Logic ---
    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save Hostnames as CSV")
        if not file_path: return
            
        try:
            with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(self.columns)
                for row_id in self.tree.get_children():
                    writer.writerow(self.tree.item(row_id)['values'])
            messagebox.showinfo("Success", f"Data successfully exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def show_error(self, status_label, error_msg, button_to_enable):
        label = getattr(self, status_label)
        label.config(text="Error occurred (see popup)", foreground="red")
        button_to_enable.config(state=tk.NORMAL)
        messagebox.showerror("Execution Error", error_msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = AkamaiApp(root)
    root.mainloop()
