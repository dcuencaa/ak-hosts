import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import json
import csv
import threading
import re
import requests
import os
import base64
import sys
from akamai.edgegrid import EdgeGridAuth, EdgeRc

# Global Debug Flag: Run with `python akhosts.py --debug` to enable terminal logging
DEBUG_MODE = "--debug" in sys.argv

class AkamaiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Akamai Hostname Tool")
        self.root.geometry("1150x750")
        
        # --- Custom Goose Icon Loader ---
        try:
            icon_path = self.get_resource_path("goose.png")
            if os.path.exists(icon_path):
                img = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, img)
        except Exception as e:
            if DEBUG_MODE: print(f"[DEBUG] Could not load goose icon: {e}")

        style = ttk.Style()
        style.theme_use('clam')
        
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Authentication Overrides (Optional) ---
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication Overrides (Optional)", padding="10")
        auth_frame.pack(fill=tk.X, pady=(0, 10))
        
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
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.search_btn = ttk.Button(search_frame, text="Search", command=self.start_search_thread)
        self.search_btn.pack(side=tk.LEFT)
        
        self.account_status = ttk.Label(search_frame, text="")
        self.account_status.pack(side=tk.LEFT, padx=(10, 0))
        
        # --- Step 2: Select ---
        ttk.Label(main_frame, text="Step 2: Select Account & Environment", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        select_frame = ttk.Frame(main_frame)
        select_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.account_var = tk.StringVar()
        self.account_dropdown = ttk.Combobox(select_frame, textvariable=self.account_var, state="readonly", width=40)
        self.account_dropdown.pack(side=tk.LEFT, padx=(0, 10))
        
        self.env_var = tk.StringVar(value="Production")
        self.env_dropdown = ttk.Combobox(select_frame, textvariable=self.env_var, state="readonly", width=15)
        self.env_dropdown['values'] = ("Production", "Staging")
        self.env_dropdown.pack(side=tk.LEFT, padx=(0, 10))
        
        self.fetch_btn = ttk.Button(select_frame, text="Get Hostnames", command=self.start_fetch_thread, state=tk.DISABLED)
        self.fetch_btn.pack(side=tk.LEFT)
        
        self.hostname_status = ttk.Label(select_frame, text="")
        self.hostname_status.pack(side=tk.LEFT, padx=(10, 0))
        
        self.account_map = {}
        
        # --- Step 3: Results Table ---
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.columns = ("Migrate", "Hostname", "CertType", "EdgeHostname", "PropertyName", "DNS CNAME", "Slot", "DV Challenge Hostname", "DV Challenge Target")
        self.tree = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        
        # Configure the Light Blue Highlight Tag
        self.tree.tag_configure("selected_row", background="#d0ebff")
        
        for col in self.columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))
            width = 60 if col == "Migrate" else (180 if "Target" in col or "Hostname" in col else 120)
            anchor = tk.CENTER if col == "Migrate" else tk.W
            self.tree.column(col, minwidth=60, width=width, anchor=anchor)
            
        self.tree.bind('<ButtonRelease-1>', self.toggle_checkbox)
            
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=scrollbar.set, xscroll=scrollbar_x.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # --- Enrichment & Export Buttons ---
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.dns_btn = ttk.Button(action_frame, text="Fetch DNS Details", command=self.start_dns_thread, state=tk.DISABLED)
        self.dns_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.dv_btn = ttk.Button(action_frame, text="Get DV Challenges", command=self.start_dv_thread, state=tk.DISABLED)
        self.dv_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_btn = ttk.Button(action_frame, text="Export to CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.RIGHT)

        # --- MIGRATION CONTROLS ---
        migration_frame = ttk.LabelFrame(main_frame, text="Migration: CPS_MANAGED to DEFAULT", padding="10")
        migration_frame.pack(fill=tk.X, pady=(15, 0))

        self.select_all_btn = ttk.Button(migration_frame, text="Select / Deselect All", command=self.toggle_all_checkboxes, state=tk.DISABLED)
        self.select_all_btn.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(migration_frame, text="Action:").pack(side=tk.LEFT, padx=(0, 5))
        self.migrate_action_var = tk.StringVar(value="Save Only")
        self.migrate_dropdown = ttk.Combobox(migration_frame, textvariable=self.migrate_action_var, state="readonly", width=20)
        self.migrate_dropdown['values'] = ("Save Only", "Activate (Staging)")
        self.migrate_dropdown.pack(side=tk.LEFT, padx=(0, 15))

        self.migrate_btn = ttk.Button(migration_frame, text="Migrate Selected Hostnames", command=self.start_migrate_thread, state=tk.DISABLED)
        self.migrate_btn.pack(side=tk.LEFT)

    # --- File/Path Helper for PyInstaller ---
    def get_resource_path(self, relative_path):
        """ Get absolute path to resource, works for development and for PyInstaller """
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    # --- UI Helpers ---
    def sort_column(self, col, reverse):
        item_list = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        item_list.sort(reverse=reverse)
        for index, (val, k) in enumerate(item_list):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda _col=col: self.sort_column(_col, not reverse))

    def browse_edgerc(self):
        file_path = filedialog.askopenfilename(title="Select .edgerc File")
        if file_path: self.edgerc_var.set(file_path)

    def get_auth_flags(self):
        flags = ""
        if self.edgerc_var.get().strip(): flags += f" -Edgerc '{self.edgerc_var.get().strip()}'"
        if self.section_var.get().strip(): flags += f" -Section '{self.section_var.get().strip()}'"
        return flags

    def toggle_checkbox(self, event):
        if self.tree.identify("region", event.x, event.y) != "cell": return
        if self.tree.identify_column(event.x) == "#1":
            item_id = self.tree.identify_row(event.y)
            if not item_id: return
            values = list(self.tree.item(item_id, "values"))
            
            if values[0] == "[ ]":
                values[0] = "[X]"
                self.tree.item(item_id, values=values, tags=("selected_row",))
            elif values[0] == "[X]":
                values[0] = "[ ]"
                self.tree.item(item_id, values=values, tags=())

    def toggle_all_checkboxes(self):
        target_state = "[X]"
        for row_id in self.tree.get_children():
            if self.tree.item(row_id, "values")[0] == "[ ]":
                target_state = "[X]"
                break
            if self.tree.item(row_id, "values")[0] == "[X]":
                target_state = "[ ]"
                
        for row_id in self.tree.get_children():
            values = list(self.tree.item(row_id, "values"))
            if values[0] in ("[ ]", "[X]"):
                values[0] = target_state
                if target_state == "[X]":
                    self.tree.item(row_id, values=values, tags=("selected_row",))
                else:
                    self.tree.item(row_id, values=values, tags=())

    # --- PowerShell Execution Helper ---
    def run_powershell(self, command):
        if DEBUG_MODE:
            print(f"\n[DEBUG] Executing: {command}")
            
        strict_command = f"$ErrorActionPreference = 'Stop'; {command}"
        process = subprocess.Popen(['pwsh', '-Command', strict_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if DEBUG_MODE:
            print(f"[DEBUG] Return Code: {process.returncode}")
            if stderr.strip(): 
                print(f"[DEBUG] STDERR: {stderr.strip()}")
            if stdout.strip(): 
                if "Get-PropertyHostname" in command:
                    print("[DEBUG] STDOUT: <Omitted due to payload size>")
                else:
                    print(f"[DEBUG] STDOUT: {stdout.strip()[:300]}") 
        
        if process.returncode != 0: raise Exception(f"{stderr.strip() or stdout.strip()}")
        
        if not stdout.strip():
            if DEBUG_MODE: print("[DEBUG] PowerShell returned completely empty output.")
            return []
            
        try:
            data = json.loads(stdout)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            if DEBUG_MODE: print(f"[DEBUG] JSON Parse Failed. Raw Output:\n{stdout}")
            raise Exception("Failed to parse PowerShell JSON output.")

    # --- Fetching Logic ---
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
        if not options: self.account_status.config(text="No matching accounts found.", foreground="red")
        else:
            self.account_status.config(text=f"Found {len(options)} accounts.", foreground="green")
            self.account_dropdown['values'] = options
            self.account_dropdown.current(0)
            self.fetch_btn.config(state=tk.NORMAL)

    def start_fetch_thread(self):
        if not self.account_var.get(): return
        self.fetch_btn.config(state=tk.DISABLED)
        for btn in [self.dns_btn, self.dv_btn, self.export_btn, self.select_all_btn, self.migrate_btn]: btn.config(state=tk.DISABLED)
        self.hostname_status.config(text="Fetching domains... please wait.", foreground="blue")
        for row in self.tree.get_children(): self.tree.delete(row)
        
        env_selection = self.env_var.get()
        threading.Thread(target=self.fetch_hostnames, args=(self.account_map[self.account_var.get()], env_selection), daemon=True).start()

    def fetch_hostnames(self, switch_key, env_selection):
        target_flag = "-Network STAGING" if env_selection == "Staging" else "-Network PRODUCTION"
        
        command = f"Get-PropertyHostname -AccountSwitchKey {switch_key} {target_flag} {self.get_auth_flags()} | Select-Object cnameFrom, productionCertType, stagingCertType, productionCnameTo, stagingCnameTo, propertyName | ConvertTo-Json"
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
            
        env_selection = self.env_var.get()
        self.hostname_status.config(text=f"Loaded {len(data)} hostnames. (Showing: {env_selection})", foreground="green")
        
        for item in data:
            cname = item.get("cnameFrom", "-")
            
            raw_cert = item.get("productionCertType") or item.get("stagingCertType") or ""
            cert_type = str(raw_cert).upper()
            
            cname_to = item.get("productionCnameTo") or item.get("stagingCnameTo") or "-"
            
            is_akamaized = str(cname).lower().endswith(".akamaized.net") or str(cname).lower().endswith(".akamaized-staging.net")
            migrate_val = "[-]" if cert_type == "DEFAULT" or is_akamaized else "[ ]"
            
            self.tree.insert("", tk.END, values=(
                migrate_val, cname, cert_type,
                cname_to, item.get("propertyName", "-"),
                "-", "-", "-", "-" 
            ), tags=())
            
        for btn in [self.dns_btn, self.dv_btn, self.export_btn, self.select_all_btn, self.migrate_btn]: btn.config(state=tk.NORMAL)

    # --- Migration Logic ---
    def start_migrate_thread(self):
        selected_groups = {}
        for row_id in self.tree.get_children():
            values = self.tree.item(row_id, "values")
            if values[0] == "[X]":
                prop = values[4]
                if prop not in selected_groups: selected_groups[prop] = []
                selected_groups[prop].append(values[1])
                
        if not selected_groups:
            messagebox.showinfo("No Selection", "Please select at least one hostname to migrate.")
            return

        confirm = messagebox.askyesno("Confirm Migration", f"You are about to modify {sum(len(h) for h in selected_groups.values())} hostnames across {len(selected_groups)} properties.\n\nNote: Migrations always branch from the active PRODUCTION version.\nProceed?")
        if not confirm: return

        self.migrate_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.execute_migration, args=(selected_groups,), daemon=True).start()

    def execute_migration(self, grouped_hosts):
        action = self.migrate_action_var.get()
        switch_key = self.account_map.get(self.account_var.get())
        auth_flags = self.get_auth_flags()

        for prop, hosts in grouped_hosts.items():
            self.root.after(0, lambda p=prop: self.hostname_status.config(text=f"Migrating property {p}...", foreground="blue"))
            hosts_ps_array = ",".join([f"'{h}'" for h in hosts])
            
            script = f"""
$ErrorActionPreference = 'Stop'
$propertyName = '{prop}'
$accountKey = '{switch_key}'
$selectedHosts = @({hosts_ps_array})
$note = 'akhosts: SBD migration'

# 1. Create the new Draft
$newVersion = New-PropertyVersion -PropertyName $propertyName -AccountSwitchKey $accountKey -CreateFromVersion production {auth_flags}

# 2. Safely capture the Draft Version Number
$draft = if ($null -ne $newVersion.PropertyVersion) {{ $newVersion.PropertyVersion }} else {{ $newVersion }}
if (-not $draft) {{ throw "Failed to identify the new draft version number." }}

# 3. Retrieve hostnames directly from the confirmed draft
$hostnames = @(Get-PropertyHostname -PropertyName $propertyName -AccountSwitchKey $accountKey -PropertyVersion $draft {auth_flags})

# 4. Modify properties in memory
$updatedCount = 0
foreach ($h in $hostnames) {{
    if ($selectedHosts -contains $h.cnameFrom) {{
        $h.certProvisioningType = 'DEFAULT'
        $h.cnameType = 'EDGE_HOSTNAME'
        $updatedCount++
    }}
}}

if ($updatedCount -eq 0) {{
    throw "Hostnames matched, but script failed to update them in memory before saving."
}}

# 5. Apply changes back to the Draft
Set-PropertyHostname -PropertyName $propertyName -AccountSwitchKey $accountKey -PropertyVersion $draft -Body $hostnames {auth_flags}
"""
            if action == "Activate (Staging)":
                script += f"\nNew-PropertyActivation -PropertyName $propertyName -AccountSwitchKey $accountKey -PropertyVersion $draft -Network STAGING -Note $note -NotifyEmails 'noreply@akamai.com' {auth_flags}\n"

            try:
                encoded_bytes = script.encode('utf-16-le')
                encoded_str = base64.b64encode(encoded_bytes).decode('utf-8')
                process = subprocess.Popen(['pwsh', '-EncodedCommand', encoded_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                if process.returncode != 0: raise Exception(f"{stderr.strip() or stdout.strip()}")
            except Exception as e:
                self.root.after(0, self.show_error, "hostname_status", f"Failed migrating {prop}:\n{e}", self.migrate_btn)
                return

        success_msg = "Migration complete!\n\nPlease check the draft version in Akamai Control Center to verify the changes."
        self.root.after(0, lambda: self.hostname_status.config(text="Migration processed successfully.", foreground="green"))
        self.root.after(0, lambda: self.migrate_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: messagebox.showinfo("Success", success_msg))

    # --- Enrichment Logic ---
    def start_dns_thread(self):
        self.dns_btn.config(state=tk.DISABLED)
        self.hostname_status.config(text="Resolving DNS... please wait.", foreground="blue")
        threading.Thread(target=self.fetch_dns_details, daemon=True).start()

    def fetch_dns_details(self):
        cname_pattern = re.compile(r'^(\S+?)\.?\s+\d+\s+IN\s+CNAME\s+(\S+)', re.IGNORECASE)
        akamai_pattern = re.compile(r'^[ae](\d+)\.dsc[a-z]\.akamai(?:edge)?\.net\.?$', re.IGNORECASE)
        
        for row_id in self.tree.get_children():
            values = list(self.tree.item(row_id)['values'])
            hostname = str(values[1]).strip()
            if not hostname or hostname.startswith('*'):
                values[5], values[6] = "Skipped (Wildcard)", "-"
            else:
                try:
                    result = subprocess.run(['dig', '+noall', '+answer', hostname], capture_output=True, text=True, check=True)
                    cname_map = {}
                    slot = ""
                    for line in result.stdout.strip().split('\n'):
                        cname_match = cname_pattern.search(line.strip())
                        if cname_match:
                            cname_map[cname_match.group(1).lower()] = cname_match.group(2)
                            akamai_match = akamai_pattern.search(cname_match.group(2))
                            if akamai_match: slot = akamai_match.group(1)
                                
                    clean_hostname = hostname.lower().rstrip('.')
                    first_cname = cname_map.get(clean_hostname, list(cname_map.values())[0] if cname_map else "")
                    values[5] = first_cname if first_cname else "No CNAME found"
                    values[6] = slot if slot else "Not Found"
                except FileNotFoundError:
                    self.root.after(0, self.show_error, "hostname_status", "'dig' command not found on OS.", self.dns_btn)
                    return
                except Exception:
                    values[5], values[6] = "Error resolving", "-"
            
            # Pass existing tags so we don't erase the blue highlight during an update
            self.root.after(0, lambda r=row_id, v=values: self.tree.item(r, values=v, tags=self.tree.item(r, "tags")))
            
        self.root.after(0, lambda: self.hostname_status.config(text="DNS resolution complete.", foreground="green"))
        self.root.after(0, lambda: self.dns_btn.config(state=tk.NORMAL))

    def start_dv_thread(self):
        self.dv_btn.config(state=tk.DISABLED)
        self.hostname_status.config(text="Fetching DV Challenges via API... please wait.", foreground="blue")
        threading.Thread(target=self.fetch_dv_challenges, daemon=True).start()

    def fetch_dv_challenges(self):
        try:
            edgerc_path = os.path.expanduser(self.edgerc_var.get().strip() or '~/.edgerc')
            section = self.section_var.get().strip() or 'default'
            edgerc = EdgeRc(edgerc_path)
            session = requests.Session()
            session.auth = EdgeGridAuth.from_edgerc(edgerc, section)
            
            ask = self.account_map.get(self.account_var.get())
            hostnames_to_check, row_map = [], {}
            
            for row_id in self.tree.get_children():
                values = list(self.tree.item(row_id)['values'])
                raw_hostname = str(values[1]).strip()
                if raw_hostname and not raw_hostname.startswith('*'):
                    clean_hostname = raw_hostname.rstrip('.')
                    hostnames_to_check.append(clean_hostname)
                    row_map[clean_hostname] = row_id
                else:
                    values[7] = "Skipped (Wildcard)"
                    self.root.after(0, lambda r=row_id, v=values: self.tree.item(r, values=v, tags=self.tree.item(r, "tags")))
            
            challenge_map = {}
            for i in range(0, len(hostnames_to_check), 20):
                chunk = hostnames_to_check[i:i+20]
                endpoint = f"https://{edgerc.get(section, 'host')}/papi/v1/hostnames/certificate-challenges"
                if ask: endpoint += f"?accountSwitchKey={ask}"
                
                response = session.post(endpoint, json={"cnamesFrom": chunk}, headers={"accept": "application/json"})
                response.raise_for_status()
                
                for item in response.json().get('hostnames', {}).get('items', []):
                    cname = item.get('cnameFrom', '').strip().lower().rstrip('.')
                    if item.get('validationCname'): challenge_map[cname] = (item['validationCname'].get('hostname', ''), item['validationCname'].get('target', ''))
                    elif item.get('validationHttp'): challenge_map[cname] = ('HTTP', item['validationHttp'].get('url', ''))
                    elif item.get('challenge'): challenge_map[cname] = ('OTHER', json.dumps(item['challenge']))

            for clean_hostname, row_id in row_map.items():
                values = list(self.tree.item(row_id)['values'])
                values[7], values[8] = challenge_map.get(clean_hostname, ("Not Found", "-"))
                self.root.after(0, lambda r=row_id, v=values: self.tree.item(r, values=v, tags=self.tree.item(r, "tags")))

            self.root.after(0, lambda: self.hostname_status.config(text=f"Fetched challenges for {len(challenge_map)} items.", foreground="green"))
            
        except Exception as e:
            self.root.after(0, self.show_error, "hostname_status", f"API/Auth Error: {e}", self.dv_btn)
        finally:
            self.root.after(0, lambda: self.dv_btn.config(state=tk.NORMAL))

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save Hostnames as CSV")
        if not file_path: return
            
        try:
            with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(self.columns[1:])
                for row_id in self.tree.get_children():
                    writer.writerow(self.tree.item(row_id)['values'][1:])
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
