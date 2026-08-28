# Akamai Hostnames App

Application for managing Akamai account hostnames and migrations to Secure by Default. It allows users to search accounts, retrieve production hostnames, resolve DNS CNAMEs and Akamai slots (using `dig`), and fetch active DV challenges directly from the Akamai API, and migrated hostnames to Secure By Default settings in PM. 

Results can be exported to a consolidated CSV file.

## System Prerequisites

Your system must have the following installed:
1. **PowerShell Core (`pwsh`)** with the **Akamai PowerShell Module** installed.
2. **`dig`** (command-line DNS lookup utility, native to most macOS/Linux systems).
3. A valid **`.edgerc`** credential file (used for both PowerShell commands and API authentication).

## Python Requirements

The app utilizes Python's built-in libraries (like `tkinter` for the GUI and `subprocess` for PowerShell execution) along with a few external packages for API requests:
* `edgegrid-python`
* `requests`

## Installation & Setup

To protect your system's default Python environment, it is highly recommended to run this app inside a virtual environment.

**1. Navigate to the project folder:**
```bash
cd /path/to/akamai_hostname_app/python_version/

**2. Create a virtual environment:**
python3 -m venv venv

**3. Activate the virtual environment:**
source venv/bin/activate

**4. Install the required Python packages:**
pip install edgegrid-python requests

How to run:
# Activate the environment (if starting a new terminal session)
source venv/bin/activate

# Run the app
python akhosts.py
