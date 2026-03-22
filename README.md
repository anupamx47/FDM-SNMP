Configure SNMP on FDM

Full CRUD (Create, Read, Update, Delete) management of SNMP configuration on a Firepower Device Manager (FDM) via its REST API. Supports SNMPv2c and SNMPv3. Available as both a **CLI tool** and a **Web GUI**.

Features

- Authenticate with an FDM device using username and password.
- **Create** SNMP host objects, SNMPv2c community strings, and SNMPv3 users.
- **Read** / list all SNMP hosts, SNMPv3 users, and SNMP server settings.
- **Update** SNMP hosts (poll/trap toggles, interface), SNMPv3 users (security level, auth, encryption), and SNMP server settings (contact, location).
- **Delete** SNMP hosts and SNMPv3 users with confirmation prompts.
- Select and configure network interfaces, VLANs, port-channels, and subinterfaces for SNMP.
- **Web GUI** — browser-based interface with tabbed views, modals, and toast notifications.
- **SNMPv3 user dropdown** — when creating an SNMP host with v3, pick an existing user or create a new one.
- **Logging** — all operations are logged to `fdm-snmp.log` for troubleshooting.
- **Download Logs** — one-click log download from the web GUI.

Prerequisites

- Python 3.x
- `requests` library: Install via `pip install requests`
- Access to the target FDM device

Files

| File | Description |
|---|---|
| `fdm-snmp.py` | CLI version — terminal-based menu interface |
| `fdm-snmp-gui.py` | Web GUI version — browser-based interface |
| `requirements.txt` | Python dependencies |

Usage

1. Clone the Repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install Dependencies:
   ```
   pip install -r requirements.txt
   ```

3. **CLI Version:**
   ```
   python fdm-snmp.py
   ```
   Follow the interactive menu:
   ```
   1. Create SNMP Configuration
   2. View SNMP Configuration
   3. Update SNMP Configuration
   4. Delete SNMP Configuration
   5. Exit
   ```

4. **Web GUI Version:**
   ```
   python fdm-snmp-gui.py            # default port 8889
   python fdm-snmp-gui.py 9000       # custom port
   ```
   Opens your browser automatically to `http://127.0.0.1:8889`. Features:
   - **SNMP Hosts** tab — create, list, view details, update, delete
   - **SNMPv3 Users** tab — create, list, view details, update, delete
   - **Server Settings** tab — view/edit contact and location
   - **Download Logs** button — download `fdm-snmp.log` for troubleshooting

Logging

All API operations are logged to `fdm-snmp.log` in the script directory. If you encounter issues, download the log file from the GUI or share it directly for troubleshooting.

Important Notes

- **Security**: Ensure that you handle authentication credentials securely and avoid hardcoding sensitive information in the script.
- **Warnings**: The script disables warnings for unverified HTTPS requests, which is not recommended for production environments. Modify the script to enable certificate verification for production use.
- **Error Handling**: The script includes error handling and will log errors to `fdm-snmp.log`. The GUI displays errors as toast notifications.

Author

- Anupam Pavithran (anpavith@cisco.com)

Version

- 2.0.0

Disclaimer

This script is provided as-is without any guarantees or support. Use it at your own risk. Ensure compliance with your organization's security policies when using this script.
