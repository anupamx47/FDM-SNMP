Configure SNMP on FDM Script

This script is designed to configure SNMP on a Firepower Device Manager (FDM). It allows the user to authenticate with the device, create SNMP host objects, and configure SNMPv2 or SNMPv3 users.

Features

- Authenticate with an FDM device using username and password.
- Create SNMP host objects with specified IP addresses.
- Configure SNMPv2 with a community string.
- Configure SNMPv3 users with specified security levels, authentication, and encryption settings.
- Select and configure network interfaces and subinterfaces for SNMP.

Prerequisites

- Python 3.x
- requests library: Install via pip install requests
- Access to the target FDM device

Usage

1. Clone the Repository:
   git clone <repository-url>
   cd <repository-directory>

2. Run the Script:
   python configure_snmp_fdm.py

3. Input Required Information:
   - Enter the device IP address.
   - Enter the username and password for the FTD device.
   - Choose between configuring SNMPv2 or SNMPv3.
   - Provide additional details based on the chosen SNMP version.

4. Select Interface:
   - Select a primary interface and, if available, a subinterface.

5. Create SNMP Host:
   - Enter the SNMP host object name.

Important Notes

- Security: Ensure that you handle authentication credentials securely and avoid hardcoding sensitive information in the script.
- Warnings: The script disables warnings for unverified HTTPS requests, which is not recommended for production environments. Modify the script to enable certificate verification for production use.
- Error Handling: The script includes basic error handling and will exit if errors occur during requests to the FDM API.

Author

- Anupam Pavithran (anpavith@cisco.com)

Version

- 1.2.0

Disclaimer

This script is provided as-is without any guarantees or support. Use it at your own risk. Ensure compliance with your organization's security policies when using this script.
