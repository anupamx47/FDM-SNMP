import json
import logging
import os
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests

# Script Metadata
__author__ = "Anupam Pavithran (anpavith@cisco.com)"
__version__ = "2.0.0-web"

requests.packages.urllib3.disable_warnings()

# Logging setup
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fdm-snmp.log')
logger = logging.getLogger('fdm-snmp')
logger.setLevel(logging.DEBUG)
_fh = logging.FileHandler(LOG_FILE, mode='a')
_fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(_fh)

# Global session object, set after login
session = None


class FDMSession:
    """Holds device connection state and provides all FDM API methods."""

    def __init__(self, device, username, password):
        self.device = device
        self.username = username
        self.password = password
        self.token = None

    def base_url(self):
        return "https://" + self.device + "/api/fdm/latest"

    def api_headers(self):
        return {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def authenticate(self):
        url = self.base_url() + "/fdm/token"
        payload = json.dumps({
            "grant_type": "password",
            "username": self.username,
            "password": self.password
        })
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        r = requests.post(url, headers=headers, data=payload, verify=False)
        if r.status_code != 200:
            raise Exception("Auth failed (HTTP %d): %s" % (r.status_code, r.text))
        body = r.json()
        self.token = body.get('access_token')
        if not self.token:
            raise Exception("No access_token in response")
        return self.token

    # --- Network Host Object ---
    def create_hostobj(self, name, ip):
        url = self.base_url() + "/object/networks"
        payload = {
            "name": name, "description": "SNMP Server Host",
            "subType": "HOST", "value": ip,
            "dnsResolution": "IPV4_ONLY", "type": "networkobject"
        }
        r = requests.post(url, headers=self.api_headers(), data=json.dumps(payload), verify=False)
        if r.status_code != 200:
            raise Exception("Create host failed: %s" % r.text)
        return r.json()

    # --- SNMPv3 Users ---
    def create_snmpv3user(self, payload):
        r = requests.post(self.base_url() + "/object/snmpusers",
                          headers=self.api_headers(), data=json.dumps(payload), verify=False)
        if r.status_code != 200:
            raise Exception("Create SNMPv3 user failed: %s" % r.text)
        return r.json()

    def list_snmpv3users(self):
        r = requests.get(self.base_url() + "/object/snmpusers",
                         headers=self.api_headers(), verify=False)
        if r.status_code != 200:
            raise Exception("List SNMPv3 users failed: %s" % r.text)
        return r.json().get('items', [])

    def get_snmpv3user(self, user_id):
        r = requests.get(self.base_url() + "/object/snmpusers/" + user_id,
                         headers=self.api_headers(), verify=False)
        if r.status_code != 200:
            raise Exception("Get SNMPv3 user failed: %s" % r.text)
        return r.json()

    def update_snmpv3user(self, user_id, payload):
        r = requests.put(self.base_url() + "/object/snmpusers/" + user_id,
                         headers=self.api_headers(), data=json.dumps(payload), verify=False)
        if r.status_code != 200:
            raise Exception("Update SNMPv3 user failed: %s" % r.text)
        return r.json()

    def delete_snmpv3user(self, user_id):
        r = requests.delete(self.base_url() + "/object/snmpusers/" + user_id,
                            headers=self.api_headers(), verify=False)
        if r.status_code not in [200, 204]:
            raise Exception("Delete SNMPv3 user failed: %s" % r.text)
        return True

    # --- Interfaces ---
    def list_interfaces(self):
        valid = []
        for endpoint in [
            "/devices/default/interfaces?limit=25",
            "/devices/default/vlaninterfaces?limit=25",
            "/devices/default/etherchannelinterfaces"
        ]:
            try:
                r = requests.get(self.base_url() + endpoint,
                                 headers=self.api_headers(), verify=False)
                if r.status_code == 200:
                    for iface in r.json().get('items', []):
                        if iface.get('name'):
                            valid.append(iface)
            except Exception:
                pass
        return valid

    # --- SNMP Hosts ---
    def create_snmphost(self, snmp_hostname, host_obj, sec_config, iface):
        payload = {
            "name": snmp_hostname,
            "managerAddress": {
                "version": host_obj['version'], "name": host_obj['name'],
                "id": host_obj['id'], "type": host_obj['type']
            },
            "pollEnabled": True, "trapEnabled": True,
            "securityConfiguration": sec_config,
            "interface": {
                "version": iface['version'], "name": iface['name'],
                "id": iface['id'], "type": iface['type']
            },
            "type": "snmphost"
        }
        r = requests.post(self.base_url() + "/object/snmphosts",
                          headers=self.api_headers(), data=json.dumps(payload), verify=False)
        if r.status_code != 200:
            raise Exception("Create SNMP host failed: %s" % r.text)
        return r.json()

    def list_snmphosts(self):
        r = requests.get(self.base_url() + "/object/snmphosts",
                         headers=self.api_headers(), verify=False)
        if r.status_code != 200:
            raise Exception("List SNMP hosts failed: %s" % r.text)
        return r.json().get('items', [])

    def get_snmphost(self, host_id):
        r = requests.get(self.base_url() + "/object/snmphosts/" + host_id,
                         headers=self.api_headers(), verify=False)
        if r.status_code != 200:
            raise Exception("Get SNMP host failed: %s" % r.text)
        return r.json()

    def update_snmphost(self, host_id, payload):
        r = requests.put(self.base_url() + "/object/snmphosts/" + host_id,
                         headers=self.api_headers(), data=json.dumps(payload), verify=False)
        if r.status_code != 200:
            raise Exception("Update SNMP host failed: %s" % r.text)
        return r.json()

    def delete_snmphost(self, host_id):
        r = requests.delete(self.base_url() + "/object/snmphosts/" + host_id,
                            headers=self.api_headers(), verify=False)
        if r.status_code not in [200, 204]:
            raise Exception("Delete SNMP host failed: %s" % r.text)
        return True

    # --- SNMP Server Settings ---
    def get_snmp_server(self):
        r = requests.get(self.base_url() + "/devicesettings/default/snmpservers",
                         headers=self.api_headers(), verify=False)
        if r.status_code != 200:
            raise Exception("Get SNMP server failed: %s" % r.text)
        items = r.json().get('items', [])
        return items[0] if items else None

    def update_snmp_server(self, server_id, payload):
        r = requests.put(self.base_url() + "/devicesettings/default/snmpservers/" + server_id,
                         headers=self.api_headers(), data=json.dumps(payload), verify=False)
        if r.status_code != 200:
            raise Exception("Update SNMP server failed: %s" % r.text)
        return r.json()


# ==================== HTTP Request Handler ====================

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Suppress default request logging; keep console clean
        pass

    def _send_file(self, filepath, content_type, filename):
        try:
            with open(filepath, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", "attachment; filename=\"%s\"" % filename)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self._send_json({"error": "Log file not found"}, 404)

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self._send_html(HTML_PAGE)
            return

        if path == "/api/logs":
            self._send_file(LOG_FILE, "text/plain", "fdm-snmp.log")
            return

        if session is None:
            self._send_json({"error": "Not authenticated"}, 401)
            return

        try:
            if path == "/api/snmphosts":
                logger.info("GET list SNMP hosts")
                self._send_json(session.list_snmphosts())
            elif path.startswith("/api/snmphosts/"):
                logger.info("GET SNMP host %s" % path.split("/")[-1])
                self._send_json(session.get_snmphost(path.split("/")[-1]))
            elif path == "/api/snmpusers":
                logger.info("GET list SNMPv3 users")
                self._send_json(session.list_snmpv3users())
            elif path.startswith("/api/snmpusers/"):
                logger.info("GET SNMPv3 user %s" % path.split("/")[-1])
                self._send_json(session.get_snmpv3user(path.split("/")[-1]))
            elif path == "/api/interfaces":
                logger.info("GET list interfaces")
                self._send_json(session.list_interfaces())
            elif path == "/api/snmpserver":
                logger.info("GET SNMP server settings")
                self._send_json(session.get_snmp_server())
            elif path == "/api/status":
                self._send_json({"authenticated": True, "device": session.device})
            else:
                self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            logger.error("GET %s failed: %s" % (path, str(e)))
            self._send_json({"error": str(e)}, 500)

    def do_POST(self):
        global session
        path = urlparse(self.path).path
        body = self._read_body()

        try:
            if path == "/api/login":
                device = body.get("device", "").strip()
                username = body.get("username", "").strip()
                password = body.get("password", "")
                if not all([device, username, password]):
                    self._send_json({"error": "All fields required"}, 400)
                    return
                logger.info("Login attempt to %s as %s" % (device, username))
                s = FDMSession(device, username, password)
                s.authenticate()
                session = s
                logger.info("Login successful to %s" % device)
                self._send_json({"ok": True, "device": device})
                return

            if session is None:
                self._send_json({"error": "Not authenticated"}, 401)
                return

            if path == "/api/snmphosts":
                host_obj = session.create_hostobj(body['hostObjName'], body['hostObjIP'])
                ver = body.get('snmpVersion', 'v2c')
                if ver == 'v3':
                    if body.get('v3CreateNew', True):
                        v3p = {
                            "type": "snmpuser", "name": body['v3Username'],
                            "securityLevel": body['v3SecLevel']
                        }
                        if body['v3SecLevel'] in ['AUTH', 'PRIV']:
                            v3p['authenticationAlgorithm'] = body['v3AuthAlg']
                            v3p['authenticationPassword'] = body['v3AuthPw']
                        if body['v3SecLevel'] == 'PRIV':
                            v3p['encryptionAlgorithm'] = body['v3EncAlg']
                            v3p['encryptionPassword'] = body['v3EncPw']
                        user = session.create_snmpv3user(v3p)
                    else:
                        user = body['v3ExistingUser']
                    sec_config = {
                        "authentication": {
                            "version": user['version'], "name": user['name'],
                            "id": user['id'], "type": user['type']
                        },
                        "type": "snmpv3securityconfiguration"
                    }
                else:
                    sec_config = {
                        "community": body['community'],
                        "type": "snmpv2csecurityconfiguration"
                    }
                iface = body['interface']
                result = session.create_snmphost(body['snmpHostName'], host_obj, sec_config, iface)
                logger.info("Created SNMP host: %s" % body['snmpHostName'])
                self._send_json(result)

            elif path == "/api/snmpusers":
                logger.info("Creating SNMPv3 user: %s" % body.get('name', ''))
                self._send_json(session.create_snmpv3user(body))

            else:
                self._send_json({"error": "Not found"}, 404)

        except Exception as e:
            logger.error("POST %s failed: %s" % (path, str(e)))
            self._send_json({"error": str(e)}, 500)

    def do_PUT(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if session is None:
            self._send_json({"error": "Not authenticated"}, 401)
            return

        try:
            if path.startswith("/api/snmphosts/"):
                logger.info("Updating SNMP host %s" % path.split("/")[-1])
                self._send_json(session.update_snmphost(path.split("/")[-1], body))
            elif path.startswith("/api/snmpusers/"):
                logger.info("Updating SNMPv3 user %s" % path.split("/")[-1])
                self._send_json(session.update_snmpv3user(path.split("/")[-1], body))
            elif path.startswith("/api/snmpserver/"):
                logger.info("Updating SNMP server settings %s" % path.split("/")[-1])
                self._send_json(session.update_snmp_server(path.split("/")[-1], body))
            else:
                self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            logger.error("PUT %s failed: %s" % (path, str(e)))
            self._send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        path = urlparse(self.path).path

        if session is None:
            self._send_json({"error": "Not authenticated"}, 401)
            return

        try:
            if path.startswith("/api/snmphosts/"):
                logger.info("Deleting SNMP host %s" % path.split("/")[-1])
                session.delete_snmphost(path.split("/")[-1])
                self._send_json({"ok": True})
            elif path.startswith("/api/snmpusers/"):
                logger.info("Deleting SNMPv3 user %s" % path.split("/")[-1])
                session.delete_snmpv3user(path.split("/")[-1])
                self._send_json({"ok": True})
            else:
                self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            logger.error("DELETE %s failed: %s" % (path, str(e)))
            self._send_json({"error": str(e)}, 500)


# ==================== Embedded HTML/CSS/JS ====================

HTML_PAGE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FDM SNMP Manager</title>
<style>
  :root { --primary: #1a73e8; --danger: #d93025; --success: #1e8e3e; --bg: #f8f9fa; --card: #fff; --border: #dadce0; --text: #202124; --muted: #5f6368; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
  h1 { font-size: 22px; margin-bottom: 20px; }
  h2 { font-size: 17px; margin-bottom: 12px; color: var(--text); }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .tabs { display: flex; gap: 0; border-bottom: 2px solid var(--border); margin-bottom: 16px; }
  .tab { padding: 10px 20px; cursor: pointer; border: none; background: none; font-size: 14px; color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -2px; }
  .tab.active { color: var(--primary); border-bottom-color: var(--primary); font-weight: 600; }
  .tab:hover { background: #e8f0fe; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: #f1f3f4; border-bottom: 2px solid var(--border); font-weight: 600; color: var(--muted); }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: #f8f9fa; }
  tr.selected td { background: #e8f0fe; }
  .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 500; }
  .btn-primary { background: var(--primary); color: #fff; }
  .btn-primary:hover { background: #1557b0; }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: #b3261e; }
  .btn-secondary { background: #fff; color: var(--text); border: 1px solid var(--border); }
  .btn-secondary:hover { background: #f1f3f4; }
  .btn-group { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .form-group { margin-bottom: 12px; }
  .form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 4px; color: var(--muted); }
  .form-group input, .form-group select { width: 100%; padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; }
  .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(26,115,232,0.2); }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.4); z-index: 100; justify-content: center; align-items: flex-start; padding-top: 60px; }
  .modal-overlay.show { display: flex; }
  .modal { background: var(--card); border-radius: 8px; padding: 24px; width: 500px; max-width: 90vw; max-height: 80vh; overflow-y: auto; box-shadow: 0 4px 24px rgba(0,0,0,0.15); }
  .modal h2 { margin-bottom: 16px; }
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
  .toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 20px; border-radius: 6px; color: #fff; font-size: 13px; z-index: 200; display: none; }
  .toast.success { background: var(--success); }
  .toast.error { background: var(--danger); }
  .toast.show { display: block; }
  .footer { text-align: center; padding: 16px 0; font-size: 12px; color: var(--muted); border-top: 1px solid var(--border); margin-top: 30px; }
  .footer a { color: var(--primary); text-decoration: none; }
  .footer a:hover { text-decoration: underline; }
  pre.json { background: #f1f3f4; padding: 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
  .login-wrap { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .login-card { width: 380px; }
  .login-card h1 { text-align: center; margin-bottom: 8px; }
  .login-card p { text-align: center; color: var(--muted); font-size: 13px; margin-bottom: 20px; }
  .status-bar { font-size: 12px; color: var(--muted); margin-bottom: 16px; }
  .hidden { display: none; }
</style>
</head>
<body>

<!-- Login -->
<div id="loginPage" class="login-wrap">
  <div class="card login-card">
    <h1>FDM SNMP Manager</h1>
    <p>Connect to your Firepower Device Manager</p>
    <div class="form-group">
      <label>Device IP Address</label>
      <input id="loginDevice" type="text" placeholder="192.168.1.1">
    </div>
    <div class="form-group">
      <label>Username</label>
      <input id="loginUser" type="text" placeholder="admin">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input id="loginPass" type="password" placeholder="Password">
    </div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" onclick="doLogin()">Login</button>
    <div id="loginError" style="color:var(--danger);font-size:13px;margin-top:10px;text-align:center"></div>
  </div>
</div>

<!-- Main App -->
<div id="mainApp" class="container hidden">
  <h1>FDM SNMP Manager</h1>
  <div class="status-bar" id="statusBar"></div>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('hosts')">SNMP Hosts</button>
    <button class="tab" onclick="switchTab('users')">SNMPv3 Users</button>
    <button class="tab" onclick="switchTab('server')">Server Settings</button>
  </div>

  <!-- SNMP Hosts Tab -->
  <div id="tab-hosts" class="tab-content active">
    <div class="btn-group">
      <button class="btn btn-secondary" onclick="loadHosts()">Refresh</button>
      <button class="btn btn-primary" onclick="showCreateHost()">Create</button>
      <button class="btn btn-secondary" onclick="viewHost()">View Details</button>
      <button class="btn btn-secondary" onclick="showUpdateHost()">Update</button>
      <button class="btn btn-danger" onclick="deleteHost()">Delete</button>
    </div>
    <div class="card" style="padding:0;overflow-x:auto">
      <table>
        <thead><tr><th>Name</th><th>ID</th><th>Interface</th><th>Poll</th><th>Trap</th></tr></thead>
        <tbody id="hostsBody"></tbody>
      </table>
    </div>
  </div>

  <!-- SNMPv3 Users Tab -->
  <div id="tab-users" class="tab-content">
    <div class="btn-group">
      <button class="btn btn-secondary" onclick="loadUsers()">Refresh</button>
      <button class="btn btn-primary" onclick="showCreateUser()">Create</button>
      <button class="btn btn-secondary" onclick="viewUser()">View Details</button>
      <button class="btn btn-secondary" onclick="showUpdateUser()">Update</button>
      <button class="btn btn-danger" onclick="deleteUser()">Delete</button>
    </div>
    <div class="card" style="padding:0;overflow-x:auto">
      <table>
        <thead><tr><th>Name</th><th>ID</th><th>Security Level</th></tr></thead>
        <tbody id="usersBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Server Settings Tab -->
  <div id="tab-server" class="tab-content">
    <div class="card">
      <div class="btn-group">
        <button class="btn btn-secondary" onclick="loadServer()">Refresh</button>
        <button class="btn btn-secondary" onclick="viewServerJSON()">View Full JSON</button>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Contact</label><input id="srvContact" type="text"></div>
        <div class="form-group"><label>Location</label><input id="srvLocation" type="text"></div>
      </div>
      <button class="btn btn-primary" onclick="saveServer()">Save Changes</button>
    </div>
  </div>

  <div style="text-align:center;margin-top:20px">
    <button class="btn btn-secondary" onclick="downloadLogs()">&#128196; Download Logs</button>
    <p style="font-size:12px;color:var(--muted);margin-top:6px">If you encounter issues, download the log file and share it for troubleshooting.</p>
  </div>

  <div class="footer">
    Contact <strong>Anupam</strong> &mdash; <a href="mailto:anpavith@cisco.com">anpavith@cisco.com</a>
  </div>
</div>

<!-- Detail Modal -->
<div class="modal-overlay" id="detailModal">
  <div class="modal">
    <h2 id="detailTitle">Details</h2>
    <pre class="json" id="detailJSON"></pre>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="closeModal('detailModal')">Close</button></div>
  </div>
</div>

<!-- Create Host Modal -->
<div class="modal-overlay" id="createHostModal">
  <div class="modal">
    <h2>Create SNMP Host</h2>
    <div class="form-row">
      <div class="form-group"><label>Host Object Name</label><input id="chObjName" type="text"></div>
      <div class="form-group"><label>Host IP Address</label><input id="chObjIP" type="text"></div>
    </div>
    <div class="form-group">
      <label>SNMP Version</label>
      <select id="chVersion" onchange="toggleV3Fields()"><option value="v2c">SNMPv2c</option><option value="v3">SNMPv3</option></select>
    </div>
    <div id="v2Fields">
      <div class="form-group"><label>Community String</label><input id="chCommunity" type="text"></div>
    </div>
    <div id="v3Fields" class="hidden">
      <div class="form-group">
        <label>SNMPv3 User</label>
        <select id="chV3UserSelect" onchange="toggleNewUserFields()"></select>
      </div>
      <div id="newUserFields" class="hidden">
        <div class="form-row">
          <div class="form-group"><label>Username</label><input id="chV3User" type="text"></div>
          <div class="form-group"><label>Security Level</label><select id="chV3Sec"><option>NOAUTH</option><option selected>AUTH</option><option>PRIV</option></select></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Auth Algorithm</label><select id="chV3AuthAlg"><option>SHA</option><option>SHA256</option></select></div>
          <div class="form-group"><label>Auth Password</label><input id="chV3AuthPw" type="password"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Encryption Algorithm</label><select id="chV3EncAlg"><option>AES128</option><option>AES192</option><option>AES256</option><option>3DES</option></select></div>
          <div class="form-group"><label>Encryption Password</label><input id="chV3EncPw" type="password"></div>
        </div>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Interface</label><select id="chIface"></select></div>
      <div class="form-group"><label>SNMP Host Name</label><input id="chHostName" type="text"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('createHostModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitCreateHost()">Create</button>
    </div>
  </div>
</div>

<!-- Update Host Modal -->
<div class="modal-overlay" id="updateHostModal">
  <div class="modal">
    <h2>Update SNMP Host</h2>
    <div class="form-group"><label>Poll Enabled</label><select id="uhPoll"><option value="true">True</option><option value="false">False</option></select></div>
    <div class="form-group"><label>Trap Enabled</label><select id="uhTrap"><option value="true">True</option><option value="false">False</option></select></div>
    <div class="form-group"><label>Interface</label><select id="uhIface"></select></div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('updateHostModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitUpdateHost()">Update</button>
    </div>
  </div>
</div>

<!-- Create User Modal -->
<div class="modal-overlay" id="createUserModal">
  <div class="modal">
    <h2>Create SNMPv3 User</h2>
    <div class="form-group"><label>Username</label><input id="cuName" type="text"></div>
    <div class="form-group"><label>Security Level</label><select id="cuSec"><option>NOAUTH</option><option selected>AUTH</option><option>PRIV</option></select></div>
    <div class="form-row">
      <div class="form-group"><label>Auth Algorithm</label><select id="cuAuthAlg"><option>SHA</option><option>SHA256</option></select></div>
      <div class="form-group"><label>Auth Password</label><input id="cuAuthPw" type="password"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Encryption Algorithm</label><select id="cuEncAlg"><option>AES128</option><option>AES192</option><option>AES256</option><option>3DES</option></select></div>
      <div class="form-group"><label>Encryption Password</label><input id="cuEncPw" type="password"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('createUserModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitCreateUser()">Create</button>
    </div>
  </div>
</div>

<!-- Update User Modal -->
<div class="modal-overlay" id="updateUserModal">
  <div class="modal">
    <h2>Update SNMPv3 User</h2>
    <div class="form-group"><label>Security Level</label><select id="uuSec"><option>NOAUTH</option><option>AUTH</option><option>PRIV</option></select></div>
    <div class="form-row">
      <div class="form-group"><label>Auth Algorithm</label><select id="uuAuthAlg"><option>SHA</option><option>SHA256</option></select></div>
      <div class="form-group"><label>Auth Password</label><input id="uuAuthPw" type="password"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Encryption Algorithm</label><select id="uuEncAlg"><option>AES128</option><option>AES192</option><option>AES256</option><option>3DES</option></select></div>
      <div class="form-group"><label>Encryption Password</label><input id="uuEncPw" type="password"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('updateUserModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitUpdateUser()">Update</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div id="toast" class="toast"></div>

<script>
// ---- State ----
let hostsData = [], usersData = [], serverData = null, ifacesCache = [], v3UsersCache = [];
let selectedHostIdx = -1, selectedUserIdx = -1, updateHostData = null, updateUserData = null;

// ---- Helpers ----
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function toast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type + ' show';
  setTimeout(() => t.className = 'toast', 3000);
}

function closeModal(id) { document.getElementById(id).classList.remove('show'); }
function openModal(id) { document.getElementById(id).classList.add('show'); }

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
  if (name === 'hosts') loadHosts();
  else if (name === 'users') loadUsers();
  else if (name === 'server') loadServer();
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// ---- Login ----
async function doLogin() {
  const device = document.getElementById('loginDevice').value.trim();
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value;
  const errEl = document.getElementById('loginError');
  errEl.textContent = '';
  if (!device || !username || !password) { errEl.textContent = 'All fields are required.'; return; }
  try {
    errEl.textContent = 'Authenticating...';
    errEl.style.color = 'var(--primary)';
    await api('POST', '/api/login', { device, username, password });
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('mainApp').classList.remove('hidden');
    document.getElementById('statusBar').textContent = 'Connected to: ' + escapeHtml(device);
    loadHosts();
  } catch (e) {
    errEl.style.color = 'var(--danger)';
    errEl.textContent = e.message;
  }
}
document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

// ---- SNMP Hosts ----
async function loadHosts() {
  try {
    hostsData = await api('GET', '/api/snmphosts');
    selectedHostIdx = -1;
    const tbody = document.getElementById('hostsBody');
    tbody.innerHTML = '';
    hostsData.forEach((h, i) => {
      const tr = document.createElement('tr');
      tr.onclick = () => selectHostRow(i);
      const iname = (h.interface || {}).name || '';
      tr.innerHTML = '<td>'+escapeHtml(h.name||'')+'</td><td style="font-size:11px">'+escapeHtml(h.id||'')+'</td><td>'+escapeHtml(iname)+'</td><td>'+h.pollEnabled+'</td><td>'+h.trapEnabled+'</td>';
      tbody.appendChild(tr);
    });
  } catch (e) { toast(e.message, 'error'); }
}

function selectHostRow(i) {
  selectedHostIdx = i;
  document.querySelectorAll('#hostsBody tr').forEach((tr, j) => tr.classList.toggle('selected', i === j));
}

async function viewHost() {
  if (selectedHostIdx < 0) { toast('Select a host first', 'error'); return; }
  try {
    const data = await api('GET', '/api/snmphosts/' + hostsData[selectedHostIdx].id);
    document.getElementById('detailTitle').textContent = 'SNMP Host - ' + escapeHtml(data.name || '');
    document.getElementById('detailJSON').textContent = JSON.stringify(data, null, 2);
    openModal('detailModal');
  } catch (e) { toast(e.message, 'error'); }
}

async function loadInterfaces(selectEl, currentName) {
  if (ifacesCache.length === 0) {
    try { ifacesCache = await api('GET', '/api/interfaces'); } catch(e) { toast(e.message,'error'); return; }
  }
  selectEl.innerHTML = '';
  ifacesCache.forEach((iface, i) => {
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = (iface.name || '') + ' (' + (iface.hardwareName || '') + ')';
    if (iface.name === currentName) opt.selected = true;
    selectEl.appendChild(opt);
  });
}

function toggleV3Fields() {
  const v = document.getElementById('chVersion').value;
  document.getElementById('v2Fields').classList.toggle('hidden', v !== 'v2c');
  document.getElementById('v3Fields').classList.toggle('hidden', v !== 'v3');
  if (v === 'v3') loadV3UserDropdown();
}

async function loadV3UserDropdown() {
  const sel = document.getElementById('chV3UserSelect');
  try {
    v3UsersCache = await api('GET', '/api/snmpusers');
  } catch(e) { v3UsersCache = []; }
  sel.innerHTML = '<option value="__new__">-- Create New User --</option>';
  v3UsersCache.forEach((u, i) => {
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = u.name + ' (' + (u.securityLevel||'') + ')';
    sel.appendChild(opt);
  });
  toggleNewUserFields();
}

function toggleNewUserFields() {
  const v = document.getElementById('chV3UserSelect').value;
  document.getElementById('newUserFields').classList.toggle('hidden', v !== '__new__');
}

async function showCreateHost() {
  document.getElementById('chObjName').value = '';
  document.getElementById('chObjIP').value = '';
  document.getElementById('chCommunity').value = '';
  document.getElementById('chHostName').value = '';
  document.getElementById('chVersion').value = 'v2c';
  toggleV3Fields();
  await loadInterfaces(document.getElementById('chIface'), '');
  openModal('createHostModal');
}

async function submitCreateHost() {
  const ver = document.getElementById('chVersion').value;
  const ifaceIdx = document.getElementById('chIface').value;
  const body = {
    hostObjName: document.getElementById('chObjName').value.trim(),
    hostObjIP: document.getElementById('chObjIP').value.trim(),
    snmpHostName: document.getElementById('chHostName').value.trim(),
    snmpVersion: ver,
    interface: ifacesCache[ifaceIdx]
  };
  if (ver === 'v2c') {
    body.community = document.getElementById('chCommunity').value;
  } else {
    const userSel = document.getElementById('chV3UserSelect').value;
    if (userSel === '__new__') {
      body.v3CreateNew = true;
      body.v3Username = document.getElementById('chV3User').value.trim();
      body.v3SecLevel = document.getElementById('chV3Sec').value;
      body.v3AuthAlg = document.getElementById('chV3AuthAlg').value;
      body.v3AuthPw = document.getElementById('chV3AuthPw').value;
      body.v3EncAlg = document.getElementById('chV3EncAlg').value;
      body.v3EncPw = document.getElementById('chV3EncPw').value;
    } else {
      body.v3CreateNew = false;
      body.v3ExistingUser = v3UsersCache[parseInt(userSel)];
    }
  }
  try {
    await api('POST', '/api/snmphosts', body);
    toast('SNMP host created. Deploy to apply changes.');
    closeModal('createHostModal');
    loadHosts();
  } catch (e) { toast(e.message, 'error'); }
}

async function showUpdateHost() {
  if (selectedHostIdx < 0) { toast('Select a host first', 'error'); return; }
  try {
    updateHostData = await api('GET', '/api/snmphosts/' + hostsData[selectedHostIdx].id);
    document.getElementById('uhPoll').value = String(updateHostData.pollEnabled);
    document.getElementById('uhTrap').value = String(updateHostData.trapEnabled);
    await loadInterfaces(document.getElementById('uhIface'), (updateHostData.interface||{}).name);
    openModal('updateHostModal');
  } catch (e) { toast(e.message, 'error'); }
}

async function submitUpdateHost() {
  const ifaceIdx = document.getElementById('uhIface').value;
  const newIface = ifacesCache[ifaceIdx];
  updateHostData.pollEnabled = document.getElementById('uhPoll').value === 'true';
  updateHostData.trapEnabled = document.getElementById('uhTrap').value === 'true';
  updateHostData.interface = { version: newIface.version, name: newIface.name, id: newIface.id, type: newIface.type };
  try {
    await api('PUT', '/api/snmphosts/' + updateHostData.id, updateHostData);
    toast('SNMP host updated. Deploy to apply changes.');
    closeModal('updateHostModal');
    loadHosts();
  } catch (e) { toast(e.message, 'error'); }
}

async function deleteHost() {
  if (selectedHostIdx < 0) { toast('Select a host first', 'error'); return; }
  const h = hostsData[selectedHostIdx];
  if (!confirm('Delete SNMP host "' + (h.name||'') + '"?')) return;
  try {
    await api('DELETE', '/api/snmphosts/' + h.id);
    toast('SNMP host deleted. Deploy to apply changes.');
    loadHosts();
  } catch (e) { toast(e.message, 'error'); }
}

// ---- SNMPv3 Users ----
async function loadUsers() {
  try {
    usersData = await api('GET', '/api/snmpusers');
    selectedUserIdx = -1;
    const tbody = document.getElementById('usersBody');
    tbody.innerHTML = '';
    usersData.forEach((u, i) => {
      const tr = document.createElement('tr');
      tr.onclick = () => selectUserRow(i);
      tr.innerHTML = '<td>'+escapeHtml(u.name||'')+'</td><td style="font-size:11px">'+escapeHtml(u.id||'')+'</td><td>'+escapeHtml(u.securityLevel||'')+'</td>';
      tbody.appendChild(tr);
    });
  } catch (e) { toast(e.message, 'error'); }
}

function selectUserRow(i) {
  selectedUserIdx = i;
  document.querySelectorAll('#usersBody tr').forEach((tr, j) => tr.classList.toggle('selected', i === j));
}

async function viewUser() {
  if (selectedUserIdx < 0) { toast('Select a user first', 'error'); return; }
  try {
    const data = await api('GET', '/api/snmpusers/' + usersData[selectedUserIdx].id);
    document.getElementById('detailTitle').textContent = 'SNMPv3 User - ' + escapeHtml(data.name || '');
    document.getElementById('detailJSON').textContent = JSON.stringify(data, null, 2);
    openModal('detailModal');
  } catch (e) { toast(e.message, 'error'); }
}

function showCreateUser() {
  document.getElementById('cuName').value = '';
  document.getElementById('cuAuthPw').value = '';
  document.getElementById('cuEncPw').value = '';
  openModal('createUserModal');
}

async function submitCreateUser() {
  const payload = {
    type: 'snmpuser',
    name: document.getElementById('cuName').value.trim(),
    securityLevel: document.getElementById('cuSec').value
  };
  if (!payload.name) { toast('Username is required', 'error'); return; }
  if (['AUTH','PRIV'].includes(payload.securityLevel)) {
    payload.authenticationAlgorithm = document.getElementById('cuAuthAlg').value;
    payload.authenticationPassword = document.getElementById('cuAuthPw').value;
  }
  if (payload.securityLevel === 'PRIV') {
    payload.encryptionAlgorithm = document.getElementById('cuEncAlg').value;
    payload.encryptionPassword = document.getElementById('cuEncPw').value;
  }
  try {
    await api('POST', '/api/snmpusers', payload);
    toast('SNMPv3 user created.');
    closeModal('createUserModal');
    loadUsers();
  } catch (e) { toast(e.message, 'error'); }
}

async function showUpdateUser() {
  if (selectedUserIdx < 0) { toast('Select a user first', 'error'); return; }
  try {
    updateUserData = await api('GET', '/api/snmpusers/' + usersData[selectedUserIdx].id);
    document.getElementById('uuSec').value = updateUserData.securityLevel || 'AUTH';
    document.getElementById('uuAuthAlg').value = updateUserData.authenticationAlgorithm || 'SHA';
    document.getElementById('uuEncAlg').value = updateUserData.encryptionAlgorithm || 'AES128';
    document.getElementById('uuAuthPw').value = '';
    document.getElementById('uuEncPw').value = '';
    openModal('updateUserModal');
  } catch (e) { toast(e.message, 'error'); }
}

async function submitUpdateUser() {
  updateUserData.securityLevel = document.getElementById('uuSec').value;
  if (['AUTH','PRIV'].includes(updateUserData.securityLevel)) {
    updateUserData.authenticationAlgorithm = document.getElementById('uuAuthAlg').value;
    updateUserData.authenticationPassword = document.getElementById('uuAuthPw').value;
  }
  if (updateUserData.securityLevel === 'PRIV') {
    updateUserData.encryptionAlgorithm = document.getElementById('uuEncAlg').value;
    updateUserData.encryptionPassword = document.getElementById('uuEncPw').value;
  }
  try {
    await api('PUT', '/api/snmpusers/' + updateUserData.id, updateUserData);
    toast('SNMPv3 user updated.');
    closeModal('updateUserModal');
    loadUsers();
  } catch (e) { toast(e.message, 'error'); }
}

async function deleteUser() {
  if (selectedUserIdx < 0) { toast('Select a user first', 'error'); return; }
  const u = usersData[selectedUserIdx];
  if (!confirm('Delete SNMPv3 user "' + (u.name||'') + '"?')) return;
  try {
    await api('DELETE', '/api/snmpusers/' + u.id);
    toast('SNMPv3 user deleted.');
    loadUsers();
  } catch (e) { toast(e.message, 'error'); }
}

// ---- Server Settings ----
async function loadServer() {
  try {
    serverData = await api('GET', '/api/snmpserver');
    document.getElementById('srvContact').value = (serverData||{}).contact || '';
    document.getElementById('srvLocation').value = (serverData||{}).location || '';
  } catch (e) { toast(e.message, 'error'); }
}

function viewServerJSON() {
  if (!serverData) { toast('No data loaded. Click Refresh.', 'error'); return; }
  document.getElementById('detailTitle').textContent = 'SNMP Server Settings';
  document.getElementById('detailJSON').textContent = JSON.stringify(serverData, null, 2);
  openModal('detailModal');
}

async function saveServer() {
  if (!serverData) { toast('No data loaded. Click Refresh.', 'error'); return; }
  serverData.contact = document.getElementById('srvContact').value.trim();
  serverData.location = document.getElementById('srvLocation').value.trim();
  try {
    serverData = await api('PUT', '/api/snmpserver/' + serverData.id, serverData);
    toast('Server settings updated. Deploy to apply changes.');
  } catch (e) { toast(e.message, 'error'); }
}

function downloadLogs() {
  window.location.href = '/api/logs';
}
</script>
</body>
</html>'''


# ==================== Entry Point ====================

if __name__ == '__main__':
    port = 8889
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    logger.info("Starting FDM SNMP Manager on port %d" % port)
    server = HTTPServer(('127.0.0.1', port), Handler)
    url = 'http://127.0.0.1:%d' % port
    print('FDM SNMP Manager running at %s' % url)
    print('Log file: %s' % LOG_FILE)
    print('Press Ctrl+C to stop.')
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down.')
        server.server_close()
