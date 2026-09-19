#!/usr/bin/env python3
"""
SpinetiX Player Provisioning Tool
Scan, configure and push content to SpinetiX HMP players on the local network.

Usage: python3 server.py
Then open http://localhost:8090 in your browser.
"""

import json
import re
import subprocess
import threading
import time
import ssl
import base64
import ipaddress
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from xml.sax.saxutils import escape as xml_escape

# ─── Config ──────────────────────────────────────────────────────────────────

PORT = 8090
BIND_HOST = '127.0.0.1'  # localhost only, not exposed to network
SCAN_TIMEOUT = 6  # seconds for mDNS browse
REBOOT_WAIT = 60  # seconds to wait after reboot
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB max request body
ALLOWED_ORIGIN = f'http://localhost:{PORT}'

# ─── SSL Context (singleton, player-only, no cert validation) ────────────────

_PLAYER_SSL_CTX = None

def _player_ssl_context():
    """SSL context for SpinetiX player communication only.
    Players use self-signed certificates, so verification is disabled."""
    global _PLAYER_SSL_CTX
    if _PLAYER_SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _PLAYER_SSL_CTX = ctx
    return _PLAYER_SSL_CTX


# ─── Validation ──────────────────────────────────────────────────────────────

def _validate_ip(ip):
    """Validate IP is a private/link-local address (not public, not loopback metadata)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr == ipaddress.ip_address('169.254.169.254'):
        return False
    if addr.is_private or addr.is_link_local:
        return True
    return False


def _validate_screen_url(url):
    """Validate screen URL is HTTPS and safe for SVG embedding."""
    if not url or not isinstance(url, str):
        return False
    if not url.startswith('https://'):
        return False
    if len(url) > 2048:
        return False
    return True


def _require_fields(body, *fields):
    """Validate required fields exist in request body. Returns error string or None."""
    for f in fields:
        if f not in body or not body[f]:
            return f'Verplicht veld ontbreekt: {f}'
    return None


# ─── Player Discovery ────────────────────────────────────────────────────────

_discovered_ips = set()  # track discovered player IPs for SSRF validation


def scan_players():
    """Discover SpinetiX players via mDNS (dns-sd on macOS)."""
    global _discovered_ips
    instances = []
    try:
        proc = subprocess.Popen(
            ['dns-sd', '-B', '_http._tcp', 'local.'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        time.sleep(SCAN_TIMEOUT)
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()

        for line in output.splitlines():
            if 'HMP' in line or 'hmp' in line:
                parts = line.strip().split()
                if len(parts) >= 7:
                    instances.append(' '.join(parts[6:]))
    except FileNotFoundError:
        players = _scan_arp_fallback()
        _discovered_ips = {p['ip'] for p in players}
        return players
    except Exception as e:
        print(f"Scan error: {e}")
        return []

    # Resolve players in parallel
    with ThreadPoolExecutor(max_workers=8) as pool:
        players = list(pool.map(_resolve_player, instances))

    players = [p for p in players if p is not None]
    _discovered_ips = {p['ip'] for p in players}
    return players


def _resolve_player(instance_name):
    """Resolve mDNS instance to IP address."""
    try:
        proc = subprocess.Popen(
            ['dns-sd', '-L', instance_name, '_http._tcp', 'local.'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        time.sleep(3)
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()

        hostname = None
        for line in output.splitlines():
            if 'can be reached at' in line:
                hostname = line.split('can be reached at')[1].strip().split(':')[0]
                break

        if not hostname:
            return None

        # Resolve hostname to IP
        proc2 = subprocess.run(
            ['ping', '-c', '1', '-t', '2', hostname],
            capture_output=True, text=True, timeout=5
        )
        ip = None
        for line in proc2.stdout.splitlines():
            if 'PING' in line and '(' in line:
                ip = line.split('(')[1].split(')')[0]
                break

        if not ip:
            return None

        # Extract model and name from instance
        parts = instance_name.split(' - ', 1)
        model = parts[0].strip() if parts else instance_name
        serial = parts[1].strip() if len(parts) > 1 else ''

        # Extract MAC from hostname (spx-hmp-XXXXXXXXXXXX)
        mac = ''
        if hostname and 'spx-hmp-' in hostname:
            raw = hostname.replace('.local.', '').replace('.local', '').split('spx-hmp-')[1]
            if len(raw) == 12:
                mac = ':'.join(raw[i:i+2] for i in range(0, 12, 2)).upper()

        return {
            'ip': ip,
            'model': model,
            'serial': serial,
            'mac': mac,
            'hostname': hostname,
        }
    except Exception as e:
        print(f"Resolve error for {instance_name}: {e}")
        return None


def _scan_arp_fallback():
    """Fallback: scan ARP table for SpinetiX devices (MAC prefix 00:1d:50)."""
    players = []
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if '0:1d:50' in line.lower() or '00:1d:50' in line.lower():
                parts = line.split()
                ip = None
                mac = None
                for p in parts:
                    if p.startswith('(') and p.endswith(')'):
                        ip = p[1:-1]
                    if ':' in p and len(p) >= 11:
                        mac_candidate = p.lower()
                        if '1d:50' in mac_candidate:
                            mac = mac_candidate.upper()
                if ip and _validate_ip(ip):
                    players.append({
                        'ip': ip,
                        'model': 'HMP',
                        'serial': '',
                        'mac': mac or '',
                        'hostname': '',
                    })
    except Exception as e:
        print(f"ARP fallback error: {e}")
    return players


# ─── Player API ──────────────────────────────────────────────────────────────

def _auth_header(username, password):
    creds = base64.b64encode(f'{username}:{password}'.encode()).decode()
    return f'Basic {creds}'


def _rpc_call(ip, method, params, username, password, timeout=10):
    """Make a JSON-RPC call to the player."""
    url = f'https://{ip}/rpc'
    payload = json.dumps({
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
        'id': 1
    }).encode()

    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', _auth_header(username, password))

    resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=timeout)
    return json.loads(resp.read().decode())


def _mac_to_auth_hash(mac):
    """Generate deterministic authHash from MAC address.
    Format: spx_{mac_without_colons_lowercase}
    Example: 00:1D:50:22:27:82 -> spx_001d50222782"""
    return 'spx_' + mac.replace(':', '').lower()


# DST Connect platform endpoint for device polling
DST_CONNECT_BASE = 'https://cms.dst-connect.io'
DEVICE_CONFIG_PATH = '/device/config'
DEVICE_STATUS_PATH = '/device/status'


def _build_svg(screen_url, auth_hash):
    """Build bridge SVG: iframe for content + JavaScript polling for RDM.

    The SVG acts as a lightweight applet replacement:
    - <iframe> renders the screen content from DST Connect
    - <script> polls /device/config/{authHash} every 30s for commands
    - <script> posts /device/status/{authHash} every 60s with telemetry
    """
    safe_url = xml_escape(screen_url, entities={'"': '&quot;'})
    safe_hash = xml_escape(auth_hash, entities={'"': '&quot;'})

    return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="1920" height="1080" viewBox="0 0 1920 1080" dur="indefinite" viewport-fill="#000000">
  <iframe src="{safe_url}" x="0" y="0" width="1920" height="1080"/>
  <script type="text/ecmascript"><![CDATA[
    // DST Connect Bridge - SpinetiX RDM Agent
    // This script runs inside the SVG on the SpinetiX player and provides
    // the same polling behavior as the native Android/webOS/Windows applet.

    var AUTH_HASH = "{safe_hash}";
    var BASE = "{DST_CONNECT_BASE}";
    var CONFIG_URL = BASE + "{DEVICE_CONFIG_PATH}/" + AUTH_HASH;
    var STATUS_URL = BASE + "{DEVICE_STATUS_PATH}/" + AUTH_HASH;
    var SCREEN_URL = "{safe_url}";
    var CONFIG_INTERVAL = 30000;  // 30s config poll
    var STATUS_INTERVAL = 60000;  // 60s status heartbeat

    // ─── Config Poll (commands from platform) ───────────────────────

    function pollConfig() {{
      try {{
        var xhr = new XMLHttpRequest();
        xhr.open("GET", CONFIG_URL, true);
        xhr.timeout = 10000;
        xhr.onload = function() {{
          if (xhr.status === 200) {{
            try {{
              var data = JSON.parse(xhr.responseText);
              handleConfig(data);
            }} catch(e) {{}}
          }}
        }};
        xhr.send();
      }} catch(e) {{}}
    }}

    function handleConfig(data) {{
      // Handle screen URL change
      if (data.screenUrl && data.screenUrl !== SCREEN_URL) {{
        SCREEN_URL = data.screenUrl;
        // Reload the iframe with new URL
        var iframes = document.getElementsByTagName("iframe");
        if (iframes.length > 0) iframes[0].setAttribute("src", SCREEN_URL);
      }}

      // Handle pending commands
      if (data.commands && data.commands.length > 0) {{
        for (var i = 0; i < data.commands.length; i++) {{
          executeCommand(data.commands[i]);
        }}
      }}
    }}

    // ─── Command Execution ──────────────────────────────────────────

    function executeCommand(cmd) {{
      var ackUrl = BASE + "/device/command/" + cmd.id + "/ack";
      var success = true;
      var error = null;

      try {{
        switch(cmd.type) {{
          case "reboot":
          case "appRestart":
          case "appletReload":
            // Reload SVG = restart content
            setTimeout(function() {{ location.reload(); }}, 1000);
            break;
          case "screenshot":
            // Screenshot is handled server-side via SpinetiX API
            break;
          default:
            error = "Unsupported command: " + cmd.type;
            success = false;
        }}
      }} catch(e) {{
        success = false;
        error = String(e);
      }}

      // ACK the command
      try {{
        var xhr = new XMLHttpRequest();
        xhr.open("POST", ackUrl, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify({{success: success, error: error}}));
      }} catch(e) {{}}
    }}

    // ─── Status Heartbeat ───────────────────────────────────────────

    function sendStatus() {{
      try {{
        var xhr = new XMLHttpRequest();
        xhr.open("POST", STATUS_URL, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.timeout = 10000;
        xhr.send(JSON.stringify({{
          online: true,
          platform: "spinetix",
          screenUrl: SCREEN_URL,
          userAgent: navigator.userAgent || "SpinetiX HMP"
        }}));
      }} catch(e) {{}}
    }}

    // ─── Start Polling ──────────────────────────────────────────────

    setTimeout(pollConfig, 5000);
    setInterval(pollConfig, CONFIG_INTERVAL);

    setTimeout(sendStatus, 10000);
    setInterval(sendStatus, STATUS_INTERVAL);
  ]]></script>
</svg>'''


def test_auth(ip, username, password):
    """Test credentials and return player info."""
    try:
        url = f'https://{ip}/status/info'
        req = urllib.request.Request(url)
        req.add_header('Authorization', _auth_header(username, password))
        resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=10)
        body = resp.read().decode()

        info = {}
        for tag in ['name', 'serial', 'ethmac', 'uptime', 'temp']:
            m = re.search(f'<{tag}>(.*?)</{tag}>', body)
            if m:
                info[tag] = m.group(1)

        # Extract firmware version
        m = re.search(r'<version>\s*<firmware>\s*<version>(.*?)</version>', body, re.DOTALL)
        if m:
            info['firmware'] = m.group(1)

        # Extract license features
        features = re.findall(r'<features>\s*<name>(.*?)</name>.*?<valid>(.*?)</valid>', body, re.DOTALL)
        info['features'] = [f[0] for f in features if f[1] == '1' and not f[0].startswith('#')]

        # Extract resolution
        w = re.search(r'<resolutionWidth>(.*?)</resolutionWidth>', body)
        h = re.search(r'<resolutionHeight>(.*?)</resolutionHeight>', body)
        if w and h and w.group(1) != 'unknown':
            info['resolution'] = f"{w.group(1)}x{h.group(1)}"

        return {'success': True, 'info': info}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {'success': False, 'error': 'Ongeldige credentials'}
        return {'success': False, 'error': f'HTTP fout ({e.code})'}
    except Exception:
        return {'success': False, 'error': 'Kan niet verbinden met player'}


def provision_player(ip, username, password, screen_url, mac=''):
    """Full provisioning: disable cloud, reboot, push bridge SVG with RDM polling."""
    steps = []

    def log(msg):
        steps.append(msg)
        print(f"  [{ip}] {msg}")

    try:
        # Step 0: Get MAC address for auth_hash if not provided
        if not mac:
            log("Player info ophalen...")
            try:
                info = test_auth(ip, username, password)
                if info.get('success') and info.get('info', {}).get('ethmac'):
                    mac = info['info']['ethmac']
            except Exception:
                pass
        if not mac:
            log("Waarschuwing: MAC-adres niet beschikbaar, authHash niet aangemaakt")
            return {'success': False, 'steps': steps, 'error': 'Kan MAC-adres niet ophalen'}

        auth_hash = _mac_to_auth_hash(mac)
        log(f"AuthHash: {auth_hash}")

        # Step 1: Disable cloud
        log("Cloud uitschakelen...")
        result = _rpc_call(ip, 'set_config', [{'xmlconfig':
            '<configuration version="2.3"><disable-cloud/></configuration>'
        }], username, password)

        r = result.get('result', {})
        if r.get('reboot_pending') or r.get('success'):
            log("Cloud uitgeschakeld")
        else:
            log("Waarschuwing: onverwacht antwoord van player")

        # Step 2: Reboot
        log("Player herstarten...")
        _rpc_call(ip, 'restart', [], username, password)
        log(f"Wacht {REBOOT_WAIT}s op herstart...")
        time.sleep(REBOOT_WAIT)

        # Step 3: Wait for player to come back
        log("Verbinding controleren...")
        for attempt in range(6):
            try:
                _rpc_call(ip, 'get_info', [], username, password, timeout=5)
                log("Player is terug online")
                break
            except Exception:
                if attempt < 5:
                    time.sleep(10)
                else:
                    log("Player reageert niet na herstart")
                    return {'success': False, 'steps': steps, 'error': 'Timeout na herstart'}

        # Step 4: Push bridge SVG with RDM polling
        log("Bridge SVG pushen (content + RDM polling)...")
        svg = _build_svg(screen_url, auth_hash)

        url = f'https://{ip}:9802/index.svg'
        req = urllib.request.Request(url, data=svg.encode('utf-8'), method='PUT')
        req.add_header('Content-Type', 'image/svg+xml')
        req.add_header('Authorization', _auth_header(username, password))
        resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=15)

        if resp.status in (200, 201, 204):
            log("Content succesvol gepusht!")
        else:
            log(f"Onverwachte status: {resp.status}")
            return {'success': False, 'steps': steps, 'error': 'Content push mislukt'}

        # Step 5: Verify with screenshot
        time.sleep(5)
        log("Screenshot ophalen ter verificatie...")
        try:
            url = f'https://{ip}/status/snapshot'
            req = urllib.request.Request(url)
            req.add_header('Authorization', _auth_header(username, password))
            resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=15)
            screenshot = base64.b64encode(resp.read()).decode()
            log("Provisioning voltooid!")
            log(f"Claim code voor CMS: {auth_hash}")
            return {'success': True, 'steps': steps, 'screenshot': screenshot, 'auth_hash': auth_hash}
        except Exception:
            log("Provisioning voltooid (screenshot niet beschikbaar)")
            log(f"Claim code voor CMS: {auth_hash}")
            return {'success': True, 'steps': steps, 'auth_hash': auth_hash}

    except Exception:
        log("Fout tijdens provisioning")
        return {'success': False, 'steps': steps, 'error': 'Provisioning mislukt'}


def push_content_only(ip, username, password, screen_url, mac=''):
    """Push content without disable-cloud (for already provisioned players)."""
    try:
        if not mac:
            info = test_auth(ip, username, password)
            if info.get('success') and info.get('info', {}).get('ethmac'):
                mac = info['info']['ethmac']
        if not mac:
            return {'success': False, 'error': 'Kan MAC-adres niet ophalen'}
        auth_hash = _mac_to_auth_hash(mac)
        svg = _build_svg(screen_url, auth_hash)

        url = f'https://{ip}:9802/index.svg'
        req = urllib.request.Request(url, data=svg.encode('utf-8'), method='PUT')
        req.add_header('Content-Type', 'image/svg+xml')
        req.add_header('Authorization', _auth_header(username, password))
        resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=15)

        if resp.status in (200, 201, 204):
            return {'success': True}
        else:
            return {'success': False, 'error': 'Content push mislukt'}
    except Exception:
        return {'success': False, 'error': 'Kan niet verbinden met player'}


def take_screenshot(ip, username, password):
    """Take a screenshot from the player."""
    try:
        url = f'https://{ip}/status/snapshot'
        req = urllib.request.Request(url)
        req.add_header('Authorization', _auth_header(username, password))
        resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=15)
        return {'success': True, 'image': base64.b64encode(resp.read()).decode()}
    except Exception:
        return {'success': False, 'error': 'Screenshot ophalen mislukt'}


# ─── Web UI ──────────────────────────────────────────────────────────────────

HTML_BYTES = '''<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SpinetiX Provisioner</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f5f5; color: #333; }
  .header { background: #1a1a2e; color: white; padding: 20px 30px; }
  .header h1 { font-size: 22px; font-weight: 600; }
  .header p { font-size: 13px; color: #aaa; margin-top: 4px; }
  .container { max-width: 1100px; margin: 20px auto; padding: 0 20px; }

  .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 16px; }
  .card h2 { font-size: 16px; margin-bottom: 16px; color: #1a1a2e; }

  .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: opacity 0.2s; }
  .btn:hover { opacity: 0.85; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-primary { background: #2563eb; color: white; }
  .btn-success { background: #16a34a; color: white; }
  .btn-warning { background: #d97706; color: white; }
  .btn-sm { padding: 6px 14px; font-size: 13px; }

  .scan-bar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }

  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 12px; font-size: 12px; text-transform: uppercase; color: #888; border-bottom: 2px solid #eee; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
  tr:hover { background: #fafafa; }

  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .status-dot.online { background: #16a34a; }

  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-kiosk { background: #dbeafe; color: #1d4ed8; }
  .badge-no { background: #fee2e2; color: #dc2626; }

  input[type="text"], input[type="password"] { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; width: 100%; }
  input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }

  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 100; align-items: center; justify-content: center; }
  .modal-overlay.active { display: flex; }
  .modal { background: white; border-radius: 12px; padding: 28px; width: 520px; max-width: 95vw; max-height: 90vh; overflow-y: auto; }
  .modal h3 { font-size: 18px; margin-bottom: 16px; }
  .modal .field { margin-bottom: 14px; }
  .modal label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 4px; color: #555; }
  .modal .actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }

  .log { background: #1a1a2e; color: #4ade80; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; max-height: 300px; overflow-y: auto; margin-top: 12px; white-space: pre-wrap; }

  .screenshot { max-width: 100%; border-radius: 8px; margin-top: 12px; border: 1px solid #ddd; }

  .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid #fff; border-top-color: transparent; border-radius: 50%; animation: spin 0.6s linear infinite; vertical-align: middle; margin-right: 6px; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .empty { text-align: center; padding: 40px; color: #999; }
</style>
</head>
<body>

<div class="header">
  <h1>SpinetiX Provisioner</h1>
  <p>Scan, configureer en push content naar SpinetiX players</p>
</div>

<div class="container">
  <div class="card">
    <div class="scan-bar">
      <button class="btn btn-primary" onclick="scanPlayers()" id="scanBtn">Scan netwerk</button>
      <span id="scanStatus" style="font-size:13px;color:#888;"></span>
    </div>
  </div>

  <div class="card">
    <h2>Gevonden players</h2>
    <div id="playerList">
      <div class="empty">Klik op "Scan netwerk" om te beginnen</div>
    </div>
  </div>
</div>

<div class="modal-overlay" id="provisionModal">
  <div class="modal">
    <h3 id="modalTitle">Player configureren</h3>
    <div id="modalStep1">
      <div class="field">
        <label>Player</label>
        <input type="text" id="modalPlayer" readonly style="background:#f5f5f5;">
      </div>
      <div class="field">
        <label>Username</label>
        <input type="text" id="modalUser" value="admin">
      </div>
      <div class="field">
        <label>Wachtwoord</label>
        <input type="password" id="modalPass" value="">
      </div>
      <div class="field">
        <label>Screen URL</label>
        <input type="text" id="modalUrl" placeholder="https://cms.dst-connect.io/screen/...">
      </div>
      <div id="authResult"></div>
      <div class="actions">
        <button class="btn" onclick="closeModal()">Annuleren</button>
        <button class="btn btn-warning" onclick="testConnection()" id="testBtn">Test verbinding</button>
        <button class="btn btn-success" onclick="startProvision()" id="provisionBtn" disabled>Provision + Push</button>
        <button class="btn btn-primary" onclick="startPushOnly()" id="pushOnlyBtn" disabled>Alleen content pushen</button>
      </div>
    </div>
    <div id="modalStep2" style="display:none;">
      <div class="log" id="provisionLog"></div>
      <div id="screenshotArea"></div>
      <div class="actions" style="margin-top:16px;">
        <button class="btn btn-primary" onclick="closeModal()">Sluiten</button>
      </div>
    </div>
  </div>
</div>

<script>
let players = [];
let currentIp = '';

async function api(path, body) {
  const opts = {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body || {})};
  const r = await fetch('/api'+path, opts);
  if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error||'Request mislukt'); }
  return r.json();
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

async function scanPlayers() {
  const btn = document.getElementById('scanBtn');
  const status = document.getElementById('scanStatus');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Scannen...';
  status.textContent = 'mDNS browse actief, even geduld...';
  try {
    const data = await api('/scan');
    players = data.players || [];
    renderPlayers();
    status.textContent = players.length + ' player(s) gevonden';
  } catch (e) {
    status.textContent = 'Scan mislukt: ' + e.message;
  }
  btn.disabled = false;
  btn.textContent = 'Scan netwerk';
}

function renderPlayers() {
  const el = document.getElementById('playerList');
  if (!players.length) {
    el.innerHTML = '<div class="empty">Geen SpinetiX players gevonden in het netwerk</div>';
    return;
  }
  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Status</th><th>Model</th><th>Serial</th><th>IP-adres</th><th>MAC</th><th>Actie</th></tr></thead>';
  const tbody = document.createElement('tbody');
  players.forEach((p, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><span class="status-dot online"></span>Online</td>' +
      '<td><strong>' + esc(p.model) + '</strong></td>' +
      '<td>' + esc(p.serial) + '</td>' +
      '<td><code>' + esc(p.ip) + '</code></td>' +
      '<td><code style="font-size:12px;">' + esc(p.mac) + '</code></td>' +
      '<td></td>';
    const btn = document.createElement('button');
    btn.className = 'btn btn-primary btn-sm';
    btn.textContent = 'Configureren';
    btn.addEventListener('click', () => openModal(p.ip, p.model, p.serial));
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  el.innerHTML = '';
  el.appendChild(table);
}

function openModal(ip, model, serial) {
  currentIp = ip;
  document.getElementById('modalPlayer').value = model + ' - ' + serial + ' (' + ip + ')';
  document.getElementById('modalTitle').textContent = model + ' ' + serial + ' configureren';
  document.getElementById('authResult').innerHTML = '';
  document.getElementById('modalStep1').style.display = 'block';
  document.getElementById('modalStep2').style.display = 'none';
  document.getElementById('provisionBtn').disabled = true;
  document.getElementById('pushOnlyBtn').disabled = true;
  document.getElementById('provisionModal').classList.add('active');
}

function closeModal() {
  document.getElementById('provisionModal').classList.remove('active');
}

async function testConnection() {
  const btn = document.getElementById('testBtn');
  const result = document.getElementById('authResult');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Testen...';
  result.innerHTML = '';
  try {
    const data = await api('/test-auth', {
      ip: currentIp,
      username: document.getElementById('modalUser').value,
      password: document.getElementById('modalPass').value,
    });
    if (data.success) {
      const info = data.info;
      const hasKiosk = (info.features || []).some(f => f.includes('KIOSK'));
      const d = document.createElement('div');
      d.style.cssText = 'margin-top:12px;padding:12px;background:#f0fdf4;border-radius:6px;border:1px solid #bbf7d0;';
      d.innerHTML = '<strong style="color:#16a34a;">Verbinding OK</strong><br>' +
        '<span style="font-size:13px;color:#555;">' +
        'Firmware: ' + esc(info.firmware||'?') +
        ' | Resolutie: ' + esc(info.resolution||'?') +
        ' | Temp: ' + esc(info.temp||'?') + '&deg;C' +
        ' | Licentie: ' + (hasKiosk ? '<span class="badge badge-kiosk">KIOSK</span>' : '<span class="badge badge-no">Geen KIOSK</span>') +
        '</span>';
      result.innerHTML = '';
      result.appendChild(d);
      document.getElementById('provisionBtn').disabled = false;
      document.getElementById('pushOnlyBtn').disabled = false;
    } else {
      result.innerHTML = '<div style="margin-top:12px;padding:12px;background:#fef2f2;border-radius:6px;border:1px solid #fecaca;">' +
        '<strong style="color:#dc2626;">Verbinding mislukt</strong><br>' +
        '<span style="font-size:13px;">' + esc(data.error) + '</span></div>';
    }
  } catch (e) {
    result.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(e.message) + '</div>';
  }
  btn.disabled = false;
  btn.textContent = 'Test verbinding';
}

function appendLog(el, text, isError) {
  const span = document.createElement('span');
  if (isError) span.style.color = '#f87171';
  span.textContent = text + '\\n';
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}

function showScreenshot(imgBase64) {
  const area = document.getElementById('screenshotArea');
  area.innerHTML = '<p style="font-size:13px;color:#888;margin-top:12px;">Screenshot van player:</p>';
  const img = document.createElement('img');
  img.className = 'screenshot';
  img.src = 'data:image/jpeg;base64,' + imgBase64;
  area.appendChild(img);
}

async function startProvision() {
  const url = document.getElementById('modalUrl').value.trim();
  if (!url) { alert('Voer een screen URL in'); return; }
  if (!url.startsWith('https://')) { alert('URL moet beginnen met https://'); return; }

  document.getElementById('modalStep1').style.display = 'none';
  document.getElementById('modalStep2').style.display = 'block';
  const log = document.getElementById('provisionLog');
  log.innerHTML = '';
  document.getElementById('screenshotArea').innerHTML = '';

  try {
    const data = await api('/provision', {
      ip: currentIp,
      username: document.getElementById('modalUser').value,
      password: document.getElementById('modalPass').value,
      screen_url: url,
    });
    (data.steps || []).forEach(s => appendLog(log, s, false));
    if (data.success) {
      appendLog(log, '\\n--- PROVISIONING VOLTOOID ---', false);
      if (data.auth_hash) {
        appendLog(log, 'Claim code voor CMS: ' + data.auth_hash, false);
        var hashArea = document.getElementById('screenshotArea');
        var box = document.createElement('div');
        box.style.cssText = 'margin-top:12px;padding:16px;background:#f0fdf4;border-radius:8px;border:1px solid #bbf7d0;';
        box.innerHTML = '<strong style="color:#16a34a;">Claim code voor DST Connect CMS:</strong><br>' +
          '<code style="font-size:18px;background:#e5e7eb;padding:4px 12px;border-radius:4px;user-select:all;">' + esc(data.auth_hash) + '</code>' +
          '<p style="font-size:12px;color:#666;margin-top:8px;">Voer deze code in bij het scherm in het CMS om de player te koppelen.</p>';
        hashArea.insertBefore(box, hashArea.firstChild);
      }
      if (data.screenshot) showScreenshot(data.screenshot);
    } else {
      appendLog(log, 'FOUT: ' + (data.error || 'Onbekende fout'), true);
    }
  } catch (e) {
    appendLog(log, 'FOUT: ' + e.message, true);
  }
}

async function startPushOnly() {
  const url = document.getElementById('modalUrl').value.trim();
  if (!url) { alert('Voer een screen URL in'); return; }
  if (!url.startsWith('https://')) { alert('URL moet beginnen met https://'); return; }

  document.getElementById('modalStep1').style.display = 'none';
  document.getElementById('modalStep2').style.display = 'block';
  const log = document.getElementById('provisionLog');
  log.innerHTML = '';
  document.getElementById('screenshotArea').innerHTML = '';
  appendLog(log, 'Content pushen...', false);

  try {
    const data = await api('/push', {
      ip: currentIp,
      username: document.getElementById('modalUser').value,
      password: document.getElementById('modalPass').value,
      screen_url: url,
    });
    if (data.success) {
      appendLog(log, 'Content succesvol gepusht!', false);
      appendLog(log, '\\n--- VOLTOOID ---', false);
      setTimeout(async () => {
        try {
          const ss = await api('/screenshot', {
            ip: currentIp,
            username: document.getElementById('modalUser').value,
            password: document.getElementById('modalPass').value,
          });
          if (ss.success) showScreenshot(ss.image);
        } catch(_) {}
      }, 8000);
    } else {
      appendLog(log, 'FOUT: ' + (data.error || 'Onbekende fout'), true);
    }
  } catch (e) {
    appendLog(log, 'FOUT: ' + e.message, true);
  }
}
</script>
</body>
</html>'''.encode('utf-8')


# ─── HTTP Handler ────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def _check_origin(self):
        """CSRF protection: reject cross-origin POST requests.
        Same-origin requests may omit Origin, so only reject when
        Origin is present AND doesn't match."""
        origin = self.headers.get('Origin')
        if origin is not None and origin != ALLOWED_ORIGIN:
            self._json_error('Cross-origin request geweigerd', 403)
            return False
        return True

    def _read_body(self):
        """Read and parse JSON body with size limit."""
        length = int(self.headers.get('Content-Length', 0))
        if length > MAX_REQUEST_SIZE:
            self._json_error('Request te groot', 413)
            return None
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json_error('Ongeldige JSON', 400)
            return None

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(HTML_BYTES))
            self.end_headers()
            self.wfile.write(HTML_BYTES)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self._check_origin():
            return

        body = self._read_body()
        if body is None:
            return

        if self.path == '/api/scan':
            self._json({'players': scan_players()})

        elif self.path == '/api/test-auth':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(test_auth(body['ip'], body['username'], body['password']))

        elif self.path == '/api/provision':
            err = _require_fields(body, 'ip', 'username', 'password', 'screen_url')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            if not _validate_screen_url(body['screen_url']):
                self._json_error('Ongeldige screen URL (moet https:// zijn)', 400); return
            self._json(provision_player(
                body['ip'], body['username'], body['password'], body['screen_url']
            ))

        elif self.path == '/api/push':
            err = _require_fields(body, 'ip', 'username', 'password', 'screen_url')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            if not _validate_screen_url(body['screen_url']):
                self._json_error('Ongeldige screen URL (moet https:// zijn)', 400); return
            self._json(push_content_only(
                body['ip'], body['username'], body['password'], body['screen_url']
            ))

        elif self.path == '/api/screenshot':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(take_screenshot(body['ip'], body['username'], body['password']))

        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _json_error(self, message, status_code=400):
        body = json.dumps({'success': False, 'error': message}).encode()
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Only log errors, not every request
        if args and str(args[0]).startswith('5'):
            print(f"[HTTP] {args}")


# ─── Threaded Server ─────────────────────────────────────────────────────────

class ThreadedHTTPServer(HTTPServer):
    """HTTPServer that handles each request in a new thread."""
    def process_request(self, request, client_address):
        t = threading.Thread(target=self._handle, args=(request, client_address), daemon=True)
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import webbrowser
    server = ThreadedHTTPServer((BIND_HOST, PORT), Handler)
    url = f'http://localhost:{PORT}'
    print(f'\nSpinetiX Provisioner draait op {url}')
    print('Druk Ctrl+C om te stoppen.\n')
    threading.Timer(1, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nGestopt.')
        server.server_close()
