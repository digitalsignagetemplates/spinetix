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
import socket
import shutil
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from xml.sax.saxutils import escape as xml_escape

# ─── Config ──────────────────────────────────────────────────────────────────

PORT = 8090
BIND_HOST = '127.0.0.1'  # localhost only, not exposed to network
SCAN_TIMEOUT = 6  # seconds for mDNS browse
MDNS_AVAILABLE = shutil.which('dns-sd') is not None  # macOS, or Windows with Bonjour
MAX_SCAN_HOSTS = 4096  # max IPs per subnet scan (a /20)
SCAN_WORKERS = 128  # parallel probes during subnet scan
PROBE_CONNECT_TIMEOUT = 0.8  # seconds for TCP connect to port 443
PROBE_HTTP_TIMEOUT = 4  # seconds for identification request
REBOOT_WAIT = 30  # seconds before first check after reboot
REBOOT_MAX_WAIT = 300  # total seconds to wait for the player to come back
REBOOT_POLL_INTERVAL = 10  # seconds between checks after reboot
PUBLISH_PORT = 9802  # Elementi publish port (WebDAV PUT of index.svg)
PUBLISH_PORT_WAIT = 90  # seconds to wait for the publish port after boot
PUSH_ATTEMPTS = 3
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
    # 0.0.0.0/8 counts as "private" in older Python but connects to localhost
    if (addr.is_unspecified or addr.is_multicast or addr.is_reserved
            or (addr.version == 4 and addr in ipaddress.ip_network('0.0.0.0/8'))):
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


def scan_players(hosts=None):
    """Discover players: mDNS in the own VLAN plus optional unicast probe of
    extra IP ranges (other VLANs). Results are merged and deduplicated by IP."""
    global _discovered_ips
    with ThreadPoolExecutor(max_workers=2) as pool:
        mdns_future = pool.submit(_scan_mdns)
        subnet_future = pool.submit(scan_subnets, hosts or [])
        mdns_players = mdns_future.result()
        subnet_players = subnet_future.result()

    merged = {}
    for p in mdns_players:
        p['source'] = 'mDNS'
        merged[p['ip']] = p
    for p in subnet_players:
        if p['ip'] in merged:
            continue
        p['source'] = 'Subnet'
        merged[p['ip']] = p

    players = sorted(merged.values(), key=lambda p: ipaddress.ip_address(p['ip']))
    _discovered_ips = {p['ip'] for p in players}
    return players


def _scan_mdns():
    """Discover SpinetiX players via mDNS (dns-sd on macOS). Own VLAN only."""
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
        # No Bonjour (e.g. Windows without Bonjour SDK): ARP table only
        return _scan_arp_fallback()
    except Exception as e:
        print(f"Scan error: {e}")
        return []

    # Resolve players in parallel
    with ThreadPoolExecutor(max_workers=8) as pool:
        players = list(pool.map(_resolve_player, instances))

    return [p for p in players if p is not None]


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

        # Resolve hostname to IPv4 (mDNS .local works via the system resolver
        # on macOS and on Windows with Bonjour; ping flags differ per OS)
        ip = None
        try:
            infos = socket.getaddrinfo(hostname.rstrip('.'), 443, socket.AF_INET, socket.SOCK_STREAM)
            if infos:
                ip = infos[0][4][0]
        except OSError:
            pass

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


SPINETIX_MAC_PREFIX = '00:1D:50'
_ARP_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_ARP_MAC_RE = re.compile(r'\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b')


def _normalize_mac(raw):
    """'0:1d:50:22:27:82' (macOS) or '00-1d-50-22-27-82' (Windows) -> '00:1D:50:22:27:82'."""
    return ':'.join(o.zfill(2) for o in re.split(r'[:-]', raw)).upper()


def _scan_arp_fallback():
    """Fallback: scan ARP table for SpinetiX devices (MAC prefix 00:1d:50).
    Handles both macOS/Linux ('? (10.0.0.5) at 0:1d:50:..') and Windows
    ('  10.0.0.5   00-1d-50-..   dynamic') output. Only sees hosts the
    computer recently talked to in its own VLAN."""
    players = []
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        seen = set()
        for line in result.stdout.splitlines():
            ip_m = _ARP_IP_RE.search(line)
            mac_m = _ARP_MAC_RE.search(line)
            if not ip_m or not mac_m:
                continue
            mac = _normalize_mac(mac_m.group(1))
            ip = ip_m.group(1)
            if not mac.startswith(SPINETIX_MAC_PREFIX) or ip in seen or not _validate_ip(ip):
                continue
            seen.add(ip)
            players.append({
                'ip': ip,
                'model': 'HMP',
                'serial': '',
                'mac': mac,
                'hostname': '',
            })
    except Exception as e:
        print(f"ARP fallback error: {e}")
    return players


# ─── Subnet Scan (cross-VLAN) ────────────────────────────────────────────────
# mDNS and ARP only work inside the own broadcast domain (VLAN). Players in
# other VLANs are found by probing a routed IP range over unicast HTTPS.

def _parse_subnets(text):
    """Parse comma/space/newline separated IPs, CIDRs or ranges (a.b.c.d-e).
    Returns (list of host IP strings, error string or None)."""
    hosts = []
    for token in re.split(r'[\s,;]+', (text or '').strip()):
        if not token:
            continue
        try:
            if '-' in token:
                start_s, end_s = token.split('-', 1)
                start = ipaddress.ip_address(start_s)
                if '.' not in end_s:  # short form 10.0.0.10-50
                    end_s = start_s.rsplit('.', 1)[0] + '.' + end_s
                end = ipaddress.ip_address(end_s)
                if start.version != 4 or end.version != 4 or end < start:
                    return [], f'Ongeldige range: {token}'
                if not (start.is_private and end.is_private):
                    return [], f'Alleen privé-adressen toegestaan: {token}'
                if int(end) - int(start) + 1 > MAX_SCAN_HOSTS:
                    return [], f'Range te groot: {token}'
                hosts.extend(str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1))
            else:
                net = ipaddress.ip_network(token, strict=False)
                if net.version != 4:
                    return [], f'Alleen IPv4 ondersteund: {token}'
                if not net.is_private:
                    return [], f'Alleen privé-adressen toegestaan: {token}'
                if net.num_addresses > MAX_SCAN_HOSTS:
                    return [], f'Subnet te groot (max /{32 - (MAX_SCAN_HOSTS.bit_length() - 1)}): {token}'
                hosts.extend(str(h) for h in (net.hosts() if net.num_addresses > 2 else net))
        except ValueError:
            return [], f'Ongeldig subnet: {token}'
        if len(hosts) > MAX_SCAN_HOSTS:
            return [], f'Te veel adressen in totaal (max {MAX_SCAN_HOSTS})'
    # dedupe, keep order, drop loopback/metadata
    seen = set()
    result = []
    for h in hosts:
        if h not in seen and _validate_ip(h):
            seen.add(h)
            result.append(h)
    return result, None


def _port_open(ip, port, timeout=PROBE_CONNECT_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _mac_from_hostname(hostname):
    """SpinetiX hostnames look like spx-hmp-001d50222782."""
    m = re.search(r'spx-hmp-([0-9a-fA-F]{12})', hostname or '')
    if not m:
        return ''
    raw = m.group(1)
    return ':'.join(raw[i:i+2] for i in range(0, 12, 2)).upper()


def _peer_cert_text(ip):
    """Return the player's TLS certificate (DER) as lowercase latin-1 text, so
    subject/issuer strings like 'SpinetiX' or 'spx-hmp-<mac>' can be matched
    without credentials. Returns '' on failure."""
    try:
        with socket.create_connection((ip, 443), timeout=PROBE_HTTP_TIMEOUT) as sock:
            with _player_ssl_context().wrap_socket(sock, server_hostname=None) as tls:
                der = tls.getpeercert(binary_form=True) or b''
        return der.decode('latin-1').lower()
    except (OSError, ValueError):
        return ''


def _identify_player(ip):
    """Check whether a host with an open HTTPS port is a SpinetiX player.
    Uses unauthenticated signals only (no credentials are sent to unknown hosts):
    reverse DNS name, TLS certificate, Server header, auth realm and login page body.
    Returns (is_spinetix, info dict)."""
    info = {'ip': ip, 'model': 'HMP', 'serial': '', 'mac': '', 'hostname': ''}
    signals = []

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        info['hostname'] = hostname
        if 'spx-hmp' in hostname.lower():
            signals.append('dns')
            info['mac'] = _mac_from_hostname(hostname)
    except (OSError, UnicodeError):
        pass

    cert = _peer_cert_text(ip)
    if 'spinetix' in cert or 'spx-hmp' in cert:
        signals.append('cert')
        if not info['mac']:
            info['mac'] = _mac_from_hostname(cert)

    for path in ('/status/info', '/'):
        try:
            req = urllib.request.Request(f'https://{ip}{path}')
            resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=PROBE_HTTP_TIMEOUT)
            headers, body = resp.headers, resp.read(65536).decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            headers = e.headers
            try:
                body = e.read(65536).decode('utf-8', 'replace')
            except Exception:
                body = ''
        except Exception:
            continue

        # SpinetiX players send X-Spinetix-Firmware / X-Spinetix-Serial /
        # X-Raperca-Version headers on every response, also without auth.
        spx_headers = {k.lower(): v for k, v in (headers.items() if headers else [])
                       if k.lower().startswith(('x-spinetix-', 'x-raperca-'))}
        if spx_headers.get('x-spinetix-serial'):
            info['serial'] = spx_headers['x-spinetix-serial'].strip()
        if spx_headers.get('x-spinetix-firmware'):
            info['firmware'] = spx_headers['x-spinetix-firmware'].strip()

        haystack = ' '.join([
            headers.get('Server', '') if headers else '',
            headers.get('WWW-Authenticate', '') if headers else '',
            body,
        ]).lower()
        if spx_headers or 'spinetix' in haystack or re.search(r'\bhmp\s?\d{3}', haystack):
            signals.append(path)
            # /status/info may be readable without auth on some configurations
            for tag, key in (('serial', 'serial'), ('ethmac', 'mac')):
                m = re.search(f'<{tag}>(.*?)</{tag}>', body)
                if m:
                    info[key] = m.group(1).strip().upper() if key == 'mac' else m.group(1).strip()
            m = re.search(r'\b(HMP\s?\d{3})\b', body, re.IGNORECASE)
            if m and info['model'] == 'HMP':
                info['model'] = m.group(1).upper().replace(' ', '')
            break

    return bool(signals), info


def _probe_host(ip):
    """Return player dict if ip is a SpinetiX player, else None."""
    if not _port_open(ip, 443):
        return None
    ok, info = _identify_player(ip)
    return info if ok else None


def scan_subnets(hosts):
    """Probe a list of IPs in parallel for SpinetiX players."""
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        results = list(pool.map(_probe_host, hosts))
    return [r for r in results if r]


def probe_manual(ip):
    """Manually added IP: accept any host with HTTPS reachable, flag if unrecognised."""
    if not _port_open(ip, 443, timeout=3):
        return {'success': False, 'error': 'Geen HTTPS-verbinding met dit IP-adres (poort 443)'}
    ok, info = _identify_player(ip)
    info['verified'] = ok
    if not ok:
        info['model'] = 'Onbekend'
    return {'success': True, 'player': info}


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


def _describe_error(e):
    """Short human readable reason for a failed player request."""
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 401:
            return 'HTTP 401, credentials geweigerd'
        return f'HTTP {e.code}'
    reason = getattr(e, 'reason', e)
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return 'geen antwoord (timeout)'
    if isinstance(reason, ConnectionRefusedError):
        return 'verbinding geweigerd'
    if isinstance(reason, ssl.SSLError):
        return 'SSL-fout'
    if isinstance(reason, OSError):
        return f'netwerkfout: {reason.strerror or reason}'
    return type(e).__name__


def _port_status(ip, port, timeout=3):
    """'open', 'refused' (host up, nothing listening) or 'timeout' (packets
    dropped, typically a firewall between VLANs)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return 'open'
    except ConnectionRefusedError:
        return 'refused'
    except (socket.timeout, TimeoutError):
        return 'timeout'
    except OSError as e:
        return f'netwerkfout: {e.strerror or e}'


def _push_svg(ip, username, password, svg, log=print):
    """Upload the bridge SVG to the publish port. Waits for the port to open
    after a reboot and retries the upload. Returns (success, error message)."""
    deadline = time.time() + PUBLISH_PORT_WAIT
    status = _port_status(ip, PUBLISH_PORT)
    if status != 'open':
        log(f"Poort {PUBLISH_PORT} nog niet bereikbaar ({status}), wachten...")
    while status != 'open' and time.time() < deadline:
        time.sleep(5)
        status = _port_status(ip, PUBLISH_PORT)
    if status == 'timeout':
        return False, (f"Poort {PUBLISH_PORT} niet bereikbaar (timeout). Poort 443 werkt wel, "
                       f"dus waarschijnlijk blokkeert een firewall poort {PUBLISH_PORT} tussen "
                       f"de VLAN's. Sta TCP {PUBLISH_PORT} toe naar de player.")
    if status == 'refused':
        return False, (f"Player weigert poort {PUBLISH_PORT}: de publish-dienst draait niet. "
                       f"Controleer of de cloud uitgeschakeld is (Provision + Push).")
    if status != 'open':
        return False, f"Poort {PUBLISH_PORT} niet bereikbaar ({status})"

    url = f'https://{ip}:{PUBLISH_PORT}/index.svg'
    last_error = ''
    for attempt in range(1, PUSH_ATTEMPTS + 1):
        try:
            req = urllib.request.Request(url, data=svg.encode('utf-8'), method='PUT')
            req.add_header('Content-Type', 'image/svg+xml')
            req.add_header('Authorization', _auth_header(username, password))
            resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=30)
            if resp.status in (200, 201, 204):
                return True, ''
            last_error = f'HTTP {resp.status}'
        except urllib.error.HTTPError as e:
            last_error = _describe_error(e)
            if e.code in (401, 403):
                break  # retrying won't help
        except Exception as e:
            last_error = _describe_error(e)
        if attempt < PUSH_ATTEMPTS:
            log(f"Push poging {attempt} mislukt ({last_error}), opnieuw proberen...")
            time.sleep(10)
    return False, f"Content push mislukt: {last_error}"


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
        log(f"Wachten tot player terug is (max {REBOOT_MAX_WAIT // 60} minuten)...")
        time.sleep(REBOOT_WAIT)

        # Step 3: Wait for player to come back
        start = time.time()
        deadline = start - REBOOT_WAIT + REBOOT_MAX_WAIT
        last_error = ''
        last_logged = 0
        while True:
            try:
                _rpc_call(ip, 'get_info', [], username, password, timeout=5)
                log(f"Player is terug online (na {int(time.time() - start) + REBOOT_WAIT}s)")
                break
            except Exception as e:
                last_error = _describe_error(e)
            elapsed = int(time.time() - start) + REBOOT_WAIT
            if time.time() >= deadline:
                log(f"Player reageert niet na {elapsed}s (laatste fout: {last_error})")
                log("Cloud is al uitgeschakeld. Gebruik 'Alleen content pushen' zodra de player "
                    "bereikbaar is. Controleer of het IP-adres na de herstart gewijzigd is.")
                return {'success': False, 'steps': steps, 'auth_hash': auth_hash,
                        'error': f'Timeout na herstart ({last_error})'}
            if elapsed - last_logged >= 30:
                log(f"Nog niet bereikbaar na {elapsed}s ({last_error}), blijft proberen...")
                last_logged = elapsed
            time.sleep(REBOOT_POLL_INTERVAL)

        # Step 4: Push bridge SVG with RDM polling
        log("Bridge SVG pushen (content + RDM polling)...")
        svg = _build_svg(screen_url, auth_hash)
        ok, err = _push_svg(ip, username, password, svg, log)
        if ok:
            log("Content succesvol gepusht!")
        else:
            log(err)
            log("Cloud is al uitgeschakeld. Na het oplossen: gebruik 'Alleen content pushen'.")
            return {'success': False, 'steps': steps, 'auth_hash': auth_hash, 'error': 'Content push mislukt'}

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

    except Exception as e:
        log(f"Fout tijdens provisioning: {_describe_error(e)}")
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
        ok, err = _push_svg(ip, username, password, svg)
        if ok:
            return {'success': True}
        return {'success': False, 'error': err}
    except Exception as e:
        return {'success': False, 'error': f'Kan niet verbinden met player: {_describe_error(e)}'}


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
  .scan-options { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
  .scan-options label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 4px; color: #555; }
  .scan-options .hint { font-size: 12px; color: #888; margin-top: 4px; }
  .inline { display: flex; gap: 8px; }
  .inline input { flex: 1; }
  @media (max-width: 700px) { .scan-options { grid-template-columns: 1fr; } }
  .badge-src { background: #f3f4f6; color: #555; }
  .badge-warn { background: #fef3c7; color: #b45309; }

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
    <div class="scan-options">
      <div>
        <label for="subnets">Extra subnets / VLAN's (optioneel)</label>
        <input type="text" id="subnets" placeholder="10.20.0.0/24, 10.30.0.0/24, 192.168.5.10-50">
        <p class="hint">mDNS vindt alleen players in je eigen VLAN. Vul hier de IP-ranges van andere VLAN's in (max 4096 adressen).</p>
      </div>
      <div>
        <label for="manualIp">Player toevoegen via IP-adres</label>
        <div class="inline">
          <input type="text" id="manualIp" placeholder="10.20.0.15">
          <button class="btn btn-primary btn-sm" onclick="addManual()" id="manualBtn">Toevoegen</button>
        </div>
        <p class="hint" id="manualStatus"></p>
      </div>
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

const SUBNETS_KEY = 'spx_subnets';
try { document.getElementById('subnets').value = localStorage.getItem(SUBNETS_KEY) || ''; } catch (_) {}
document.getElementById('manualIp').addEventListener('keydown', e => { if (e.key === 'Enter') addManual(); });

async function scanPlayers() {
  const btn = document.getElementById('scanBtn');
  const status = document.getElementById('scanStatus');
  const subnets = document.getElementById('subnets').value.trim();
  try { localStorage.setItem(SUBNETS_KEY, subnets); } catch (_) {}
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Scannen...';
  status.textContent = subnets ? 'mDNS + subnet-scan actief, dit kan tot een minuut duren...' : 'mDNS browse actief, even geduld...';
  try {
    const data = await api('/scan', {subnets: subnets});
    const manual = players.filter(p => p.source === 'Handmatig');
    players = data.players || [];
    manual.forEach(m => { if (!players.some(p => p.ip === m.ip)) players.push(m); });
    renderPlayers();
    status.textContent = players.length + ' player(s) gevonden' +
      (data.mdns === false ? '. Let op: mDNS is niet beschikbaar op deze computer (alleen macOS of Windows met Bonjour), vul ook je eigen subnet in bij "Extra subnets".' : '');
  } catch (e) {
    status.textContent = 'Scan mislukt: ' + e.message;
  }
  btn.disabled = false;
  btn.textContent = 'Scan netwerk';
}

async function addManual() {
  const input = document.getElementById('manualIp');
  const btn = document.getElementById('manualBtn');
  const status = document.getElementById('manualStatus');
  const ip = input.value.trim();
  if (!ip) return;
  btn.disabled = true;
  status.style.color = '#888';
  status.textContent = 'Verbinding controleren...';
  try {
    const data = await api('/probe', {ip: ip});
    if (!data.success) throw new Error(data.error || 'Niet bereikbaar');
    const p = data.player;
    p.source = 'Handmatig';
    players = players.filter(x => x.ip !== p.ip);
    players.push(p);
    renderPlayers();
    input.value = '';
    status.style.color = p.verified ? '#16a34a' : '#b45309';
    status.textContent = p.verified ? 'SpinetiX player toegevoegd.' : 'Toegevoegd, maar niet herkend als SpinetiX. Controleer via "Test verbinding".';
  } catch (e) {
    status.style.color = '#dc2626';
    status.textContent = e.message;
  }
  btn.disabled = false;
}

function renderPlayers() {
  const el = document.getElementById('playerList');
  if (!players.length) {
    el.innerHTML = '<div class="empty">Geen SpinetiX players gevonden in het netwerk</div>';
    return;
  }
  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Status</th><th>Model</th><th>Serial</th><th>IP-adres</th><th>MAC</th><th>Via</th><th>Actie</th></tr></thead>';
  const tbody = document.createElement('tbody');
  players.forEach((p, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><span class="status-dot online"></span>Online</td>' +
      '<td><strong>' + esc(p.model) + '</strong></td>' +
      '<td>' + esc(p.serial) + '</td>' +
      '<td><code>' + esc(p.ip) + '</code></td>' +
      '<td><code style="font-size:12px;">' + esc(p.mac) + '</code></td>' +
      '<td><span class="badge ' + (p.verified === false ? 'badge-warn' : 'badge-src') + '">' + esc(p.source || 'mDNS') + '</span></td>' +
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
  appendLog(log, 'Bezig met provisionen, dit duurt 1 tot 5 minuten (inclusief herstart)...', false);

  try {
    const data = await api('/provision', {
      ip: currentIp,
      username: document.getElementById('modalUser').value,
      password: document.getElementById('modalPass').value,
      screen_url: url,
    });
    log.innerHTML = '';
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
            hosts, err = _parse_subnets(body.get('subnets', ''))
            if err:
                self._json_error(err, 400); return
            self._json({'players': scan_players(hosts), 'mdns': MDNS_AVAILABLE})

        elif self.path == '/api/probe':
            err = _require_fields(body, 'ip')
            if err:
                self._json_error(err, 400); return
            ip = str(body['ip']).strip()
            if not _validate_ip(ip):
                self._json_error('Ongeldig IP-adres (alleen privé-adressen)', 400); return
            result = probe_manual(ip)
            if result.get('success'):
                _discovered_ips.add(ip)
            self._json(result)

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
