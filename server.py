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
import gzip
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

# Player screen orientation (<display-orientation> values, verified on HMP400
# fw 4.9.8). Value -> (label, content is portrait)
ORIENTATIONS = {
    'horizontal': ('Liggend', False),
    'rotateRight': ('Staand (met de klok mee)', True),
    'rotateLeft': ('Staand (tegen de klok in)', True),
    'rotate180': ('Liggend, 180 graden gedraaid', False),
}
DEFAULT_ORIENTATION = 'horizontal'
MIN_CONTENT_SIZE = 240
MAX_CONTENT_SIZE = 7680
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
DEVICE_LOGS_PATH = '/device/logs'  # bridge ships its ring buffer here (RDM, to build)

# Watchdog timing baked into the bridge (keeps the screen always playing)
BRIDGE_REFRESH_HOUR = 3          # local hour (0-23) for the nightly iframe refresh
BRIDGE_PROBE_INTERVAL_MS = 120000  # reachability probe
BRIDGE_PROBE_FAILS_MAX = 3         # consecutive fails = treat as down

# Firmware update: official SpinetiX repositories per model (from support wiki).
# firmware_update(repo_uri, repo_id) installs in the background; the player
# applies it on the next reboot. repo_id selects the release channel.
FIRMWARE_REPOS = {
    'HMP400':  'http://download.spinetix.com/hmp400/updates/',
    'HMP400W': 'http://download.spinetix.com/hmp400w/updates/',
    'HMP350':  'http://download.spinetix.com/hmp350/updates/',
    'HMP300':  'http://download.spinetix.com/hmp300/updates/',
    'DiVA':    'http://download.spinetix.com/diva/updates/',
    'iBX410':  'http://download.spinetix.com/ibx410/updates/',
    'iBX410W': 'http://download.spinetix.com/ibx410w/updates/',
    'iBX440':  'http://download.spinetix.com/ibx440/updates/',
}
DEFAULT_FW_REPO_URI = 'http://download.spinetix.com/dsos/updates/'
DEFAULT_FW_REPO_ID = 'stable'


def _content_size(orientation, width=None, height=None):
    """Content size for the bridge SVG. Defaults to 1920x1080, or 1080x1920
    for portrait orientations. Custom sizes give other aspect ratios; the
    player scales the SVG to fit the screen. Returns ((w, h), error)."""
    if not width and not height:
        portrait = ORIENTATIONS.get(orientation, ORIENTATIONS[DEFAULT_ORIENTATION])[1]
        return ((1080, 1920) if portrait else (1920, 1080)), None
    try:
        w, h = int(width), int(height)
    except (TypeError, ValueError):
        return None, 'Vul zowel breedte als hoogte in (hele getallen)'
    if not (MIN_CONTENT_SIZE <= w <= MAX_CONTENT_SIZE and MIN_CONTENT_SIZE <= h <= MAX_CONTENT_SIZE):
        return None, f'Breedte en hoogte moeten tussen {MIN_CONTENT_SIZE} en {MAX_CONTENT_SIZE} liggen'
    return (w, h), None


def _set_orientation(ip, username, password, orientation):
    """Set the player's screen orientation. Applies immediately, no reboot.
    Returns error string or None."""
    xml = (f'<configuration version="2.3"><display-orientation>{orientation}'
           f'</display-orientation></configuration>')
    result = _rpc_call(ip, 'set_config', [{'xmlconfig': xml}], username, password).get('result', {})
    if result.get('success'):
        return None
    errors = '; '.join(e.get('description', '') for e in result.get('errors', []) if isinstance(e, dict))
    return f"Stand van het scherm niet ingesteld: {errors or 'onbekende fout'}"


def set_display_mode(ip, username, password, width=0, height=0, refresh=60, auto=False):
    """Set the player's HDMI/DP output video mode via <display-video-mode>.
    Standard notation is WxH@refresh (e.g. 1920x1080@60). A reboot is applied so
    the mode takes effect. Pass auto=True to revert to the preferred mode.

    Note: on HMP400/iBX the advanced display config needs the SYSTEMS feature;
    without it the player returns a config error, which is surfaced as-is."""
    if auto:
        mode = 'auto'
    else:
        try:
            w, h, r = int(width), int(height), int(refresh or 60)
        except (TypeError, ValueError):
            return {'success': False, 'error': 'Breedte/hoogte/refresh moeten gehele getallen zijn'}
        if not (MIN_CONTENT_SIZE <= w <= MAX_CONTENT_SIZE and MIN_CONTENT_SIZE <= h <= MAX_CONTENT_SIZE):
            return {'success': False, 'error': f'Resolutie buiten bereik ({MIN_CONTENT_SIZE}-{MAX_CONTENT_SIZE} px)'}
        if not (1 <= r <= 240):
            return {'success': False, 'error': 'Ongeldige refresh (1-240 Hz)'}
        mode = f'{w}x{h}@{r}'

    xml = (f'<configuration version="2.3"><display-video-mode>{xml_escape(mode)}'
           f'</display-video-mode><reboot/></configuration>')
    try:
        result = _rpc_call(ip, 'set_config', [{'xmlconfig': xml}], username, password, timeout=20).get('result', {})
    except Exception as e:
        return {'success': False, 'error': f'Kan niet verbinden met player: {_describe_error(e)}'}
    if result.get('success') or result.get('reboot_pending'):
        return {'success': True, 'mode': mode, 'reboot': True}
    errors = '; '.join(e.get('description', '') for e in result.get('errors', []) if isinstance(e, dict))
    return {'success': False, 'error': errors or 'Resolutie niet ingesteld (mogelijk SYSTEMS-licentie vereist)'}


def _build_svg(screen_url, auth_hash, width=1920, height=1080):
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
     width="{width}" height="{height}" viewBox="0 0 {width} {height}" dur="indefinite" viewport-fill="#000000">
  <iframe src="{safe_url}" x="0" y="0" width="{width}" height="{height}"/>
  <script type="text/ecmascript"><![CDATA[
    // DST Connect Bridge - SpinetiX RDM Agent
    // This script runs inside the SVG on the SpinetiX player and provides
    // the same polling behavior as the native Android/webOS/Windows applet.

    var AUTH_HASH = "{safe_hash}";
    var BASE = "{DST_CONNECT_BASE}";
    var CONFIG_URL = BASE + "{DEVICE_CONFIG_PATH}/" + AUTH_HASH;
    var STATUS_URL = BASE + "{DEVICE_STATUS_PATH}/" + AUTH_HASH;
    var LOGS_URL   = BASE + "{DEVICE_LOGS_PATH}/" + AUTH_HASH;
    var SCREEN_URL = "{safe_url}";
    var CONFIG_INTERVAL = 30000;  // 30s config poll
    var STATUS_INTERVAL = 60000;  // 60s status heartbeat

    // ─── Watchdog settings (keep the screen always playing) ─────────
    // Nightly refresh from the SVG context pre-empts the screen page's own
    // (unreliable in-iframe) auto-reload: the iframe is reloaded here before
    // the inner page's long-run timer can ever fire.
    var REFRESH_HOUR   = {BRIDGE_REFRESH_HOUR};  // local hour for the nightly refresh
    var PROBE_INTERVAL = {BRIDGE_PROBE_INTERVAL_MS};
    var PROBE_FAILS_MAX  = {BRIDGE_PROBE_FAILS_MAX};
    var probeFails = 0;
    var wasDown = false;
    var START_TS = (new Date()).getTime();

    // ─── Log ring buffer (extended logs) ────────────────────────────
    // Captures bridge + watchdog events so dev can see WHY a screen reloaded
    // or dropped. Shipped on a "getLogs" command and on every reload.
    var LOG_MAX = 200;
    var logBuf = [];
    function logEvent(level, msg) {{
      try {{
        logBuf.push((new Date()).toISOString() + " [" + level + "] " + msg);
        if (logBuf.length > LOG_MAX) logBuf.shift();
      }} catch(e) {{}}
    }}
    function shipLogs(reason) {{
      try {{
        var xhr = new XMLHttpRequest();
        xhr.open("POST", LOGS_URL, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.timeout = 15000;
        xhr.send(JSON.stringify({{
          reason: reason || "manual",
          serial: AUTH_HASH,
          uptimeMs: (new Date()).getTime() - START_TS,
          screenUrl: SCREEN_URL,
          onLine: (typeof navigator.onLine === "boolean") ? navigator.onLine : null,
          userAgent: navigator.userAgent || "SpinetiX HMP",
          lines: logBuf
        }}));
      }} catch(e) {{}}
    }}

    // ─── Reliable iframe reload (SpinetiX-native path) ──────────────
    function reloadScreen() {{
      try {{
        var iframes = document.getElementsByTagName("iframe");
        if (iframes.length > 0) {{
          var sep = SCREEN_URL.indexOf("?") === -1 ? "?" : "&";
          iframes[0].setAttribute("src", SCREEN_URL + sep + "_r=" + (new Date()).getTime());
          logEvent("INFO", "reloadScreen() -> iframe src reset");
        }}
      }} catch(e) {{ logEvent("ERROR", "reloadScreen failed: " + e); }}
    }}

    // ─── Reachability watchdog ──────────────────────────────────────
    // The bridge cannot inspect the cross-origin iframe DOM, so it probes the
    // screen URL. If the host goes down and comes back, we reload once it is
    // reachable again, so a transient outage self-heals.
    function probeScreen() {{
      try {{
        var xhr = new XMLHttpRequest();
        xhr.open("GET", SCREEN_URL + (SCREEN_URL.indexOf("?") === -1 ? "?" : "&") + "_p=" + (new Date()).getTime(), true);
        xhr.timeout = 15000;
        xhr.onreadystatechange = function() {{
          if (xhr.readyState !== 4) return;
          if (xhr.status >= 200 && xhr.status < 400) {{
            if (wasDown) {{ wasDown = false; probeFails = 0; logEvent("WARN", "screen recovered -> reload"); shipLogs("recovered"); reloadScreen(); }}
            else {{ probeFails = 0; }}
          }} else {{
            probeFails++;
            logEvent("WARN", "probe HTTP " + xhr.status + " (fail " + probeFails + ")");
            if (probeFails >= PROBE_FAILS_MAX) wasDown = true;
          }}
        }};
        xhr.ontimeout = function() {{
          probeFails++;
          logEvent("WARN", "probe timeout (fail " + probeFails + ")");
          if (probeFails >= PROBE_FAILS_MAX) wasDown = true;
        }};
        xhr.send();
      }} catch(e) {{}}
    }}

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
        reloadScreen();
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
          case "screenReload":
            // Reload just the content iframe (no full applet restart)
            reloadScreen();
            break;
          case "getLogs":
            // Ship the extended log buffer to the platform on demand
            shipLogs("command");
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

    setInterval(probeScreen, PROBE_INTERVAL);     // reachability watchdog

    // Nightly hard refresh at REFRESH_HOUR local time (reschedules itself; the
    // SVG script keeps running across iframe reloads, so the chain persists).
    function msUntilNextRefresh() {{
      var now = new Date();
      var next = new Date(now.getFullYear(), now.getMonth(), now.getDate(), REFRESH_HOUR, 0, 0, 0);
      if (next.getTime() <= now.getTime()) next = new Date(next.getTime() + 86400000);
      return next.getTime() - now.getTime();
    }}
    function scheduleNightlyRefresh() {{
      setTimeout(function() {{
        logEvent("INFO", "nightly refresh (" + REFRESH_HOUR + ":00)");
        shipLogs("scheduled");
        reloadScreen();
        scheduleNightlyRefresh();
      }}, msUntilNextRefresh());
    }}
    scheduleNightlyRefresh();

    logEvent("INFO", "bridge started, onLine=" + ((typeof navigator.onLine === "boolean") ? navigator.onLine : "n/a"));
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

        # Extract resolution (render/output resolution)
        w = re.search(r'<resolutionWidth>(.*?)</resolutionWidth>', body)
        h = re.search(r'<resolutionHeight>(.*?)</resolutionHeight>', body)
        if w and h and w.group(1) != 'unknown':
            info['resolution'] = f"{w.group(1)}x{h.group(1)}"

        # Extra display metrics (refresh, colorspace, output type, orientation)
        rfr = re.search(r'<verticalRefresh>(.*?)</verticalRefresh>', body) \
            or re.search(r'<display>.*?<refresh>(.*?)</refresh>', body, re.DOTALL)
        if rfr:
            info['refresh'] = rfr.group(1)
        cs = re.search(r'<colorspace>(.*?)</colorspace>', body)
        if cs:
            info['colorspace'] = cs.group(1)
        dt = re.search(r'<display>.*?<type>(.*?)</type>', body, re.DOTALL)
        if dt:
            info['outputType'] = dt.group(1)
        orient = re.search(r'<orientation>(.*?)</orientation>', body)
        if orient:
            info['orientation'] = orient.group(1)

        # Current configured video mode (auto when the tag is unset)
        try:
            cfg = _rpc_call(ip, 'get_config', [], username, password, timeout=8)
            xml = cfg.get('result', {}).get('xmlconfig', '')
            vm = re.search(r'<display-video-mode>(.*?)</display-video-mode>', xml)
            info['videoMode'] = vm.group(1) if vm else 'auto'
        except Exception:
            pass

        return {'success': True, 'info': info}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {'success': False, 'error': 'Ongeldige credentials'}
        return {'success': False, 'error': f'HTTP fout ({e.code})'}
    except Exception:
        return {'success': False, 'error': 'Kan niet verbinden met player'}


def provision_player(ip, username, password, screen_url, mac='',
                     orientation=DEFAULT_ORIENTATION, size=(1920, 1080)):
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

        # Step 4: Screen orientation (applies immediately, no reboot)
        log(f"Stand van het scherm: {ORIENTATIONS[orientation][0]}")
        err = _set_orientation(ip, username, password, orientation)
        if err:
            log(err)
            return {'success': False, 'steps': steps, 'auth_hash': auth_hash, 'error': err}

        # Step 5: Push bridge SVG with RDM polling
        log(f"Bridge SVG pushen ({size[0]}x{size[1]}, content + RDM polling)...")
        svg = _build_svg(screen_url, auth_hash, *size)
        ok, err = _push_svg(ip, username, password, svg, log)
        if ok:
            log("Content succesvol gepusht!")
        else:
            log(err)
            log("Cloud is al uitgeschakeld. Na het oplossen: gebruik 'Alleen content pushen'.")
            return {'success': False, 'steps': steps, 'auth_hash': auth_hash, 'error': 'Content push mislukt'}

        # Step 6: Verify with screenshot
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


def push_content_only(ip, username, password, screen_url, mac='',
                      orientation=DEFAULT_ORIENTATION, size=(1920, 1080)):
    """Push content without disable-cloud (for already provisioned players)."""
    try:
        if not mac:
            info = test_auth(ip, username, password)
            if info.get('success') and info.get('info', {}).get('ethmac'):
                mac = info['info']['ethmac']
        if not mac:
            return {'success': False, 'error': 'Kan MAC-adres niet ophalen'}
        auth_hash = _mac_to_auth_hash(mac)
        err = _set_orientation(ip, username, password, orientation)
        if err:
            return {'success': False, 'error': err}
        svg = _build_svg(screen_url, auth_hash, *size)
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
        image = base64.b64encode(resp.read()).decode()
    except Exception as e:
        return {'success': False, 'error': f'Screenshot mislukt: {_describe_error(e)}'}
    # The snapshot is the raw panel output; report the orientation so the UI
    # can show it upright. Not fatal if it can't be read.
    orientation = ''
    try:
        xml = _rpc_call(ip, 'get_config', [], username, password).get('result', {}).get('xmlconfig', '')
        m = re.search(r'<display-orientation>(.*?)</display-orientation>', xml)
        orientation = m.group(1) if m else ''
    except Exception:
        pass
    return {'success': True, 'image': image, 'orientation': orientation}


# ─── Bridge upgrade (fleet rollout, preserves per-player content) ─────────────

def _fetch_remote_svg(ip, username, password):
    """Read the bridge SVG currently published on the player."""
    url = f'https://{ip}/content/index.svg'
    req = urllib.request.Request(url)
    req.add_header('Authorization', _auth_header(username, password))
    resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=15)
    return resp.read().decode('utf-8', 'replace')


def _extract_svg_fields(svg):
    """Pull the per-player values out of an existing bridge SVG so an upgrade
    can keep the player's own screen, auth hash and size."""
    screen = re.search(r'var SCREEN_URL = "(.*?)"', svg)
    ahash = re.search(r'var AUTH_HASH = "(.*?)"', svg)
    size = re.search(r'<svg[^>]*\bwidth="(\d+)"[^>]*\bheight="(\d+)"', svg)
    return {
        'screen_url': screen.group(1) if screen else '',
        'auth_hash': ahash.group(1) if ahash else '',
        'size': (int(size.group(1)), int(size.group(2))) if size else (1920, 1080),
    }


def upgrade_bridge(ip, username, password):
    """Re-push the current bridge template to an already-provisioned player,
    keeping its own screen URL / auth hash / size. Used for the fleet rollout."""
    try:
        svg = _fetch_remote_svg(ip, username, password)
        f = _extract_svg_fields(svg)
        if not f['screen_url'] or not f['auth_hash']:
            return {'success': False, 'error': 'Kan huidige screen-URL/authHash niet uit de player lezen'}
        new_svg = _build_svg(f['screen_url'], f['auth_hash'], *f['size'])
        ok, err = _push_svg(ip, username, password, new_svg)
        if ok:
            return {'success': True, 'screen_url': f['screen_url'], 'auth_hash': f['auth_hash']}
        return {'success': False, 'error': err}
    except Exception as e:
        return {'success': False, 'error': f'Kan niet verbinden met player: {_describe_error(e)}'}


# ─── Diagnostics / extended logs (read straight from the device) ──────────────

def fetch_diagnostics(ip, username, password):
    """Pull the player's own status report (/info): uptime, temp, boot reason,
    firmware, and the fileErrors list — where content/connection errors show up
    (this is where the CMS 404 heartbeat failure is visible)."""
    try:
        url = f'https://{ip}/info'
        req = urllib.request.Request(url)
        req.add_header('Authorization', _auth_header(username, password))
        resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=15)
        xml = resp.read().decode('utf-8', 'replace')
    except Exception as e:
        return {'success': False, 'error': f'Diagnose mislukt: {_describe_error(e)}'}

    def one(tag):
        m = re.search(rf'<{tag}>(.*?)</{tag}>', xml, re.DOTALL)
        return m.group(1).strip() if m else ''

    errors = []
    for block in re.findall(r'<error>(.*?)</error>', xml, re.DOTALL):
        def sub(tag):
            m = re.search(rf'<{tag}>(.*?)</{tag}>', block, re.DOTALL)
            return m.group(1).strip() if m else ''
        errors.append({'time': sub('time'), 'code': sub('code'),
                       'source': sub('source'), 'detail': sub('custom')})

    return {'success': True, 'diagnostics': {
        'serial': one('serial'),
        'uptime': one('uptime'),
        'temp': one('temp'),
        'bootReason': one('bootReason'),
        'safemode': one('safemode'),
        'firmware': one('firmware'),
        'ip': one('ip'),
        'fileErrors': errors,
    }}


# ─── Firmware update (official SpinetiX repository) ───────────────────────────

def _detect_model(ip, username, password):
    """Read the player model (e.g. HMP400) from /info's device <name>."""
    try:
        url = f'https://{ip}/info'
        req = urllib.request.Request(url)
        req.add_header('Authorization', _auth_header(username, password))
        resp = urllib.request.urlopen(req, context=_player_ssl_context(), timeout=10)
        xml = resp.read().decode('utf-8', 'replace')
        m = re.search(r'<device>.*?<name>(.*?)</name>', xml, re.DOTALL)
        return m.group(1).strip() if m else ''
    except Exception:
        return ''


def _fw_repo_for_model(model):
    if not model:
        return DEFAULT_FW_REPO_URI
    for key, uri in FIRMWARE_REPOS.items():
        if key.lower() in model.lower():
            return uri
    return DEFAULT_FW_REPO_URI


def update_firmware(ip, username, password, repo_uri='', repo_id=''):
    """Start a firmware update from SpinetiX's official repository. The player
    downloads in the background and applies it on the next reboot. Returns the
    handle for firmware_status()."""
    model = _detect_model(ip, username, password)
    repo_uri = repo_uri or _fw_repo_for_model(model)
    repo_id = repo_id or DEFAULT_FW_REPO_ID
    # The RPC param shape isn't published; try a named object, fall back to
    # positional. A wrong shape errors out harmlessly (no firmware is applied).
    last_err = ''
    for params in ([{'repo_uri': repo_uri, 'repo_id': repo_id}], [repo_uri, repo_id]):
        try:
            res = _rpc_call(ip, 'firmware_update', params, username, password, timeout=30)
            if 'error' in res and res['error']:
                last_err = str(res['error']); continue
            return {'success': True, 'model': model, 'repo_uri': repo_uri,
                    'repo_id': repo_id, 'result': res.get('result')}
        except Exception as e:
            last_err = _describe_error(e)
    return {'success': False, 'error': f'Firmware-update kon niet starten: {last_err}',
            'model': model, 'repo_uri': repo_uri}


def reboot_player(ip, username, password):
    """Reboot the player via the RPC restart method."""
    try:
        _rpc_call(ip, 'restart', [], username, password, timeout=15)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': f'Herstart mislukt: {_describe_error(e)}'}


_LATEST_FW_CACHE = {}  # model -> (timestamp, 'ver-rel' or None)

def _latest_firmware(model):
    """Look up the newest firmware for a model in the official SpinetiX repo.
    Reads repodata/*-spxdata.xml.gz and returns 'ver-rel' (e.g. '4.10.0-1.0.1')
    or None. Cached for 1 hour so bulk checks hit the repo once."""
    if not model:
        return None
    key = model.lower()
    hit = _LATEST_FW_CACHE.get(key)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]

    base = _fw_repo_for_model(model).rstrip('/')  # .../<model>/updates
    pkg_name = 'fw-spinetix-' + key
    latest = None
    try:
        # Find the spxdata file (its name carries a checksum) via repomd.xml,
        # falling back to scraping the repodata directory listing.
        repomd = urllib.request.urlopen(f'{base}/repodata/repomd.xml', timeout=12).read().decode('utf-8', 'replace')
        m = re.search(r'(?:href|location href)="(repodata/[0-9a-f]+-spxdata\.xml\.gz)"', repomd)
        if not m:
            listing = urllib.request.urlopen(f'{base}/repodata/', timeout=12).read().decode('utf-8', 'replace')
            m = re.search(r'([0-9a-f]+-spxdata\.xml\.gz)', listing)
            spx_path = 'repodata/' + m.group(1) if m else None
        else:
            spx_path = m.group(1)
        if not spx_path:
            raise ValueError('spxdata not found')
        spx_url = f'{base}/{spx_path}'
        raw = urllib.request.urlopen(spx_url, timeout=15).read()
        xml = gzip.decompress(raw).decode('utf-8', 'replace')
        # Scan each package; keep the one whose <name> matches exactly.
        for block in re.findall(r'<package\b.*?</package>', xml, re.DOTALL):
            nm = re.search(r'<name>(.*?)</name>', block)
            if not nm or nm.group(1).strip() != pkg_name:
                continue
            ver = re.search(r'<version[^>]*\bver="([^"]+)"', block)
            rel = re.search(r'<version[^>]*\brel="([^"]+)"', block)
            if ver:
                cand = ver.group(1) + ('-' + rel.group(1) if rel else '')
                if latest is None or _fw_tuple(cand) > _fw_tuple(latest):
                    latest = cand
    except Exception:
        latest = None

    _LATEST_FW_CACHE[key] = (time.time(), latest)
    return latest


def _fw_tuple(version):
    """Comparable tuple from a firmware string like '4.10.0-1.0.1-2ee62d60'.
    Uses the numeric ver and rel parts (ignores the trailing build hash)."""
    nums = []
    for part in version.split('-')[:2]:            # ver, rel
        for n in part.split('.'):
            nums.append(int(n) if n.isdigit() else 0)
    return tuple(nums)


def check_firmware(ip, username, password):
    """Compare the player's firmware against the newest in the SpinetiX repo."""
    try:
        info = _rpc_call(ip, 'get_info', [], username, password, timeout=12).get('result', {})
    except Exception as e:
        return {'success': False, 'error': f'Kan versie niet ophalen: {_describe_error(e)}'}
    current = (info.get('firmware', {}) or {}).get('version', '') if isinstance(info.get('firmware'), dict) else ''
    model = info.get('model', '')
    latest = _latest_firmware(model)
    result = {'success': True, 'current': current, 'model': model, 'latest': latest}
    if not current or not latest:
        result['status'] = 'unknown'
    elif _fw_tuple(current) >= _fw_tuple(latest):
        result['status'] = 'up_to_date'
    else:
        result['status'] = 'update_available'
    return result


def firmware_status(ip, username, password, handle=None):
    """Poll an in-progress firmware update."""
    params = [handle] if handle is not None else []
    try:
        res = _rpc_call(ip, 'firmware_update_status', params, username, password, timeout=15)
        if 'error' in res and res['error']:
            return {'success': False, 'error': str(res['error'])}
        return {'success': True, 'result': res.get('result')}
    except Exception as e:
        return {'success': False, 'error': _describe_error(e)}


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
  .badge-ok { background: #dcfce7; color: #16a34a; }

  .modal .hint { font-size: 12px; color: #888; margin-top: 4px; }
  select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; width: 100%; background: white; }
  input[type="text"], input[type="password"] { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; width: 100%; }
  input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }

  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 100; align-items: center; justify-content: center; }
  .modal-overlay.active { display: flex; }
  .modal { background: white; border-radius: 12px; padding: 28px; width: 720px; max-width: 95vw; max-height: 92vh; overflow-y: auto; }
  .modal h3 { font-size: 18px; margin-bottom: 16px; }
  .modal .field { margin-bottom: 14px; }
  .modal label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 4px; color: #555; }
  .modal .actions { display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-start; margin-top: 16px; }
  .section { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
  .section > .section-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; margin: -4px 0 12px; }
  .section .field:last-child { margin-bottom: 0; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .btn-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  .btn-row + .btn-row { margin-top: 10px; }
  .row-label { width: 100%; font-size: 12px; color: #6b7280; margin-bottom: 2px; }
  @media (max-width: 560px) { .grid2 { grid-template-columns: 1fr; } }

  .log { background: #1a1a2e; color: #4ade80; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; max-height: 300px; overflow-y: auto; margin-top: 12px; white-space: pre-wrap; }

  .shots-bar { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 16px; }
  .shots-bar .f { display: flex; flex-direction: column; gap: 4px; }
  .shots-bar label { font-size: 12px; color: #555; font-weight: 500; }
  .shots-bar input { width: 160px; }
  .thumb { width: 128px; max-height: 128px; object-fit: contain; background: #000; border-radius: 4px; cursor: zoom-in; display: block; }
  .shot-msg { font-size: 12px; color: #888; max-width: 160px; }
  .shot-msg.err { color: #dc2626; }
  .lightbox { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.85); z-index: 200; align-items: center; justify-content: center; flex-direction: column; gap: 12px; padding: 16px; }
  .lightbox.active { display: flex; }
  .lightbox img { max-width: 100%; max-height: 82vh; border-radius: 6px; background: #000; }
  .lightbox .cap { color: #ddd; font-size: 13px; }
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
    <div class="shots-bar">
      <div class="f"><label for="shotUser">Username</label><input type="text" id="shotUser" value="admin" autocomplete="off"></div>
      <div class="f"><label for="shotPass">Wachtwoord</label><input type="password" id="shotPass" autocomplete="off"></div>
      <button class="btn btn-primary btn-sm" onclick="screenshotAll()" id="shotAllBtn">Screenshots van alle players</button>
      <button class="btn btn-primary btn-sm" onclick="checkFwAll()" id="fwAllBtn">Firmware controleren</button>
      <button class="btn btn-warning btn-sm" onclick="upgradeAll()" id="upgradeAllBtn">Bridge bijwerken op alle players</button>
      <button class="btn btn-warning btn-sm" onclick="rebootAll()" id="rebootAllBtn">Herstart alle players</button>
      <span id="upgradeAllStatus" style="font-size:13px;color:#555;margin-left:8px;"></span>
      <span id="shotStatus" class="shot-msg" style="max-width:none;"></span>
    </div>
    <div id="playerList">
      <div class="empty">Klik op "Scan netwerk" om te beginnen</div>
    </div>
  </div>
</div>

<div class="lightbox" id="lightbox" onclick="closeLightbox()">
  <img id="lightboxImg" alt="Screenshot">
  <div class="cap" id="lightboxCap"></div>
</div>

<div class="modal-overlay" id="provisionModal">
  <div class="modal">
    <h3 id="modalTitle">Player configureren</h3>
    <div id="modalStep1">
      <div class="section">
        <div class="section-title">Verbinding</div>
        <div class="field">
          <label>Player</label>
          <input type="text" id="modalPlayer" readonly style="background:#f5f5f5;">
        </div>
        <div class="grid2">
          <div class="field">
            <label>Username</label>
            <input type="text" id="modalUser" value="admin">
          </div>
          <div class="field">
            <label>Wachtwoord</label>
            <input type="password" id="modalPass" value="">
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-warning" onclick="testConnection()" id="testBtn">Test verbinding</button>
        </div>
        <div id="authResult"></div>
      </div>

      <div class="section">
        <div class="section-title">Content</div>
        <div class="field">
          <label>Screen URL</label>
          <input type="text" id="modalUrl" placeholder="https://cms.dst-connect.io/screen/...">
        </div>
        <div class="grid2">
          <div class="field">
            <label for="modalOrientation">Stand van het scherm</label>
            <select id="modalOrientation">__ORIENTATION_OPTIONS__</select>
          </div>
          <div class="field">
            <label>Eigen formaat content (optioneel)</label>
            <div class="inline">
              <input type="text" id="modalWidth" inputmode="numeric" placeholder="Breedte">
              <span style="align-self:center;color:#888;">x</span>
              <input type="text" id="modalHeight" inputmode="numeric" placeholder="Hoogte">
            </div>
          </div>
        </div>
        <p class="hint">Leeg laten = automatisch: 1920x1080 liggend, 1080x1920 staand. Een eigen formaat wordt passend geschaald op het scherm.</p>
      </div>

      <div class="section">
        <div class="section-title">Uitvoerresolutie van de player (HDMI/DP)</div>
        <div class="btn-row">
          <input type="text" id="outW" inputmode="numeric" placeholder="Breedte" style="width:90px;">
          <span style="color:#888;">x</span>
          <input type="text" id="outH" inputmode="numeric" placeholder="Hoogte" style="width:90px;">
          <span style="color:#888;">@</span>
          <input type="text" id="outR" inputmode="numeric" placeholder="Hz" value="60" style="width:60px;">
          <button class="btn btn-warning btn-sm" onclick="applyDisplayMode(false)" id="resBtn" disabled>Resolutie toepassen</button>
          <button class="btn btn-sm" onclick="applyDisplayMode(true)" id="resAutoBtn" disabled>Auto</button>
        </div>
        <p class="hint">Handmatig in pixels, bijv. 4K-player naar Full HD: 1920 x 1080 @ 60. De player <strong>herstart</strong> om de mode toe te passen. Let op: op HMP400/iBX vereist dit de SYSTEMS-licentie.</p>
      </div>

      <div class="section">
        <div class="section-title">Acties</div>
        <div class="btn-row">
          <span class="row-label">Uitrollen</span>
          <button class="btn btn-success" onclick="startProvision()" id="provisionBtn" disabled>Provision + Push</button>
          <button class="btn btn-primary" onclick="startPushOnly()" id="pushOnlyBtn" disabled>Alleen content pushen</button>
        </div>
        <div class="btn-row">
          <span class="row-label">Hulpmiddelen</span>
          <button class="btn btn-primary" onclick="fetchDiagnostics()" id="diagBtn" disabled>Diagnose / logs</button>
          <button class="btn btn-primary" onclick="modalScreenshot()" id="shotBtn" disabled>Screenshot</button>
          <button class="btn btn-warning" onclick="modalReboot()" id="rebootBtn" disabled>Herstart</button>
          <button class="btn btn-warning" onclick="startFirmware()" id="fwBtn" disabled>Firmware bijwerken</button>
        </div>
      </div>

      <div id="diagResult"></div>
      <div class="actions">
        <button class="btn" onclick="closeModal()">Sluiten</button>
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
const shots = {};  // ip -> {image, time} or {error} or {loading}; kept across rescans
const fwStatus = {};  // ip -> {current, latest, status} or {loading} or {error}

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
  table.innerHTML = '<thead><tr><th>Status</th><th>Model</th><th>Serial</th><th>IP-adres</th><th>MAC</th><th>Via</th><th>Firmware</th><th>Screenshot</th><th>Actie</th></tr></thead>';
  const tbody = document.createElement('tbody');
  players.forEach((p, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><span class="status-dot online"></span>Online</td>' +
      '<td><strong>' + esc(p.model) + '</strong></td>' +
      '<td>' + esc(p.serial) + '</td>' +
      '<td><code>' + esc(p.ip) + '</code></td>' +
      '<td><code style="font-size:12px;">' + esc(p.mac) + '</code></td>' +
      '<td><span class="badge ' + (p.verified === false ? 'badge-warn' : 'badge-src') + '">' + esc(p.source || 'mDNS') + '</span></td>' +
      '<td class="fw-cell"></td>' +
      '<td class="shot-cell"></td>' +
      '<td></td>';
    tr.querySelector('.fw-cell').appendChild(renderFwCell(p));
    tr.querySelector('.shot-cell').appendChild(renderShotCell(p));
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

function shotCreds() {
  return {
    username: document.getElementById('shotUser').value.trim(),
    password: document.getElementById('shotPass').value,
  };
}

function renderFwCell(p) {
  const wrap = document.createElement('div');
  const f = fwStatus[p.ip];
  if (f && f.loading) {
    wrap.innerHTML = '<span class="shot-msg">Controleren...</span>';
  } else if (f && f.error) {
    wrap.innerHTML = '<span class="shot-msg err">' + esc(f.error) + '</span>';
  } else if (f && f.current) {
    let badge = '';
    if (f.status === 'up_to_date') badge = '<span class="badge badge-ok">actueel</span>';
    else if (f.status === 'update_available') badge = '<span class="badge badge-warn">nieuw: ' + esc(f.latest) + '</span>';
    else badge = '<span class="badge badge-src">?</span>';
    wrap.innerHTML = '<code style="font-size:12px;">' + esc(f.current) + '</code><br>' + badge;
  } else {
    wrap.innerHTML = '<span class="shot-msg">&ndash;</span>';
  }
  return wrap;
}

async function checkFwAll() {
  const btn = document.getElementById('fwAllBtn');
  const status = document.getElementById('shotStatus');
  if (!players.length) { status.textContent = 'Nog geen players, scan eerst het netwerk.'; return; }
  const creds = shotCreds();
  if (!creds.password) { status.textContent = 'Vul eerst het wachtwoord in.'; return; }
  btn.disabled = true;
  const queue = players.slice();
  let done = 0;
  players.forEach(p => { fwStatus[p.ip] = {loading: true}; });
  renderPlayers();
  status.textContent = 'Firmware controleren: 0 van ' + queue.length;
  const worker = async () => {
    while (queue.length) {
      const p = queue.shift();
      try {
        const data = await api('/firmware-check', {ip: p.ip, username: creds.username, password: creds.password});
        fwStatus[p.ip] = data.success ? {current: data.current, latest: data.latest, status: data.status}
                                      : {error: data.error || 'mislukt'};
      } catch (e) { fwStatus[p.ip] = {error: e.message}; }
      done++;
      status.textContent = 'Firmware controleren: ' + done + ' van ' + players.length;
      renderPlayers();
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  const n = players.filter(p => (fwStatus[p.ip]||{}).status === 'update_available').length;
  status.textContent = 'Firmware gecontroleerd' + (n ? ' — ' + n + ' player(s) met een nieuwere versie beschikbaar' : ' — alles actueel');
  btn.disabled = false;
}

async function rebootAll() {
  const btn = document.getElementById('rebootAllBtn');
  const status = document.getElementById('shotStatus');
  if (!players.length) { status.textContent = 'Nog geen players, scan eerst het netwerk.'; return; }
  const creds = shotCreds();
  if (!creds.password) { status.textContent = 'Vul eerst het wachtwoord in.'; return; }
  if (!confirm('ALLE ' + players.length + ' gevonden players herstarten? De schermen zijn ~1-2 min zwart tijdens de reboot.')) return;
  btn.disabled = true;
  const queue = players.slice();
  let done = 0, okCount = 0, fails = [];
  status.textContent = 'Herstarten: 0 van ' + queue.length;
  const worker = async () => {
    while (queue.length) {
      const p = queue.shift();
      try {
        const data = await api('/reboot', {ip: p.ip, username: creds.username, password: creds.password});
        if (data.success) okCount++; else fails.push(p.ip);
      } catch (e) { fails.push(p.ip); }
      done++;
      status.textContent = 'Herstarten: ' + done + ' van ' + players.length;
    }
  };
  await Promise.all([worker(), worker(), worker()]);
  status.textContent = okCount + ' van ' + done + ' herstart' + (fails.length ? ' — mislukt: ' + fails.join(', ') : '');
  btn.disabled = false;
}

function renderShotCell(p) {
  const wrap = document.createElement('div');
  const s = shots[p.ip];
  if (s && s.loading) {
    wrap.innerHTML = '<span class="shot-msg">Ophalen...</span>';
  } else if (s && s.image) {
    const img = document.createElement('img');
    img.className = 'thumb';
    img.src = 'data:image/jpeg;base64,' + s.image;
    img.title = 'Klik om te vergroten';
    img.addEventListener('click', () => openLightbox(p));
    wrap.appendChild(img);
    const t = document.createElement('div');
    t.className = 'shot-msg';
    t.textContent = s.time;
    wrap.appendChild(t);
  } else if (s && s.error) {
    const m = document.createElement('div');
    m.className = 'shot-msg err';
    m.textContent = s.error;
    wrap.appendChild(m);
  }
  if (!s || !s.loading) {
    const btn = document.createElement('button');
    btn.className = 'btn btn-sm';
    btn.style.marginTop = '4px';
    btn.textContent = s && s.image ? 'Vernieuwen' : 'Screenshot';
    btn.addEventListener('click', () => takeShot(p));
    wrap.appendChild(btn);
  }
  return wrap;
}

// Snapshot shows the panel as mounted; rotate so the content reads upright.
const ROTATE_DEG = {rotateRight: 90, rotateLeft: 270, rotate180: 180};

function uprightImage(b64, orientation) {
  const deg = ROTATE_DEG[orientation];
  if (!deg) return Promise.resolve(b64);
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas');
      const swap = deg !== 180;
      c.width = swap ? img.height : img.width;
      c.height = swap ? img.width : img.height;
      const ctx = c.getContext('2d');
      ctx.translate(c.width / 2, c.height / 2);
      ctx.rotate(deg * Math.PI / 180);
      ctx.drawImage(img, -img.width / 2, -img.height / 2);
      resolve(c.toDataURL('image/jpeg', 0.9).split(',')[1]);
    };
    img.onerror = () => resolve(b64);
    img.src = 'data:image/jpeg;base64,' + b64;
  });
}

async function takeShot(p) {
  const creds = shotCreds();
  if (!creds.password) {
    shots[p.ip] = {error: 'Vul eerst het wachtwoord in boven de tabel'};
    renderPlayers();
    return false;
  }
  shots[p.ip] = {loading: true};
  renderPlayers();
  let ok = false;
  try {
    const data = await api('/screenshot', {ip: p.ip, ...creds});
    if (data.success) {
      shots[p.ip] = {image: await uprightImage(data.image, data.orientation), time: new Date().toLocaleTimeString('nl-NL')};
      ok = true;
    } else {
      shots[p.ip] = {error: data.error || 'Screenshot mislukt'};
    }
  } catch (e) {
    shots[p.ip] = {error: e.message};
  }
  renderPlayers();
  return ok;
}

async function screenshotAll() {
  const btn = document.getElementById('shotAllBtn');
  const status = document.getElementById('shotStatus');
  if (!players.length) { status.textContent = 'Nog geen players, scan eerst het netwerk.'; return; }
  if (!shotCreds().password) { status.textContent = 'Vul eerst het wachtwoord in.'; return; }
  btn.disabled = true;
  const queue = players.slice();
  let done = 0, okCount = 0;
  status.textContent = 'Bezig: 0 van ' + queue.length;
  const worker = async () => {
    while (queue.length) {
      const p = queue.shift();
      if (await takeShot(p)) okCount++;
      done++;
      status.textContent = 'Bezig: ' + done + ' van ' + players.length;
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  status.textContent = okCount + ' van ' + done + ' screenshots opgehaald' + (okCount < done ? ' (zie meldingen in de tabel)' : '');
  btn.disabled = false;
}

async function upgradeAll() {
  const btn = document.getElementById('upgradeAllBtn');
  const status = document.getElementById('upgradeAllStatus');
  if (!players.length) { status.textContent = 'Nog geen players, scan eerst het netwerk.'; return; }
  const creds = shotCreds();
  if (!creds.password) { status.textContent = 'Vul eerst het wachtwoord in.'; return; }
  if (!confirm('De geharde bridge (watchdog + logs) op alle ' + players.length + ' gevonden players bijwerken? Elke player behoudt zijn eigen screen-URL.')) return;
  btn.disabled = true;
  const queue = players.slice();
  let done = 0, okCount = 0, fails = [];
  status.textContent = 'Bezig: 0 van ' + queue.length;
  const worker = async () => {
    while (queue.length) {
      const p = queue.shift();
      try {
        const data = await api('/upgrade', {ip: p.ip, username: creds.username, password: creds.password});
        if (data.success) okCount++; else fails.push(p.ip + ': ' + (data.error||'mislukt'));
      } catch (e) { fails.push(p.ip + ': ' + e.message); }
      done++;
      status.textContent = 'Bezig: ' + done + ' van ' + players.length;
    }
  };
  await Promise.all([worker(), worker(), worker()]);
  status.textContent = okCount + ' van ' + done + ' bijgewerkt' + (fails.length ? ' — mislukt: ' + fails.join('; ') : '');
  btn.disabled = false;
}

function openLightbox(p) {
  const s = shots[p.ip];
  if (!s || !s.image) return;
  document.getElementById('lightboxImg').src = 'data:image/jpeg;base64,' + s.image;
  document.getElementById('lightboxCap').textContent = (p.model || '') + ' ' + (p.serial || '') + ' (' + p.ip + ') om ' + s.time + '. Klik om te sluiten.';
  document.getElementById('lightbox').classList.add('active');
}

function closeLightbox() {
  document.getElementById('lightbox').classList.remove('active');
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeLightbox(); });

function openModal(ip, model, serial) {
  currentIp = ip;
  const creds = shotCreds();
  if (creds.username) document.getElementById('modalUser').value = creds.username;
  if (creds.password && !document.getElementById('modalPass').value) document.getElementById('modalPass').value = creds.password;
  document.getElementById('modalPlayer').value = model + ' - ' + serial + ' (' + ip + ')';
  document.getElementById('modalTitle').textContent = model + ' ' + serial + ' configureren';
  document.getElementById('authResult').innerHTML = '';
  document.getElementById('modalStep1').style.display = 'block';
  document.getElementById('modalStep2').style.display = 'none';
  document.getElementById('provisionBtn').disabled = true;
  document.getElementById('pushOnlyBtn').disabled = true;
  document.getElementById('diagBtn').disabled = true;
  document.getElementById('fwBtn').disabled = true;
  document.getElementById('shotBtn').disabled = true;
  document.getElementById('rebootBtn').disabled = true;
  document.getElementById('resBtn').disabled = true;
  document.getElementById('resAutoBtn').disabled = true;
  document.getElementById('outW').value = '';
  document.getElementById('outH').value = '';
  document.getElementById('outR').value = '60';
  document.getElementById('diagResult').innerHTML = '';
  document.getElementById('provisionModal').classList.add('active');
}

function modalCreds() {
  return {
    ip: currentIp,
    username: document.getElementById('modalUser').value,
    password: document.getElementById('modalPass').value,
  };
}

async function fetchDiagnostics() {
  const btn = document.getElementById('diagBtn');
  const out = document.getElementById('diagResult');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Ophalen...';
  out.innerHTML = '';
  try {
    const data = await api('/diagnostics', modalCreds());
    if (data.success) {
      const d = data.diagnostics;
      const upH = d.uptime ? (parseFloat(d.uptime) / 3600).toFixed(1) + ' uur' : '?';
      let html = '<div style="margin-top:12px;padding:12px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;font-size:13px;">' +
        '<strong>Diagnose</strong><br>' +
        'Uptime: ' + esc(upH) + ' | Temp: ' + esc(d.temp||'?') + '&deg;C | Boot: ' + esc(d.bootReason||'?') +
        ' | Safe mode: ' + esc(d.safemode||'?') + '<br>';
      if (d.fileErrors && d.fileErrors.length) {
        html += '<strong style="color:#dc2626;">Content-/verbindingsfouten (' + d.fileErrors.length + '):</strong><ul style="margin:6px 0 0 18px;">';
        d.fileErrors.forEach(e => {
          html += '<li>' + esc(e.time) + ' code ' + esc(e.code) + ' &mdash; ' + esc(e.source) +
                  (e.detail ? '<br><span style="color:#888;">' + esc(e.detail) + '</span>' : '') + '</li>';
        });
        html += '</ul>';
      } else {
        html += '<span style="color:#16a34a;">Geen content-/verbindingsfouten gemeld.</span>';
      }
      html += '</div>';
      out.innerHTML = html;
    } else {
      out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(data.error) + '</div>';
    }
  } catch (e) {
    out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(e.message) + '</div>';
  }
  btn.disabled = false; btn.textContent = 'Diagnose / logs';
}

async function checkModalFirmware() {
  const result = document.getElementById('authResult');
  const line = document.createElement('div');
  line.style.cssText = 'margin-top:8px;font-size:13px;color:#555;';
  line.innerHTML = '<span class="spinner"></span>Firmware controleren...';
  result.appendChild(line);
  try {
    const data = await api('/firmware-check', modalCreds());
    if (data.success) {
      fwStatus[currentIp] = {current: data.current, latest: data.latest, status: data.status};
      let badge;
      if (data.status === 'up_to_date') badge = '<span class="badge badge-ok">actueel</span>';
      else if (data.status === 'update_available') badge = '<span class="badge badge-warn">nieuwer beschikbaar: ' + esc(data.latest) + '</span>';
      else badge = '<span class="badge badge-src">onbekend</span>';
      line.innerHTML = 'Firmware: <code>' + esc(data.current || '?') + '</code> ' + badge;
    } else {
      line.innerHTML = 'Firmware-check: <span style="color:#dc2626;">' + esc(data.error) + '</span>';
    }
  } catch (e) {
    line.innerHTML = 'Firmware-check: <span style="color:#dc2626;">' + esc(e.message) + '</span>';
  }
}

async function modalReboot() {
  if (!confirm('Deze player herstarten? Het scherm is ~1-2 min zwart.')) return;
  const btn = document.getElementById('rebootBtn');
  const out = document.getElementById('diagResult');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Herstarten...';
  try {
    const data = await api('/reboot', modalCreds());
    out.innerHTML = data.success
      ? '<div style="margin-top:12px;padding:12px;background:#fffbeb;border-radius:6px;border:1px solid #fde68a;font-size:13px;">Herstart gestart. De player is over 1-2 minuten weer online.</div>'
      : '<div style="margin-top:12px;color:#dc2626;">' + esc(data.error) + '</div>';
  } catch (e) {
    out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(e.message) + '</div>';
  }
  btn.disabled = false; btn.textContent = 'Herstart';
}

async function modalScreenshot() {
  const btn = document.getElementById('shotBtn');
  const out = document.getElementById('diagResult');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Ophalen...';
  out.innerHTML = '';
  try {
    const data = await api('/screenshot', modalCreds());
    if (data.success) {
      out.innerHTML = '<p style="font-size:13px;color:#888;margin-top:12px;">Live screenshot:</p>';
      const img = document.createElement('img');
      img.className = 'screenshot';
      img.src = 'data:image/jpeg;base64,' + data.image;
      if (data.orientation === 'rotateRight') img.style.transform = 'rotate(90deg)';
      else if (data.orientation === 'rotateLeft') img.style.transform = 'rotate(-90deg)';
      else if (data.orientation === 'rotate180') img.style.transform = 'rotate(180deg)';
      out.appendChild(img);
    } else {
      out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(data.error) + '</div>';
    }
  } catch (e) {
    out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(e.message) + '</div>';
  }
  btn.disabled = false; btn.textContent = 'Screenshot';
}

async function applyDisplayMode(auto) {
  const out = document.getElementById('diagResult');
  const w = document.getElementById('outW').value.trim();
  const h = document.getElementById('outH').value.trim();
  const r = document.getElementById('outR').value.trim() || '60';
  if (!auto && (!w || !h)) { alert('Vul breedte en hoogte in pixels in'); return; }
  const what = auto ? 'de automatische (preferred) mode' : (w + 'x' + h + '@' + r);
  if (!confirm('Uitvoerresolutie instellen op ' + what + '? De player HERSTART om dit toe te passen.')) return;
  const btn = document.getElementById(auto ? 'resAutoBtn' : 'resBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Toepassen...';
  try {
    const data = await api('/display-mode', Object.assign(modalCreds(),
      auto ? {auto: true} : {width: w, height: h, refresh: r}));
    if (data.success) {
      out.innerHTML = '<div style="margin-top:12px;padding:12px;background:#f0fdf4;border-radius:6px;border:1px solid #bbf7d0;font-size:13px;">' +
        '<strong style="color:#16a34a;">Resolutie ingesteld: ' + esc(data.mode) + '</strong><br>' +
        'De player herstart nu. Na de herstart kun je met "Test verbinding" de nieuwe mode controleren.</div>';
    } else {
      out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(data.error) + '</div>';
    }
  } catch (e) {
    out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(e.message) + '</div>';
  }
  btn.disabled = false; btn.textContent = auto ? 'Auto' : 'Resolutie toepassen';
}

async function startFirmware() {
  if (!confirm('Firmware bijwerken vanaf de officiele SpinetiX-server? De player installeert op de achtergrond en past het toe bij de volgende herstart.')) return;
  const btn = document.getElementById('fwBtn');
  const out = document.getElementById('diagResult');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Starten...';
  try {
    const data = await api('/firmware', modalCreds());
    if (data.success) {
      out.innerHTML = '<div style="margin-top:12px;padding:12px;background:#fffbeb;border-radius:6px;border:1px solid #fde68a;font-size:13px;">' +
        '<strong style="color:#d97706;">Firmware-update gestart</strong><br>' +
        'Model: ' + esc(data.model||'?') + '<br>Bron: ' + esc(data.repo_uri||'?') + ' (' + esc(data.repo_id||'?') + ')<br>' +
        'De player installeert op de achtergrond en herstart zelf.</div>';
    } else {
      out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(data.error) +
        (data.repo_uri ? '<br><span style="color:#888;">Bron geprobeerd: ' + esc(data.repo_uri) + '</span>' : '') + '</div>';
    }
  } catch (e) {
    out.innerHTML = '<div style="margin-top:12px;color:#dc2626;">' + esc(e.message) + '</div>';
  }
  btn.disabled = false; btn.textContent = 'Firmware bijwerken';
}

function displayOptions() {
  return {
    orientation: document.getElementById('modalOrientation').value,
    width: document.getElementById('modalWidth').value.trim(),
    height: document.getElementById('modalHeight').value.trim(),
  };
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
      const resLine = esc(info.resolution||'?') +
        (info.refresh ? ' @' + esc(info.refresh) + 'Hz' : '') +
        (info.colorspace ? ' ' + esc(info.colorspace) : '') +
        (info.outputType ? ' (' + esc(info.outputType) + ')' : '');
      d.innerHTML = '<strong style="color:#16a34a;">Verbinding OK</strong><br>' +
        '<span style="font-size:13px;color:#555;">' +
        'Firmware: ' + esc(info.firmware||'?') +
        ' | Temp: ' + esc(info.temp||'?') + '&deg;C' +
        ' | Stand: ' + esc(info.orientation||'?') +
        ' | Licentie: ' + (hasKiosk ? '<span class="badge badge-kiosk">KIOSK</span>' : '<span class="badge badge-no">Geen KIOSK</span>') +
        '<br>Uitvoerresolutie: <strong>' + resLine + '</strong>' +
        ' | Video-mode: ' + esc(info.videoMode||'?') +
        '</span>';
      // Pre-fill the output-resolution inputs with the player's current values
      const rm = (info.resolution||'').match(/^(\\d+)x(\\d+)$/);
      if (rm) { document.getElementById('outW').value = rm[1]; document.getElementById('outH').value = rm[2]; }
      if (info.refresh) document.getElementById('outR').value = info.refresh;
      result.innerHTML = '';
      result.appendChild(d);
      document.getElementById('provisionBtn').disabled = false;
      document.getElementById('pushOnlyBtn').disabled = false;
      document.getElementById('diagBtn').disabled = false;
      document.getElementById('fwBtn').disabled = false;
      document.getElementById('shotBtn').disabled = false;
      document.getElementById('rebootBtn').disabled = false;
      document.getElementById('resBtn').disabled = false;
      document.getElementById('resAutoBtn').disabled = false;
      checkModalFirmware();
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
      ...displayOptions(),
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
      ...displayOptions(),
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
</html>'''.replace('__ORIENTATION_OPTIONS__', ''.join(
    f'<option value="{key}">{label}</option>' for key, (label, _) in ORIENTATIONS.items()
)).encode('utf-8')


def _display_options(body):
    """Validate orientation + optional custom size from a request body."""
    orientation = body.get('orientation') or DEFAULT_ORIENTATION
    if orientation not in ORIENTATIONS:
        return None, 'Ongeldige stand van het scherm'
    size, err = _content_size(orientation, body.get('width'), body.get('height'))
    if err:
        return None, err
    return {'orientation': orientation, 'size': size}, None


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
            display, err = _display_options(body)
            if err:
                self._json_error(err, 400); return
            self._json(provision_player(
                body['ip'], body['username'], body['password'], body['screen_url'], **display
            ))

        elif self.path == '/api/push':
            err = _require_fields(body, 'ip', 'username', 'password', 'screen_url')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            if not _validate_screen_url(body['screen_url']):
                self._json_error('Ongeldige screen URL (moet https:// zijn)', 400); return
            display, err = _display_options(body)
            if err:
                self._json_error(err, 400); return
            self._json(push_content_only(
                body['ip'], body['username'], body['password'], body['screen_url'], **display
            ))

        elif self.path == '/api/screenshot':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(take_screenshot(body['ip'], body['username'], body['password']))

        elif self.path == '/api/upgrade':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(upgrade_bridge(body['ip'], body['username'], body['password']))

        elif self.path == '/api/diagnostics':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(fetch_diagnostics(body['ip'], body['username'], body['password']))

        elif self.path == '/api/firmware':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(update_firmware(body['ip'], body['username'], body['password'],
                                       repo_uri=str(body.get('repo_uri', '')).strip(),
                                       repo_id=str(body.get('repo_id', '')).strip()))

        elif self.path == '/api/reboot':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(reboot_player(body['ip'], body['username'], body['password']))

        elif self.path == '/api/firmware-check':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(check_firmware(body['ip'], body['username'], body['password']))

        elif self.path == '/api/display-mode':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(set_display_mode(
                body['ip'], body['username'], body['password'],
                width=body.get('width', 0), height=body.get('height', 0),
                refresh=body.get('refresh', 60), auto=bool(body.get('auto', False))))

        elif self.path == '/api/firmware-status':
            err = _require_fields(body, 'ip', 'username', 'password')
            if err:
                self._json_error(err, 400); return
            if not _validate_ip(body['ip']):
                self._json_error('Ongeldig IP-adres', 400); return
            self._json(firmware_status(body['ip'], body['username'], body['password'],
                                       handle=body.get('handle')))

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
