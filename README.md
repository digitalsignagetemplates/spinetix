# SpinetiX Provisioner

Provisioning tool voor SpinetiX HMP players. Scant het lokale netwerk, configureert players en pusht DST Connect content met ingebouwde RDM-polling.

## Vereisten

- Python 3.7+
- macOS of Windows. mDNS discovery via `dns-sd` werkt op macOS en op Windows met Bonjour; zonder `dns-sd` valt de tool terug op de ARP-tabel en vul je je eigen subnet in bij "Extra subnets"
- Geen externe dependencies (alleen Python stdlib)

## Gebruik

```bash
python3 server.py
```

Opent automatisch `http://localhost:8090` in de browser.

## Flow

### Eerste keer per player (Provision + Push)
1. **Scan netwerk** - vindt SpinetiX players via mDNS (eigen VLAN) en optioneel via subnet-scan (andere VLAN's)
2. **Configureren** - klik op een player, voer credentials + screen URL in
3. **Test verbinding** - controleert auth, toont firmware/licentie/temperatuur
4. **Provision + Push** - eenmalige setup (1 tot 5 minuten, afhankelijk van de herstart):
   - Schakelt ARYA cloud uit (`<disable-cloud/>`)
   - Herstart player
   - Pusht bridge SVG met content iframe + RDM polling script
   - Toont claim code (authHash) voor koppeling in DST Connect CMS

### Players in andere VLAN's
mDNS (Bonjour) en ARP werken alleen binnen het eigen VLAN; routers sturen die multicast niet door. Voor players in andere VLAN's:

- **Extra subnets**: vul IP-ranges in, bijvoorbeeld `10.20.0.0/24, 10.30.0.0/24` of `192.168.5.10-50` (max 4096 adressen, alleen privé-ranges). De tool zoekt per adres naar poort 443 en herkent een SpinetiX aan hostname (`spx-hmp-...`), Server-header, auth-realm of loginpagina. Er worden hierbij geen credentials naar onbekende hosts gestuurd.
- **Player toevoegen via IP-adres**: voor als je het adres al weet. Een host die niet als SpinetiX herkend wordt, komt in de lijst met label "Onbekend"; controleer dan met "Test verbinding".

De gebruiker moet vanaf zijn VLAN via routing/firewall bij poort 443 en 9802 van de players kunnen.

### Timeout na herstart
Na de herstart probeert de tool tot 5 minuten lang de player te bereiken en toont de laatste fout (timeout, verbinding geweigerd, 401). Komt de player niet terug, dan is de cloud al uitgeschakeld: gebruik **Alleen content pushen** zodra de player bereikbaar is. Controleer bij een timeout of de player na de herstart via DHCP een ander IP-adres heeft gekregen.

### Content push mislukt (poort 9802)
Voor de push controleert de tool eerst poort 9802 (tot 90s na de herstart) en probeert de upload 3 keer:
- **timeout**: pakketten worden weggegooid, meestal een firewall tussen VLAN's. Poort 443 werkt dan wel. Sta TCP 9802 toe van de beheer-pc naar de player.
- **geweigerd**: de player draait, maar de publish-dienst niet. Controleer of de cloud uitgeschakeld is.

Testen vanaf Windows: `Test-NetConnection <ip> -Port 9802` (PowerShell).

### Herkenning bij subnet-scan / handmatig
Zonder credentials herkent de tool een SpinetiX aan: reverse DNS (`spx-hmp-...`), het TLS-certificaat, de Server-header, de auth-realm of de loginpagina.

### URL wijzigen (Alleen content pushen)
Voor al-geprovisioned players: direct een nieuwe screen URL pushen zonder reboot.

## Bridge SVG

De tool pusht een SVG naar de player die twee dingen doet:

1. **Content weergave** - `<iframe>` die de DST Connect screen URL laadt
2. **RDM Agent** - JavaScript dat elke 30s pollt naar `cms.dst-connect.io/device/config/{authHash}` voor commands en elke 60s een status heartbeat stuurt

Dit vervangt de native applet (Android/webOS/Windows) en biedt dezelfde functionaliteit:
- Screen URL kan remote gewijzigd worden via het CMS
- Commands (reboot, screenshot) worden ontvangen via de config poll
- Status heartbeat houdt de player "online" in het CMS

## AuthHash / Claim Code

Elke player krijgt een deterministische claim code op basis van het MAC-adres:

```
MAC: 00:1D:50:22:27:82 -> authHash: spx_001d50222782
```

Deze code wordt na provisioning getoond en moet ingevoerd worden in het DST Connect CMS om de player aan een scherm te koppelen.

## Technische details

### SpinetiX API endpoints (lokaal netwerk)

| Endpoint | Poort | Methode | Doel |
|----------|-------|---------|------|
| `/rpc` | 443 (HTTPS) | POST | JSON-RPC: get_info, get_config, set_config, restart |
| `/status/info` | 443 (HTTPS) | GET | XML status (firmware, licentie, temperatuur) |
| `/status/snapshot` | 443 (HTTPS) | GET | JPEG screenshot |
| `/index.svg` | 9802 (HTTPS) | PUT | Content publiceren (Elementi publish-poort) |

### Vereiste player configuratie
- **KIOSK Feature Set** (of hoger) - nodig voor HTML5/iframe rendering
- Credentials (username + wachtwoord)
- Netwerktoegang tot de player

### Security
- Server bindt op `127.0.0.1` (alleen lokaal bereikbaar)
- CSRF bescherming via Origin header check
- IP-validatie (alleen private ranges)
- Screen URL validatie (alleen HTTPS)
- SVG content wordt XML-escaped tegen injection
- Request body limiet (1MB)
- Generieke foutmeldingen (geen stack traces naar client)
- SSL verificatie uitgeschakeld alleen voor player-communicatie (self-signed certs)

## Toekomstige integratie

### Platform endpoints (nog te bouwen)
De bridge SVG pollt naar deze endpoints die in het DST Connect platform gebouwd moeten worden:

- `GET /device/config/{authHash}` - config poll, retourneert screenUrl + pending commands
- `POST /device/status/{authHash}` - status heartbeat met telemetrie
- `POST /device/command/{id}/ack` - command acknowledgement

Dit volgt hetzelfde patroon als de bestaande Android/webOS/Windows applet communicatie in het platform (`RdmController`).
