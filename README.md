# SpinetiX Provisioner

Provisioning tool voor SpinetiX HMP players. Scant het lokale netwerk, configureert players en pusht DST Connect content met ingebouwde RDM-polling.

## Vereisten

- Python 3.7+
- macOS (voor mDNS discovery via `dns-sd`)
- Geen externe dependencies (alleen Python stdlib)

## Gebruik

```bash
python3 server.py
```

Opent automatisch `http://localhost:8090` in de browser.

## Flow

### Eerste keer per player (Provision + Push)
1. **Scan netwerk** - vindt SpinetiX players via mDNS
2. **Configureren** - klik op een player, voer credentials + screen URL in
3. **Test verbinding** - controleert auth, toont firmware/licentie/temperatuur
4. **Provision + Push** - eenmalige setup (~90 seconden):
   - Schakelt ARYA cloud uit (`<disable-cloud/>`)
   - Herstart player
   - Pusht bridge SVG met content iframe + RDM polling script
   - Toont claim code (authHash) voor koppeling in DST Connect CMS

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
