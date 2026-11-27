#!/usr/bin/env bash
# =============================================================================
# AegisProbe (aegisprobe.sh)
# -----------------------------------------------------------------------------
# Bouwt (1x) en draait één Docker-container die zoveel mogelijk gratis
# securitytools uitvoert tegen een loginpagina van een webwinkel, en sluit af
# met één geconsolideerd, wachtwoord-beveiligd PDF-rapport dat op elke pagina
# het AegisProbe-logo draagt.
#
# LOGO: plaats het bestand "aegisprobe-logo.png" in dezelfde map als dit
# script (of geef een ander pad op met --logo PATH of de env var LOGO_PATH).
# Zonder dat bestand werkt alles nog steeds, maar toont het rapport enkel de
# tekstuele "AegisProbe"-naam in plaats van het logo.
#
# Tools (basis):
#   OWASP ZAP, Nuclei, Nikto, Wapiti, Nmap, testssl.sh, sslyze, retire.js,
#   MDN HTTP Observatory + eigen controles (headers, cookies, formulier,
#   open redirect, methodes, blootgestelde paden, enumeratie, rate limiting,
#   sessie-regeneratie).
#
# Tools (uitgebreid, los uit te zetten via --skip):
#   sqlmap, dalfox, feroxbuster, arjun, cors, clickjack, jwt, cspeval,
#   secrets (gitleaks), graphql, wpscan.
#
# Voorbereiding vóór elke scan (gecachet op de hostmachine):
#   nuclei-templates, feroxbuster-wordlist, nikto-signatuurdatabase,
#   sqlmap, wpscan-database.
#
# Eindresultaat: AegisProbe-Report-Protected.pdf — één leesbaar, niet-
# technisch geschreven rapport (met technische bijlage) voor management EN
# IT-staff, met het AegisProbe-logo op elke pagina, beveiligd met een
# wachtwoord (AES-256 via qpdf).
#
# VEILIGHEID / PCI: betaal- en checkout-paden worden standaard UITGESLOTEN
# van actieve/fuzzing-tools (sqlmap, dalfox, feroxbuster, arjun). Pas
# PAYMENT_PATH_EXCLUDE aan indien nodig. Test betaalproviders (Mollie,
# Stripe, PayPal, ...) nooit zonder aparte, schriftelijke toestemming van
# die provider: hun voorwaarden verbieden dit meestal expliciet.
#
# GEBRUIK ALLEEN MET SCHRIFTELIJKE TOESTEMMING VAN DE EIGENAAR.
# Zie README.md voor uitleg, vereisten, risico's en juridische aandachtspunten.
#
# Voorbeelden:
#   ./aegisprobe.sh                                     # veilige modus (grotendeels passief)
#   ./aegisprobe.sh --active                            # + ZAP full, Wapiti, Nikto, sqlmap, dalfox, feroxbuster, arjun
#   ./aegisprobe.sh -t https://shop.example/nl/login --skip nmap,wapiti,sqlmap
#   TEST_EMAIL=test@example.com TEST_PASSWORD='...' ./aegisprobe.sh --ratelimit
#   REPORT_PASSWORD='Mijn-Sterk-Wachtwoord!' ./aegisprobe.sh --active
#   ./aegisprobe.sh --uninstall                         # verwijdert de image
# =============================================================================
set -Eeuo pipefail

IMAGE="aegisprobe:latest"
TARGET="https://www.example.com/nl/login"
ACTIVE=0
ZAP_MIN=3
RATELIMIT=0
SKIP=""
REBUILD=0
YES=0
MODE="run"
RESULTS_ROOT="${PWD}/aegisprobe-results"
CACHE_ROOT="${CACHE_ROOT:-${PWD}/aegisprobe-cache}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LOGO_PATH="${LOGO_PATH:-$SCRIPT_DIR/aegisprobe-logo.png}"

# Optioneel: testaccount (GEEN echt klantaccount).
TEST_EMAIL="${TEST_EMAIL:-}"
TEST_PASSWORD="${TEST_PASSWORD:-}"

# JS-bestanden die het ZAP-rapport als kwetsbaar markeerde.
EXTRA_JS="${EXTRA_JS:-https://www.example.com/js/swiper.js https://www.example.com/assets/vendor/jquery.min.js https://www.example.com/js/scripts/jquery-ui.min.js https://www.example.com/assets/js/app-settings.js}"

# Paden die NOOIT door fuzzing/injectie-tools benaderd mogen worden.
PAYMENT_PATH_EXCLUDE="${PAYMENT_PATH_EXCLUDE:-checkout,pay,payment,mollie,stripe,paypal,bancontact,ideal,order/confirm,cart}"

# Wordlist voor feroxbuster (klein en snel; override met eigen pad/URL).
FEROX_WORDLIST_URL="${FEROX_WORDLIST_URL:-https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt}"

# Rapport
REPORT_LANG="${REPORT_LANG:-nl}"
REPORT_PASSWORD="${REPORT_PASSWORD:-}"

print_banner() {
  local R='\033[1;31m' W='\033[1;37m' G='\033[0;37m' N='\033[0m'
  if command -v chafa >/dev/null 2>&1 && [ -f "$LOGO_PATH" ]; then
    chafa --size=46x23 "$LOGO_PATH" 2>/dev/null || true
  fi
  printf "\n${W}  ══════════════════════════════════════════════════════${N}\n"
  printf "${W}   █▀▀█ █▀▀ █▀▀▀ ▀█▀ █▀▀▀ ${N}  ${R}█▀▀█ █▀▀█ █▀▀█ █▀▀▄ █▀▀${N}\n"
  printf "${W}   █▄▄█ █▀▀ █ ▀█  █  ▀▀▀█ ${N}  ${R}█▄▄▀ █▄▄▀ █  █ █▀▀▄ █▀▀${N}\n"
  printf "${W}   ▀  ▀ ▀▀▀ ▀▀▀▀ ▀▀▀ ▀▀▀▀ ${N}  ${R}▀    ▀ ▀▀ ▀▀▀▀ ▀▀▀  ▀▀▀${N}\n"
  printf "${G}     Red Team light weight Web Security Toolkit${N}\n"
  printf "${G}     Gebruik enkel met schriftelijke toestemming${N}\n"
  printf "${W}  ══════════════════════════════════════════════════════${N}\n\n"
}

usage() {
  cat <<EOF
AegisProbe — Red Team Web Security Toolkit

Gebruik: $0 [opties]
  -t, --target URL       Loginpagina (standaard: $TARGET)
      --active           Ook actieve scans: ZAP full scan, Wapiti, Nikto,
                          sqlmap, dalfox, feroxbuster, arjun
      --zap-minutes N    Spider-tijd van ZAP in minuten (standaard: $ZAP_MIN)
      --ratelimit        Stuur 15 foute logins om rate limiting te testen
      --skip a,b,c       Sla stappen over: nmap,testssl,sslyze,observatory,retire,custom,
                          nuclei,zap,nikto,wapiti,sqlmap,dalfox,feroxbuster,arjun,cors,
                          clickjack,jwt,cspeval,secrets,graphql,wpscan
      --logo PATH         Pad naar het AegisProbe-logo (PNG) voor het PDF-rapport
                          (standaard: aegisprobe-logo.png naast dit script)
      --rebuild          Bouw de image opnieuw (nieuwste tools/templates/logo)
      --shell            Open een shell in de container
      --uninstall        Verwijder de image (resultaten/cache blijven staan)
  -y, --yes              Sla de toestemmingsvraag over
  -h, --help             Deze hulp

Omgevingsvariabelen: TEST_EMAIL, TEST_PASSWORD, EXTRA_JS, USER_FIELD, PASS_FIELD,
                      PAYMENT_PATH_EXCLUDE, FEROX_WORDLIST_URL, CACHE_ROOT, LOGO_PATH,
                      REPORT_LANG (nl, standaard), REPORT_PASSWORD (anders
                      automatisch gegenereerd en getoond na de run)

Zie README.md voor volledige uitleg, vereisten, risico's en juridische aandachtspunten.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    --active) ACTIVE=1; shift;;
    --zap-minutes) ZAP_MIN="$2"; shift 2;;
    --ratelimit) RATELIMIT=1; shift;;
    --skip) SKIP="$2"; shift 2;;
    --logo) LOGO_PATH="$2"; shift 2;;
    --rebuild) REBUILD=1; shift;;
    --shell) MODE="shell"; shift;;
    --uninstall) MODE="uninstall"; shift;;
    -y|--yes) YES=1; shift;;
    -h|--help) print_banner; usage; exit 0;;
    *) echo "Onbekende optie: $1"; usage; exit 1;;
  esac
done

print_banner

command -v docker >/dev/null 2>&1 || { echo "Docker is niet geïnstalleerd of niet in PATH."; exit 1; }

if [[ "$MODE" == "uninstall" ]]; then
  docker rmi "$IMAGE" 2>/dev/null && echo "Image $IMAGE verwijderd." || echo "Image niet gevonden."
  echo "Resultaten staan nog in: $RESULTS_ROOT (verwijder handmatig indien gewenst)."
  echo "Cache (nuclei-templates/wordlists) staat nog in: $CACHE_ROOT (mag blijven staan, of verwijder handmatig)."
  exit 0
fi

mkdir -p "$CACHE_ROOT/nuclei-templates" "$CACHE_ROOT/wordlists" "$CACHE_ROOT/wpscan"

if [ ! -f "$LOGO_PATH" ]; then
  echo "Let op: geen logo gevonden op $LOGO_PATH."
  echo "Plaats 'aegisprobe-logo.png' naast dit script (of gebruik --logo PATH) voor het"
  echo "volledige, gebrande rapport. Het rapport wordt nu aangemaakt met enkel de tekst"
  echo "'AegisProbe' in plaats van het logo."
fi

# ----------------------------- image bouwen ----------------------------------
build_image() {
  local B; B="$(mktemp -d)"
  trap 'rm -rf "$B"' RETURN

  if [ -f "$LOGO_PATH" ]; then
    cp "$LOGO_PATH" "$B/aegisprobe-logo.png"
  else
    # Minimale, onzichtbare 1x1 transparante PNG als fallback zodat de
    # Docker-build nooit faalt wanneer het echte logo ontbreekt.
    echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=" \
      | base64 -d > "$B/aegisprobe-logo.png"
  fi

  cat > "$B/Dockerfile" <<'DOCKERFILE'
FROM ghcr.io/zaproxy/zaproxy:stable
USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap curl wget git jq unzip ca-certificates openssl dnsutils bsdextrautils \
      procps python3 python3-venv python3-pip python3-pil perl libnet-ssleay-perl gnupg xxd \
      ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev \
      libxslt1-dev zlib1g-dev golang-go \
    && rm -rf /var/lib/apt/lists/*

# Toolchain voor het PDF-rapport (HTML -> PDF, en wachtwoordbeveiliging)
RUN apt-get update && apt-get install -y --no-install-recommends \
      wkhtmltopdf qpdf fontconfig fonts-dejavu-core fonts-dejavu-extra \
      libxrender1 libxext6 libjpeg62-turbo xfonts-75dpi xfonts-base \
    && rm -rf /var/lib/apt/lists/*

# Python-tools in een venv
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir wapiti3 sslyze arjun \
      pyjwt requests \
 && ln -s /opt/venv/bin/wapiti /usr/local/bin/wapiti \
 && ln -s /opt/venv/bin/sslyze /usr/local/bin/sslyze \
 && ln -s /opt/venv/bin/arjun /usr/local/bin/arjun

# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
 && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
 && chmod +x /usr/local/bin/sqlmap

# graphql-cop
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
 && /opt/venv/bin/pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
 && printf '#!/bin/sh\nexec /opt/venv/bin/python3 /opt/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
 && chmod +x /usr/local/bin/graphql-cop

# jwt_tool
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
 && /opt/venv/bin/pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt \
 && printf '#!/bin/sh\nexec /opt/venv/bin/python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
 && chmod +x /usr/local/bin/jwt_tool

# testssl.sh en nikto (git-checkouts; worden ook bij elke run bijgewerkt, zie prepare_tools)
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh \
 && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
 && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto

# WPScan (optioneel; alleen gebruikt als WordPress wordt gedetecteerd)
RUN gem install wpscan --no-document || echo "wpscan installatie mislukt (optioneel, wordt overgeslagen)"

# Node.js + retire.js + MDN HTTP Observatory
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g retire
RUN npm install -g @mdn/mdn-http-observatory || echo "observatory niet geinstalleerd (optioneel)"

# Nuclei (binary). De TEMPLATES zelf worden NIET hier gedownload: dat gebeurt
# bij elke run in prepare_tools(), met retries, naar een gecachete map op de
# hostmachine, zodat een scan nooit meer stil faalt omdat deze build-stap de
# download miste.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=amd64;; arm64) a=arm64;; *) echo "onbekende arch $arch"; exit 1;; esac; \
    url="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | jq -r --arg s "linux_${a}.zip" '.assets[] | select(.name|endswith($s)) | .browser_download_url' | head -n1)"; \
    curl -fsSL "$url" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; chmod +x /usr/local/bin/nuclei; rm -f /tmp/nuclei.zip

# dalfox (laatste release binary)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=linux_amd64;; arm64) a=linux_arm64;; *) echo "onbekende arch $arch"; exit 1;; esac; \
    url="$(curl -fsSL https://api.github.com/repos/hahwul/dalfox/releases/latest \
        | jq -r --arg s "$a.tar.gz" '.assets[] | select(.name|endswith($s)) | .browser_download_url' | head -n1)"; \
    if [ -n "$url" ]; then \
      curl -fsSL "$url" -o /tmp/dalfox.tgz; tar -xzf /tmp/dalfox.tgz -C /usr/local/bin dalfox; \
      chmod +x /usr/local/bin/dalfox; rm -f /tmp/dalfox.tgz; \
    else echo "dalfox-release niet gevonden, probeer go install"; go install github.com/hahwul/dalfox/v2@latest \
      && cp /root/go/bin/dalfox /usr/local/bin/dalfox; fi

# feroxbuster (laatste release binary)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=x86_64-linux;; arm64) a=arm-linux;; *) echo "onbekende arch $arch"; exit 1;; esac; \
    url="$(curl -fsSL https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | jq -r --arg s "$a.zip" '.assets[] | select(.name|test($s)) | .browser_download_url' | head -n1)"; \
    if [ -n "$url" ]; then \
      curl -fsSL "$url" -o /tmp/ferox.zip; unzip -o /tmp/ferox.zip -d /usr/local/bin feroxbuster; \
      chmod +x /usr/local/bin/feroxbuster; rm -f /tmp/ferox.zip; \
    else echo "feroxbuster-release niet gevonden, wordt overgeslagen"; fi

# gitleaks
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=x64;; arm64) a=arm64;; *) echo "onbekende arch $arch"; exit 1;; esac; \
    url="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | jq -r --arg s "linux_${a}.tar.gz" '.assets[] | select(.name|endswith($s)) | .browser_download_url' | head -n1)"; \
    curl -fsSL "$url" -o /tmp/gitleaks.tgz; tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    chmod +x /usr/local/bin/gitleaks; rm -f /tmp/gitleaks.tgz

COPY aegisprobe-logo.png /opt/aegisprobe-logo.png
COPY formscan.py /opt/formscan.py
COPY report_build.py /opt/report_build.py
COPY run-checks.sh /opt/run-checks.sh
RUN chmod +x /opt/run-checks.sh
WORKDIR /results
ENTRYPOINT ["/opt/run-checks.sh"]
DOCKERFILE

  # ---- helper: HTML-formulieren uitlezen ----
  cat > "$B/formscan.py" <<'PYEOF'
import sys, json
from html.parser import HTMLParser
from urllib.parse import urljoin

class P(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.forms = []
        self.cur = None
        self.csrf_meta = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"action": urljoin(self.base, a.get("action") or ""),
                        "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self.cur)
        elif tag == "input" and self.cur is not None:
            self.cur["inputs"].append({"name": a.get("name"),
                                       "type": (a.get("type") or "text").lower(),
                                       "autocomplete": a.get("autocomplete"),
                                       "value": a.get("value")})
        elif tag == "meta" and (a.get("name") or "").lower() == "csrf-token":
            self.csrf_meta = a.get("content")
    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None

p = P(sys.argv[2])
p.feed(open(sys.argv[1], errors="ignore").read())
print(json.dumps({"forms": p.forms, "csrf_meta": p.csrf_meta}, indent=1))
PYEOF

  # ---- rapportgenerator ----
  cat > "$B/report_build.py" <<'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_build.py — bouwt het AegisProbe-rapport (HTML, voor conversie naar
PDF) uit de resultaten van aegisprobe.sh, geschreven voor een gemengd
publiek van management en IT-staff. Genereert ook een apart header.html
zodat het AegisProbe-logo op elke pagina van het PDF-rapport verschijnt.
"""
import argparse, json, os, re, io, base64, collections
from html import escape as esc

LOGO_PATH_CONTAINER = "/opt/aegisprobe-logo.png"

try:
    from PIL import Image
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False


def load_logo_b64(max_height_px):
    if not os.path.isfile(LOGO_PATH_CONTAINER):
        return ""
    try:
        if HAVE_PIL:
            im = Image.open(LOGO_PATH_CONTAINER).convert("RGBA")
            if im.height > max_height_px:
                ratio = max_height_px / im.height
                im = im.resize((max(1, int(im.width * ratio)), max_height_px))
            buf = io.BytesIO()
            im.save(buf, format="PNG")
            data = buf.getvalue()
        else:
            data = open(LOGO_PATH_CONTAINER, "rb").read()
        return base64.b64encode(data).decode("ascii")
    except Exception:
        return ""


def build_header_html(logo_b64):
    img_tag = (f'<img src="data:image/png;base64,{logo_b64}" '
               f'style="height:16mm;vertical-align:middle;margin-right:6mm;">') if logo_b64 else ""
    return f'''<!doctype html><html><head><meta charset="utf-8">
<style>
  body {{ margin:0; padding:0 6mm; font-family:"DejaVu Sans",Arial,sans-serif;
          background:#0b0f14; color:#ffffff; }}
  .bar {{ display:flex; align-items:center; height:20mm; border-bottom:2px solid #dc2626; }}
  .brand {{ font-size:16px; font-weight:bold; white-space:nowrap; }}
  .brand .probe {{ color:#dc2626; }}
  .tagline {{ font-size:9px; color:#9ca3af; margin-left:auto; text-align:right; }}
</style></head>
<body><div class="bar">{img_tag}
  <span class="brand">Aegis<span class="probe">Probe</span></span>
  <span class="tagline">Red Team Beveiligingsrapport — vertrouwelijk</span>
</div></body></html>'''


# ------------------------------------------------------------- kennisbank --
# Elke regel in findings.txt heeft de vorm "[TAG] bericht". De onderstaande
# lijst koppelt vaste tekstdelen (substring, kleine letters) aan een id.
# Volgorde is belangrijk: de EERSTE match wint, dus specifiekere teksten
# staan vóór algemenere teksten die er een deel van zijn.
KB_MATCH = [
    ("post niet naar https", "form_https_bad"),
    ("loginformulier post naar https", "form_https_ok"),
    ("header aanwezig:", "header_present"),
    ("kernheaders aanwezig", "header_present"),
    ("header ontbreekt:", "header_missing"),
    ("ontbrekende headers:", "header_missing"),
    ("csp bevat geen default-src", "csp_weak"),
    ("x-powered-by header lekt", "tech_leak"),
    ("server header bevat versienummer", "server_version_leak"),
    ("x-xss-protection is verouderd", "xss_protection_deprecated"),
    ("referrer-policy no-referrer-when-downgrade", "referrer_leak"),
    ("loginpagina zonder cache-control", "cache_control_login"),
    ("xsrf-token zonder httponly", "cookie_httponly_info"),
    ("zonder httponly", "cookie_httponly"),
    ("zonder secure", "cookie_insecure"),
    ("zonder samesite", "cookie_samesite"),
    ("formulieren op pagina:", "form_info"),
    ("csrf-/hidden-token aanwezig", "csrf_ok"),
    ("geen csrf-token in loginformulier", "csrf_missing"),
    ("autocomplete op wachtwoordveld:", "autocomplete_info"),
    ("http redirect naar https", "https_redirect_ok"),
    ("http->https redirect onduidelijk", "https_redirect_bad"),
    ("trace is toegestaan", "trace_enabled"),
    ("veroorzaakt directe redirect naar extern domein", "open_redirect_direct"),
    ("wordt in de html gereflecteerd", "reflection_info"),
    ("ongeëncodeerd gereflecteerd in target_url", "xss_confirmed"),
    ("niet ongeëncodeerd gereflecteerd", "xss_not_confirmed"),
    ("lekt configuratie", "env_leak"),
    ("geen .env-inhoud", "env_accessible_info"),
    (".git is publiek bereikbaar", "git_leak"),
    ("sitemap.xml", "path_benign_info"),
    ("security.txt", "path_benign_info"),
    ("bereikbaar (http 200,", "hidden_path_exposed"),
    ("-> redirect (", "admin_redirect_info"),
    ("mogelijke gebruikersenumeratie", "user_enum_warn"),
    ("geen zichtbaar verschil tussen bestaand", "user_enum_ok"),
    ("gebruikersenumeratie overgeslagen", "skipped_info"),
    ("sessie-cookie wordt vernieuwd na login", "session_regen_ok"),
    ("sessie-cookie lijkt niet te veranderen na login", "session_fixation"),
    ("open redirect: na login", "open_redirect_login"),
    ("geen redirect naar extern domein na login", "open_redirect_login_ok"),
    ("rate limiting actief", "ratelimit_ok"),
    ("geen http 429 na 15 pogingen", "ratelimit_missing"),
    ("matcht een payment_path_exclude", "payment_scope_info"),
    ("met allow-credentials: true", "cors_critical"),
    ("teruggespiegeld", "cors_high"),
    ("access-control-allow-origin=*", "cors_wildcard_info"),
    ("geen reflectie van een willekeurige origin", "cors_ok"),
    ("framing wordt beperkt", "clickjack_ok"),
    ("geen x-frame-options en geen csp frame-ancestors", "clickjack_missing"),
    ("geen jwt gevonden", "jwt_none_info"),
    ("jwt gevonden, structurele analyse", "jwt_found_info"),
    ("jwt gebruikt alg=none", "jwt_alg_none"),
    ("jwt alg=", "jwt_detail_info"),
    ("jwt heeft geen exp-claim", "jwt_no_exp"),
    ("kon niet gedecodeerd worden", "jwt_decode_fail"),
    ("geen csp-header aanwezig", "cspeval_missing_info"),
    ("csp-evaluator:", "cspeval_info"),
    ("mogelijk graphql-endpoint", "graphql_found_info"),
    ("graphql introspectie", "graphql_introspection"),
    ("geen graphql-endpoint gevonden", "graphql_none_info"),
    ("arjun vond mogelijke parameters", "arjun_found_info"),
    ("sqlmap meldt mogelijke sql-injectie", "sqli_found"),
    ("sqlmap vond geen injectie", "sqli_ok"),
    ("dalfox vond mogelijke xss", "xss_dalfox_found"),
    ("dalfox vond geen xss", "xss_dalfox_ok"),
    ("feroxbuster-wordlist kon niet", "tool_unavailable_info"),
    ("feroxbuster niet beschikbaar", "tool_unavailable_info"),
    ("feroxbuster:", "ferox_found_info"),
    ("gitleaks vond geen secrets", "secrets_ok"),
    ("gitleaks vond", "secrets_found"),
    ("gitleaks niet beschikbaar", "tool_unavailable_info"),
    ("geen wordpress gedetecteerd", "wordpress_none_info"),
    ("wordpress gedetecteerd", "wordpress_info"),
    ("overgeslagen", "skipped_info"),
]

LABELS = {
    "header_present": "Beveiligingsheader correct ingesteld",
    "cookie_httponly_info": "XSRF-cookie zonder HttpOnly (normaal voor dit platform)",
    "form_info": "Formulieren op de pagina geïnventariseerd",
    "form_https_ok": "Loginformulier verstuurt gegevens versleuteld (HTTPS)",
    "csrf_ok": "Beveiliging tegen CSRF aanwezig in het loginformulier",
    "autocomplete_info": "Autocomplete-instelling wachtwoordveld genoteerd",
    "https_redirect_ok": "Onversleutelde verbinding wordt automatisch doorgestuurd naar HTTPS",
    "reflection_info": "Technische observatie rond parameterverwerking",
    "xss_not_confirmed": "Geen directe XSS gevonden via dit pad",
    "env_accessible_info": "Pad bereikbaar, maar geen gevoelige inhoud aangetroffen",
    "path_benign_info": "Onschuldig, bedoeld publiek pad bereikbaar",
    "admin_redirect_info": "Adminpad stuurt door (geen directe toegang)",
    "user_enum_ok": "Geen gebruikersenumeratie via het loginformulier gevonden",
    "session_regen_ok": "Sessie wordt ververst bij het inloggen",
    "open_redirect_login_ok": "Geen doorverwijzing naar externe sites na login",
    "ratelimit_ok": "Limiet op mislukte inlogpogingen actief",
    "payment_scope_info": "Betaalgerelateerd pad correct buiten testbereik gehouden",
    "cors_wildcard_info": "CORS staat open voor iedereen, zonder gevoelige gegevens (doorgaans onschuldig)",
    "cors_ok": "Geen CORS-misconfiguratie gevonden",
    "clickjack_ok": "Bescherming tegen clickjacking aanwezig",
    "jwt_none_info": "Geen inlog-token (JWT) aangetroffen om te analyseren",
    "jwt_found_info": "Inlog-token (JWT) gevonden en geanalyseerd",
    "jwt_detail_info": "Technische details van het inlog-token genoteerd",
    "cspeval_missing_info": "Geen Content-Security-Policy aanwezig om te analyseren",
    "cspeval_info": "Content-Security-Policy geanalyseerd",
    "graphql_found_info": "Mogelijk GraphQL-koppelpunt gevonden",
    "graphql_none_info": "Geen GraphQL-koppelpunt gevonden",
    "arjun_found_info": "Mogelijke extra parameters op de website gevonden",
    "sqli_ok": "Geen SQL-injectie gevonden op het loginformulier",
    "xss_dalfox_ok": "Geen XSS gevonden door de geautomatiseerde XSS-scanner",
    "tool_unavailable_info": "Een hulpmiddel was niet beschikbaar tijdens deze test",
    "secrets_ok": "Geen gelekte wachtwoorden/sleutels gevonden in publieke bestanden",
    "wordpress_info": "WordPress gedetecteerd en apart gecontroleerd",
    "wordpress_none_info": "Geen WordPress gedetecteerd (controle overgeslagen)",
    "skipped_info": "Onderdeel bewust overgeslagen (zie testbereik)",
    "xss_protection_deprecated": "Verouderde header gevonden (geen actie nodig)",
    "options_info": "Toegestane HTTP-methodes genoteerd",
}

DETAIL = {
    "trace_enabled": (
        "De server staat de HTTP-methode TRACE toe",
        "Een aanvaller kan deze methode soms gebruiken om beveiligingscookies "
        "te stelen, zelfs als die cookies normaal beschermd zijn.",
        "Vraag je hosting provider of ontwikkelaar om de TRACE-methode uit te "
        "schakelen op de webserver (bij Apache: 'TraceEnable off'; bij Nginx "
        "staat dit standaard al uit, controleer de configuratie)."
    ),
    "open_redirect_direct": (
        "De website stuurt bezoekers zonder controle door naar een extern adres",
        "Criminelen kunnen een link met jouw domeinnaam versturen die de "
        "bezoeker uiteindelijk naar een nepsite stuurt (bijvoorbeeld voor "
        "phishing). Dit ondermijnt het vertrouwen in je merk.",
        "Laat de ontwikkelaar de 'target_url'-parameter (of gelijkaardige "
        "doorverwijsparameters) controleren tegen een vaste lijst van "
        "toegestane, interne adressen voordat er wordt doorverwezen."
    ),
    "xss_confirmed": (
        "Tekst die een bezoeker intypt, wordt ongefilterd teruggetoond op de pagina",
        "Hiermee kan een aanvaller schadelijke code laten uitvoeren in de "
        "browser van een ander bezoekers, bijvoorbeeld om een sessie over te "
        "nemen of gegevens te stelen. Dit heet cross-site scripting (XSS).",
        "Laat de ontwikkelaar alle gebruikersinvoer die op de pagina getoond "
        "wordt automatisch laten 'escapen' (coderen) door het framework, en "
        "controleer dit specifiek voor de 'target_url'-parameter."
    ),
    "env_leak": (
        "Een configuratiebestand met gevoelige gegevens staat publiek open",
        "Dit bestand kan databasewachtwoorden, API-sleutels en andere "
        "geheimen bevatten. Als het uitlekt, kan een aanvaller volledige "
        "controle over de webshop en de database krijgen.",
        "Zorg dat dit bestand onmiddellijk ontoegankelijk wordt gemaakt via "
        "de webserverconfiguratie, en vervang daarna alle sleutels en "
        "wachtwoorden die erin stonden (ze moeten als gecompromitteerd "
        "worden beschouwd)."
    ),
    "git_leak": (
        "De broncode-geschiedenis van de website (.git) is publiek bereikbaar",
        "Een aanvaller kan hiermee vaak de volledige broncode downloaden, "
        "inclusief eerdere versies die mogelijk wachtwoorden of interne "
        "logica bevatten.",
        "Blokkeer toegang tot de map '.git' in de webserverconfiguratie, of "
        "zorg dat deze map niet binnen de publiek toegankelijke website-map "
        "staat."
    ),
    "laravel_log_leak": (
        "Een technisch logbestand van de website is publiek leesbaar",
        "Logbestanden bevatten vaak interne foutmeldingen, paden en soms "
        "gevoelige gegevens die een aanvaller kunnen helpen bij een aanval.",
        "Maak dit logbestand ontoegankelijk via de webserverconfiguratie en "
        "controleer of logbestanden structureel buiten de publieke map staan."
    ),
    "open_redirect_login": (
        "Na het inloggen kan een bezoeker naar een extern, niet-vertrouwd adres worden gestuurd",
        "Dit maakt phishing-aanvallen geloofwaardiger: een link lijkt van je "
        "eigen webshop te komen, maar eindigt ergens anders.",
        "Laat de doorverwijzing na het inloggen enkel toestaan naar een vaste "
        "lijst van interne pagina's, nooit naar een door de bezoeker "
        "meegegeven extern adres."
    ),
    "jwt_alg_none": (
        "Het inlog-token (JWT) kan worden geaccepteerd zonder digitale handtekening",
        "Dit is een ernstige fout: een aanvaller zou zich mogelijk kunnen "
        "voordoen als een andere gebruiker (inclusief een beheerder) zonder "
        "het wachtwoord te kennen.",
        "Laat de ontwikkelaar het token-algoritme ('alg') hard vastleggen aan "
        "de serverzijde (bijvoorbeeld altijd RS256 of HS256) en elk token met "
        "'alg=none' of een ander onverwacht algoritme meteen weigeren."
    ),
    "cors_critical": (
        "De website accepteert gevoelige verzoeken van eender welke andere website",
        "Een kwaadaardige website die een bezoeker bezoekt zou daardoor "
        "namens die bezoeker gegevens van jouw webshop kunnen opvragen, "
        "inclusief ingelogde sessiegegevens.",
        "Laat de ontwikkelaar de CORS-instellingen beperken tot een vaste, "
        "korte lijst van vertrouwde domeinen, en 'Allow-Credentials' nooit "
        "combineren met een willekeurige/teruggespiegelde oorsprong."
    ),
    "sqli_found": (
        "Het loginformulier blijkt gevoelig voor SQL-injectie",
        "Dit is één van de ernstigste mogelijke fouten: een aanvaller kan "
        "hiermee potentieel alle klantgegevens, bestellingen en wachtwoorden "
        "uit de database lezen, wijzigen of verwijderen.",
        "Behandel dit als topprioriteit. Laat de ontwikkelaar alle "
        "databasequeries herschrijven met 'prepared statements' / "
        "parameterbinding in plaats van tekst samen te voegen, en voer na de "
        "fix een hertest uit."
    ),
    "xss_dalfox_found": (
        "Een geautomatiseerde test bevestigt een cross-site scripting (XSS) kwetsbaarheid",
        "Een aanvaller kan hiermee schadelijke code laten uitvoeren in de "
        "browser van andere bezoekers, bijvoorbeeld om sessies te kapen.",
        "Laat de ontwikkelaar de betrokken invoer filteren/coderen volgens de "
        "OWASP-richtlijnen voor XSS-preventie en test opnieuw na de fix."
    ),
    "secrets_found": (
        "Er zijn wachtwoorden, API-sleutels of andere geheimen gevonden in publiek bereikbare bestanden",
        "Met deze gegevens kan een aanvaller mogelijk inloggen op koppelingen "
        "met betaalproviders, e-maildiensten of andere systemen.",
        "Beschouw elke gevonden sleutel als gecompromitteerd: vervang "
        "('roteer') ze onmiddellijk bij de betreffende dienst, en verwijder "
        "ze uit de publiek bereikbare bestanden. Zet geheimen voortaan enkel "
        "in niet-publieke configuratie, nooit in JavaScript-bestanden die "
        "bezoekers kunnen downloaden."
    ),
    "form_https_bad": (
        "Het loginformulier verstuurt gegevens niet (volledig) versleuteld",
        "Gebruikersnaam en wachtwoord kunnen hierdoor onderschept worden op "
        "het netwerk, bijvoorbeeld op openbare wifi.",
        "Laat de ontwikkelaar het formulier altijd naar een https://-adres "
        "laten versturen, en schakel HTTPS verplicht in voor de volledige "
        "website (HSTS)."
    ),
    "session_fixation": (
        "De sessie van een bezoeker verandert niet bij het inloggen",
        "Een aanvaller zou in bepaalde scenario's een bestaande sessie "
        "kunnen 'opleggen' aan een slachtoffer en zo toegang krijgen nadat "
        "die persoon inlogt.",
        "Laat de ontwikkelaar bij elke succesvolle login een nieuwe "
        "sessie-identificatie aanmaken ('session regeneration'), zoals de "
        "meeste webframeworks standaard ondersteunen."
    ),
    "ratelimit_missing": (
        "Er is geen zichtbare limiet op het aantal mislukte inlogpogingen",
        "Een aanvaller kan hierdoor geautomatiseerd duizenden "
        "wachtwoordcombinaties uitproberen op klantaccounts (brute force).",
        "Laat de ontwikkelaar een limiet instellen op mislukte inlogpogingen "
        "per account en per IP-adres (bijvoorbeeld tijdelijk blokkeren na 5 "
        "pogingen), en overweeg een CAPTCHA bij herhaalde mislukkingen."
    ),
    "graphql_introspection": (
        "Een GraphQL-koppelpunt geeft (gedeeltelijk) zijn interne structuur prijs",
        "Een aanvaller krijgt hiermee als het ware een plattegrond van alle "
        "beschikbare gegevens en functies, wat verdere aanvallen vergemakkelijkt.",
        "Laat de ontwikkelaar 'introspectie' uitschakelen op de "
        "productieomgeving van de GraphQL-API."
    ),
    "cors_high": (
        "De website lijkt verzoeken van een willekeurige andere website te accepteren",
        "Dit kan misbruikt worden om gegevens van je webshop op te vragen "
        "vanaf een kwaadaardige website die een bezoeker toevallig bezoekt.",
        "Laat de ontwikkelaar de CORS-instellingen beperken tot een vaste, "
        "korte lijst van vertrouwde domeinen in plaats van elke oorsprong "
        "te accepteren."
    ),
    "header_missing": (
        "Eén of meer aanbevolen beveiligingsheaders ontbreken",
        "Deze headers zijn een extra verdedigingslaag in de browser tegen "
        "onder meer XSS en clickjacking. Hun afwezigheid maakt andere "
        "problemen gemakkelijker uitbuitbaar, maar is op zich meestal geen "
        "acuut risico.",
        "Laat de ontwikkelaar of hosting provider de ontbrekende headers "
        "toevoegen aan de webserverconfiguratie (Nginx/Apache) of in de "
        "applicatie zelf; dit is doorgaans een kwestie van enkele regels "
        "configuratie."
    ),
    "csp_weak": (
        "De Content-Security-Policy-header biedt weinig echte bescherming",
        "Deze header kan XSS-aanvallen beperken zelfs als er ergens een fout "
        "in de code zit. Een zwakke policy mist die extra vangnetfunctie.",
        "Laat de ontwikkelaar een CSP opstellen die minstens 'default-src' "
        "en 'script-src' beperkt tot de eigen website en expliciet "
        "vertrouwde bronnen."
    ),
    "cookie_httponly": (
        "Een cookie is leesbaar voor JavaScript op de pagina",
        "Als er ooit een XSS-fout zou optreden, kan deze cookie (mogelijk "
        "een sessie) daarmee gestolen worden.",
        "Laat de ontwikkelaar het vlagje 'HttpOnly' toevoegen aan deze "
        "cookie, zodat JavaScript er niet bij kan."
    ),
    "cookie_insecure": (
        "Een cookie wordt niet gemarkeerd als enkel-via-HTTPS",
        "Deze cookie zou in bepaalde situaties onversleuteld over het "
        "netwerk kunnen worden verstuurd en onderschept worden.",
        "Laat de ontwikkelaar het vlagje 'Secure' toevoegen aan deze cookie."
    ),
    "cookie_samesite": (
        "Een cookie heeft geen SameSite-instelling",
        "Dit maakt bepaalde aanvallen (cross-site request forgery) "
        "gemakkelijker, waarbij een andere website namens een ingelogde "
        "bezoeker acties kan laten uitvoeren.",
        "Laat de ontwikkelaar 'SameSite=Lax' (of 'Strict' waar mogelijk) "
        "instellen op deze cookie."
    ),
    "csrf_missing": (
        "Het loginformulier heeft geen zichtbare bescherming tegen CSRF",
        "Dit kan het voor een aanvaller gemakkelijker maken om een bezoeker "
        "te misleiden tot ongewenste acties.",
        "Laat de ontwikkelaar een CSRF-token toevoegen aan het formulier; de "
        "meeste webframeworks (zoals Laravel) bieden dit standaard aan."
    ),
    "https_redirect_bad": (
        "Het is niet duidelijk of onversleuteld verkeer automatisch wordt doorgestuurd naar HTTPS",
        "Zonder deze doorverwijzing kan een bezoeker per ongeluk de "
        "onversleutelde versie van de site gebruiken.",
        "Laat de hosting provider of ontwikkelaar een verplichte "
        "doorverwijzing van HTTP naar HTTPS instellen op serverniveau."
    ),
    "user_enum_warn": (
        "De website laat mogelijk zien of een e-mailadres al dan niet een account heeft",
        "Een aanvaller kan dit gebruiken om een lijst van geldige "
        "klant-e-mailadressen op te bouwen, bijvoorbeeld voor phishing of "
        "om gerichter wachtwoorden te raden.",
        "Laat de ontwikkelaar ervoor zorgen dat inlog- en "
        "wachtwoord-vergeten-formulieren altijd exact dezelfde melding en "
        "reactietijd tonen, ongeacht of het adres bestaat."
    ),
    "clickjack_missing": (
        "De pagina kan mogelijk onzichtbaar in een ander venster worden ingeladen",
        "Hiermee kan een aanvaller een bezoeker misleiden om onbewust op "
        "iets te klikken ('clickjacking'), bijvoorbeeld een actie binnen "
        "jouw webshop.",
        "Laat de ontwikkelaar de header 'X-Frame-Options: DENY' of een CSP "
        "met 'frame-ancestors' toevoegen."
    ),
    "jwt_no_exp": (
        "Het inlog-token (JWT) heeft geen vervaldatum",
        "Een gestolen token zou hierdoor voor onbepaalde tijd bruikbaar "
        "blijven voor een aanvaller.",
        "Laat de ontwikkelaar een beperkte geldigheidsduur ('exp') instellen "
        "op elk token, met een vernieuwingsmechanisme indien nodig."
    ),
    "jwt_decode_fail": (
        "Er werd een token gevonden in een niet-standaardformaat",
        "Dit op zich is geen bevestigd probleem, maar verdient een korte "
        "controle door de ontwikkelaar.",
        "Laat de ontwikkelaar handmatig bevestigen dat dit token volgens de "
        "verwachte standaard is opgebouwd."
    ),
    "hidden_path_exposed": (
        "Er is een onverwacht pad op de website publiek bereikbaar",
        "Afhankelijk van wat zich op dat pad bevindt, kan dit informatie "
        "prijsgeven die een aanvaller verder op weg helpt.",
        "Laat de ontwikkelaar controleren of dit pad opzettelijk publiek is; "
        "zo niet, maak het ontoegankelijk of verwijder het."
    ),
    "ferox_found_info": (
        "Een gerichte zoekactie vond extra mappen/bestanden op de website",
        "Sommige hiervan kunnen beheerpanelen, back-ups of testbestanden "
        "zijn die niet publiek hoeven te zijn.",
        "Laat de ontwikkelaar de lijst in 'feroxbuster.filtered.txt' "
        "nalopen en alles verwijderen of afschermen wat niet publiek hoeft "
        "te zijn."
    ),
    "server_version_leak": (
        "De server toont een exact versienummer van de gebruikte software",
        "Dit maakt het voor een aanvaller iets gemakkelijker om gericht naar "
        "gekende kwetsbaarheden in die specifieke versie te zoeken.",
        "Laat de hosting provider de 'Server'-header verbergen of "
        "generieker maken."
    ),
    "tech_leak": (
        "De website toont welke technologie er precies gebruikt wordt",
        "Dit is op zich een klein risico, maar maakt gericht zoeken naar "
        "kwetsbaarheden iets gemakkelijker voor een aanvaller.",
        "Laat de ontwikkelaar de header 'X-Powered-By' uitschakelen."
    ),
    "referrer_leak": (
        "Volledige paginalinks kunnen doorlekken naar andere websites die je bezoekers daarna bezoeken",
        "Dit kan in zeldzame gevallen gevoelige informatie die in een "
        "link-adres staat, blootgeven aan een andere website.",
        "Laat de ontwikkelaar de header 'Referrer-Policy' instellen op "
        "bijvoorbeeld 'strict-origin-when-cross-origin'."
    ),
    "cache_control_login": (
        "De inlogpagina mag mogelijk door de browser worden opgeslagen in de cache",
        "Op een gedeelde computer zou een volgende gebruiker hierdoor "
        "mogelijk (delen van) de ingevulde inlogpagina kunnen terugzien.",
        "Laat de ontwikkelaar 'Cache-Control: no-store' instellen op de "
        "inlogpagina."
    ),
}

CRITICAL_IDS = {
    "trace_enabled", "open_redirect_direct", "xss_confirmed", "env_leak",
    "git_leak", "laravel_log_leak", "open_redirect_login", "jwt_alg_none",
    "cors_critical", "sqli_found", "xss_dalfox_found", "secrets_found",
}
HIGH_IDS = {
    "form_https_bad", "session_fixation", "ratelimit_missing",
    "graphql_introspection", "cors_high",
}
LOW_IDS = {
    "server_version_leak", "tech_leak", "referrer_leak", "cache_control_login",
}

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_LABEL_NL = {"critical": "Kritiek", "high": "Hoog", "medium": "Gemiddeld", "low": "Laag"}
SEV_COLOR = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#d97706", "low": "#ca8a04"}

TEST_CATALOG = [
    ("custom", False, "Basisconfiguratie van de inlogpagina",
     "Controle van beveiligingsheaders, cookies, het loginformulier zelf, "
     "blootgestelde bestanden/paden, gebruikersenumeratie, sessiebeheer en "
     "de limiet op mislukte inlogpogingen."),
    ("retire", False, "Verouderde of kwetsbare JavaScript-bibliotheken",
     "De JavaScript-bestanden die de website naar bezoekers stuurt worden "
     "vergeleken met een lijst van gekende kwetsbaarheden."),
    ("cors", False, "Cross-domein verzoeken (CORS)",
     "Controle of de website per ongeluk gevoelige gegevens deelt met "
     "andere, niet-vertrouwde websites."),
    ("clickjack", False, "Bescherming tegen 'clickjacking'",
     "Controle of de pagina onzichtbaar in een ander venster geladen kan "
     "worden om bezoekers te misleiden."),
    ("jwt", False, "Login-tokens (JWT)",
     "Indien aanwezig: technische controle van de opbouw en geldigheid van "
     "het token dat na het inloggen gebruikt wordt."),
    ("cspeval", False, "Content-Security-Policy-analyse",
     "Analyse van de browserbeveiligingsregel die XSS-aanvallen kan "
     "beperken."),
    ("graphql", False, "GraphQL-koppelpunt (indien aanwezig)",
     "Controle of een eventuele GraphQL-API per ongeluk zijn volledige "
     "interne structuur prijsgeeft."),
    ("wpscan", False, "WordPress-specifieke controle (indien van toepassing)",
     "Als WordPress gedetecteerd wordt: controle op kwetsbare plugins/"
     "thema's en versies."),
    ("nmap", False, "Open netwerkpoorten en draaiende diensten",
     "Controle welke diensten vanaf het internet bereikbaar zijn op de "
     "server."),
    ("testssl", False, "Versleuteling (SSL/TLS) van het verkeer",
     "Controle of verouderde, onveilige versleutelingsinstellingen worden "
     "gebruikt."),
    ("sslyze", False, "Versleuteling (SSL/TLS), tweede controle",
     "Een tweede, onafhankelijke controle van dezelfde versleutelings"
     "instellingen."),
    ("nuclei", False, "Bekende kwetsbaarheden (brede automatische scan)",
     "Een scanner met duizenden testpatronen voor gekende "
     "kwetsbaarheden en veelvoorkomende misconfiguraties."),
    ("zap", False, "Geautomatiseerde kwetsbaarhedenscan (OWASP ZAP)",
     "Een industriestandaard-scanner die de website doorzoekt en test op "
     "een brede waaier aan webkwetsbaarheden."),
    ("nikto", True, "Uitgebreide webserver-scan (Nikto)",
     "Diepgaandere, actieve controle van de webserverconfiguratie."),
    ("wapiti", True, "Actieve kwetsbaarhedenscan (Wapiti)",
     "Een tweede actieve scanner die zelf test-invoer naar de website "
     "stuurt."),
    ("secrets", True, "Gelekte wachtwoorden/sleutels in publieke bestanden",
     "Controle of er per ongeluk geheimen (API-sleutels, wachtwoorden) "
     "publiek terug te vinden zijn."),
    ("feroxbuster", True, "Verborgen mappen en bestanden",
     "Een gerichte zoekactie naar mappen/bestanden die niet bedoeld zijn "
     "om publiek te zijn."),
    ("arjun", True, "Verborgen parameters in de website",
     "Opsporen van extra, niet-gedocumenteerde invoervelden die de "
     "website mogelijk verwerkt."),
    ("sqlmap", True, "SQL-injectie op het inlogformulier",
     "Actieve test of het loginformulier kwetsbaar is voor manipulatie "
     "van databasequeries."),
    ("dalfox", True, "Cross-site scripting (XSS) op het inlogformulier",
     "Actieve test of kwaadaardige code via het loginformulier kan worden "
     "ingebracht en uitgevoerd."),
]


def classify(tag, fid):
    if fid in CRITICAL_IDS:
        return "critical"
    if fid in HIGH_IDS:
        return "high"
    if fid in LOW_IDS:
        return "low"
    if tag == "FAIL":
        return "high"
    if tag == "WARN":
        return "medium"
    return None


def match_id(msg_lower):
    if re.search(r"bereikbaar \(\d+b\)", msg_lower):
        return "laravel_log_leak"
    for needle, fid in KB_MATCH:
        if needle in msg_lower:
            return fid
    return None


def parse_findings(path):
    items = []
    if not os.path.isfile(path):
        return items
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"^\[(OK|WARN|FAIL|INFO)\]\s*(.*)$", line.strip())
            if not m:
                continue
            tag, msg = m.group(1), m.group(2)
            fid = match_id(msg.lower())
            items.append({"tag": tag, "msg": msg, "id": fid})
    return items


def strip_html(s):
    return re.sub(r"<[^>]+>", " ", s or "").strip()


def parse_zap(path):
    out = []
    if not os.path.isfile(path):
        return out
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
        sites = data.get("site") or []
        for site in sites:
            for alert in site.get("alerts") or []:
                risk = (alert.get("riskdesc") or "Informational").split(" ")[0].lower()
                sev = {"high": "high", "medium": "medium", "low": "low"}.get(risk)
                if not sev:
                    continue
                name = alert.get("name") or "ZAP-melding"
                desc = strip_html(alert.get("desc") or "")[:300]
                sol = strip_html(alert.get("solution") or "")[:300]
                n = len(alert.get("instances") or [])
                out.append({
                    "severity": sev, "source": "OWASP ZAP", "title": name,
                    "impact": desc or "Zie het volledige ZAP-rapport voor details.",
                    "fix": sol or "Zie het volledige ZAP-rapport voor de aanbevolen oplossing.",
                    "extra": f"{n} keer aangetroffen" if n else "",
                })
    except Exception:
        pass
    return out


def parse_nuclei(path):
    out = []
    if not os.path.isfile(path):
        return out
    sev_words = {"critical", "high", "medium", "low", "info"}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                brackets = re.findall(r"\[([^\]]+)\]", line)
                sev = next((b.lower() for b in brackets if b.lower() in sev_words), None)
                if sev in (None, "info"):
                    continue
                tmpl = brackets[0] if brackets else "onbekend"
                out.append({
                    "severity": sev, "source": "Nuclei", "title": f"Scanpatroon: {tmpl}",
                    "impact": "Een automatische scanner herkende een patroon dat overeenkomt "
                              "met een gekende kwetsbaarheid of blootstelling.",
                    "fix": "Bezorg deze scan-ID aan je IT-team of hosting provider om te "
                           "bevestigen en de aanbevolen patch of configuratiewijziging toe "
                           "te passen.",
                    "extra": line[:200],
                })
    except Exception:
        pass
    return out


def parse_retire(path):
    out = []
    if not os.path.isfile(path):
        return out
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
        for entry in data.get("data") or []:
            fname = entry.get("file", "")
            for res in entry.get("results") or []:
                comp = res.get("component", "bibliotheek")
                ver = res.get("version", "?")
                for vuln in res.get("vulnerabilities") or []:
                    sev = (vuln.get("severity") or "medium").lower()
                    if sev not in ("critical", "high", "medium", "low"):
                        sev = "medium"
                    ids = vuln.get("identifiers") or {}
                    cve = ", ".join(ids.get("CVE", [])) or "geen CVE-nummer"
                    out.append({
                        "severity": sev, "source": "Verouderde JS-bibliotheek",
                        "title": f"{comp} {ver}",
                        "impact": f"Deze veelgebruikte JavaScript-bibliotheek bevat een "
                                  f"gekende kwetsbaarheid ({cve}), geladen vanuit {fname}.",
                        "fix": f"Laat de ontwikkelaar {comp} bijwerken naar een nieuwere, "
                               f"gepatchte versie.",
                        "extra": "",
                    })
    except Exception:
        pass
    return out


def parse_testssl(path):
    out = []
    if not os.path.isfile(path):
        return out
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
        entries = data if isinstance(data, list) else data.get("scanResult", [])
        bad = [e for e in entries if isinstance(e, dict)
               and str(e.get("severity", "")).upper() in ("HIGH", "CRITICAL")]
        if bad:
            out.append({
                "severity": "high", "source": "SSL/TLS-configuratie (testssl.sh)",
                "title": f"{len(bad)} probleem/problemen met hoge ernst in de versleuteling",
                "impact": "Verouderde of zwakke versleutelingsinstellingen kunnen het "
                          "voor een aanvaller gemakkelijker maken om versleuteld "
                          "verkeer te onderscheppen of te manipuleren.",
                "fix": "Laat de hosting provider of ontwikkelaar de volledige lijst in "
                       "testssl.html nalopen en de aanbevolen TLS-instellingen "
                       "toepassen.",
                "extra": "",
            })
    except Exception:
        pass
    return out


def parse_nmap(path):
    out = []
    if not os.path.isfile(path):
        return out
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
        ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", text)
        extra = [(p, s) for p, s in ports if p not in ("80", "443")]
        if extra:
            lijst = ", ".join(f"{p}/{s}" for p, s in extra[:10])
            out.append({
                "severity": "low", "source": "Open netwerkpoorten (Nmap)",
                "title": f"{len(extra)} extra open poort(en) gevonden naast 80/443",
                "impact": f"Volgende poorten/diensten zijn ook vanaf het internet "
                          f"bereikbaar: {lijst}. Elke extra bereikbare dienst is een "
                          f"extra mogelijk aanvalspunt.",
                "fix": "Laat de hosting provider controleren of deze diensten "
                       "opzettelijk publiek bereikbaar moeten zijn; zo niet, "
                       "beperk de toegang via een firewall.",
                "extra": "",
            })
    except Exception:
        pass
    return out


def build_html(args, custom_items, auto_items, cover_logo_b64):
    actionable = []
    passed = collections.Counter()
    info = collections.Counter()

    for it in custom_items:
        tag, msg, fid = it["tag"], it["msg"], it["id"]
        if tag == "OK":
            passed[LABELS.get(fid, msg[:90])] += 1
            continue
        if tag == "INFO":
            info[LABELS.get(fid, msg[:90])] += 1
            continue
        sev = classify(tag, fid)
        det = DETAIL.get(fid)
        if det:
            title, impact, fix = det
        else:
            title, impact, fix = (msg[:140],
                                   "Nader onderzoek door IT aanbevolen.",
                                   "Bespreek deze bevinding met je ontwikkelaar of "
                                   "hosting provider.")
        actionable.append({
            "severity": sev, "source": "Eigen controle", "title": title,
            "impact": impact, "fix": fix, "extra": msg if det else "",
        })

    actionable.extend(auto_items)
    actionable.sort(key=lambda x: SEV_ORDER.index(x["severity"]))

    counts = collections.Counter(x["severity"] for x in actionable)
    if counts.get("critical"):
        overall = "critical"
    elif counts.get("high"):
        overall = "high"
    elif counts.get("medium"):
        overall = "medium"
    elif counts.get("low"):
        overall = "low"
    else:
        overall = None

    skip_set = set(s.strip() for s in (args.skip or "").split(",") if s.strip())
    tested = []
    for key, active_only, title, desc in TEST_CATALOG:
        if key in skip_set:
            continue
        if active_only and not args.active:
            continue
        tested.append((title, desc))

    def badge(sev):
        return (f'<span class="badge" style="background:{SEV_COLOR[sev]}">'
                f'{esc(SEV_LABEL_NL[sev])}</span>')

    cards = []
    cur_sev = None
    for item in actionable:
        if item["severity"] != cur_sev:
            cur_sev = item["severity"]
            cards.append(f'<h3 class="sev-head" style="color:{SEV_COLOR[cur_sev]}">'
                         f'{esc(SEV_LABEL_NL[cur_sev])}</h3>')
        extra = f'<p class="extra">Details: {esc(item["extra"])}</p>' if item.get("extra") else ""
        cards.append(f'''
        <div class="card">
          <div class="card-head">{badge(item["severity"])}
            <span class="source">{esc(item["source"])}</span></div>
          <h4>{esc(item["title"])}</h4>
          <p><strong>Waarom dit ertoe doet:</strong> {esc(item["impact"])}</p>
          <p><strong>Wat te doen:</strong> {esc(item["fix"])}</p>
          {extra}
        </div>''')
    if not actionable:
        cards.append('<p>Er werden geen punten gevonden die onmiddellijke actie vereisen.</p>')

    passed_html = "".join(
        f'<li>✔ {esc(label)}{" (" + str(n) + "x)" if n > 1 else ""}</li>'
        for label, n in sorted(passed.items())
    ) or "<li>Geen gegevens.</li>"

    info_html = "".join(
        f'<li>ℹ {esc(label)}{" (" + str(n) + "x)" if n > 1 else ""}</li>'
        for label, n in sorted(info.items())
    ) or "<li>Geen bijkomende opmerkingen.</li>"

    tested_html = "".join(
        f'<li><strong>{esc(t)}</strong> — {esc(d)}</li>' for t, d in tested
    )

    appendix_files = [
        ("zap-report.html", "Volledig technisch rapport van de OWASP ZAP-scan"),
        ("testssl.html", "Volledig technisch rapport van de SSL/TLS-controle"),
        ("sslyze.json", "Tweede SSL/TLS-controle (ruwe data)"),
        ("nuclei.txt", "Volledige lijst van scanpatronen die een match gaven"),
        ("nikto.txt", "Volledig technisch rapport van de Nikto-scan"),
        ("wapiti", "Volledig technisch rapport van de Wapiti-scan (map)"),
        ("sqlmap", "Ruwe uitvoer van de SQL-injectietest (map)"),
        ("dalfox.json", "Ruwe uitvoer van de XSS-test"),
        ("feroxbuster.filtered.txt", "Volledige lijst gevonden mappen/bestanden"),
        ("gitleaks.json", "Details van eventueel gevonden gelekte geheimen"),
        ("arjun.json", "Volledige lijst ontdekte parameters"),
        ("retire.json", "Volledige lijst kwetsbare JavaScript-bibliotheken"),
        ("wpscan.txt", "Volledig technisch rapport van de WordPress-scan"),
        ("nmap.nmap", "Volledig technisch rapport van de poortscan"),
    ]
    appendix_html = "".join(
        f'<li><code>{esc(fn)}</code> — {esc(desc)}</li>'
        for fn, desc in appendix_files if os.path.exists(os.path.join(args.out, fn))
    ) or "<li>Geen aanvullende technische bestanden beschikbaar.</li>"

    overall_txt = (
        f'<p class="overall" style="color:{SEV_COLOR[overall]}">'
        f'Algemene risico-inschatting: <strong>{SEV_LABEL_NL[overall]}</strong></p>'
        if overall else
        '<p class="overall" style="color:#16a34a">Algemene risico-inschatting: '
        '<strong>Geen significante risico\'s gevonden</strong></p>'
    )

    cover_logo_html = (
        f'<img src="data:image/png;base64,{cover_logo_b64}" style="height:45mm;margin-bottom:10mm;">'
        if cover_logo_b64 else ""
    )

    html_doc = f'''<!doctype html>
<html lang="nl"><head><meta charset="utf-8">
<style>
  body {{ font-family: "DejaVu Sans", Arial, sans-serif; color:#1f2937; font-size:13px; line-height:1.5; }}
  h1 {{ font-size:26px; margin-bottom:0; }}
  h1 .probe {{ color:#dc2626; }}
  h2 {{ font-size:19px; margin-top:28px; border-bottom:2px solid #1f2937; padding-bottom:4px; page-break-before:always; }}
  h2.first {{ page-break-before:auto; }}
  h3.sev-head {{ font-size:16px; margin-top:22px; }}
  h4 {{ margin:0 0 6px 0; font-size:14px; }}
  .cover {{ text-align:center; margin-top:60px; }}
  .cover .sub {{ color:#6b7280; margin-top:10px; }}
  .badge {{ color:white; border-radius:4px; padding:2px 8px; font-size:11px; font-weight:bold; margin-right:8px; }}
  .card {{ border:1px solid #e5e7eb; border-left:5px solid #9ca3af; border-radius:4px; padding:10px 14px; margin:10px 0; background:#fafafa; }}
  .card .source {{ color:#6b7280; font-size:11px; text-transform:uppercase; }}
  .card .extra {{ color:#6b7280; font-size:11px; font-style:italic; }}
  table.legend {{ border-collapse:collapse; width:100%; margin:12px 0; }}
  table.legend td, table.legend th {{ border:1px solid #e5e7eb; padding:6px 10px; text-align:left; font-size:12px; }}
  .overall {{ font-size:16px; }}
  ul {{ padding-left:20px; }}
  .conf {{ color:#6b7280; font-size:11px; margin-top:40px; border-top:1px solid #e5e7eb; padding-top:8px; }}
</style></head>
<body>

<div class="cover">
  {cover_logo_html}
  <h1>Aegis<span class="probe">Probe</span></h1>
  <p class="sub" style="font-size:15px;">Red Team Beveiligingsrapport</p>
  <p class="sub">Doel: {esc(args.target)}</p>
  <p class="sub">Datum: {esc(args.date)}</p>
  <p class="sub">Testmodus: {esc(args.mode)}</p>
  {overall_txt}
  <p class="sub" style="margin-top:40px;">VERTROUWELIJK — enkel bestemd voor geadresseerden</p>
</div>

<h2 class="first">Samenvatting voor management</h2>
<p>Dit rapport beschrijft een beveiligingsonderzoek ("penetratietest") dat werd
uitgevoerd op jouw website, met bijzondere aandacht voor de inlogpagina's en
het betalingsproces. Hieronder vind je een overzicht in gewone taal: wat we
getest hebben, wat we gevonden hebben, en wat er moet gebeuren.</p>
<p>Gevonden knelpunten per ernst: 
Kritiek: {counts.get("critical",0)} — 
Hoog: {counts.get("high",0)} — 
Gemiddeld: {counts.get("medium",0)} — 
Laag: {counts.get("low",0)}.</p>

<h2>Hoe lees je dit rapport?</h2>
<table class="legend">
<tr><th>Niveau</th><th>Betekenis</th></tr>
<tr><td style="color:{SEV_COLOR['critical']}"><strong>Kritiek</strong></td><td>Onmiddellijk actie ondernemen — reëel risico op grote schade (bv. diefstal van klantgegevens).</td></tr>
<tr><td style="color:{SEV_COLOR['high']}"><strong>Hoog</strong></td><td>Binnen enkele dagen tot weken oplossen.</td></tr>
<tr><td style="color:{SEV_COLOR['medium']}"><strong>Gemiddeld</strong></td><td>Inplannen als verbetering op middellange termijn.</td></tr>
<tr><td style="color:{SEV_COLOR['low']}"><strong>Laag</strong></td><td>Verbeteren wanneer het past; beperkte impact.</td></tr>
<tr><td>✔ In orde</td><td>Getest en correct bevonden — geen actie nodig.</td></tr>
<tr><td>ℹ Ter info</td><td>Geen risico, wel een nuttige technische vaststelling.</td></tr>
</table>

<h2>Wat hebben we getest?</h2>
<ul>{tested_html}</ul>
<p><em>Betaalgerelateerde onderdelen ({esc(args.exclude)}) werden bewust
buiten de actieve/indringende testen gehouden; test deze enkel met aparte,
schriftelijke toestemming van de betaalprovider zelf.</em></p>

<h2>Gedetailleerde bevindingen</h2>
{"".join(cards)}

<h2>Wat is er al in orde?</h2>
<ul>{passed_html}</ul>

<h2>Bijkomende technische opmerkingen</h2>
<ul>{info_html}</ul>

<h2>Bijlage voor IT-staff: technische rapporten</h2>
<p>Onderstaande ruwe, technische rapporten zijn beschikbaar in dezelfde
resultatenmap als dit rapport, voor wie dieper wil graven:</p>
<ul>{appendix_html}</ul>

<h2>Methodologie, reikwijdte en voorbehoud</h2>
<p>Dit onderzoek werd uitgevoerd met AegisProbe, een combinatie van
geautomatiseerde open-sourcetools (onder meer OWASP ZAP, Nuclei, sqlmap,
dalfox, Nikto, Wapiti, testssl.sh) en gerichte, zelfgeschreven controles.
Geautomatiseerde tools kunnen zowel valse meldingen (false positives) als
gemiste problemen (false negatives) opleveren: dit rapport is een
momentopname en vervangt geen doorlopende beveiligingsmonitoring of een
volledige, handmatige penetratietest door een gecertificeerd tester.</p>
<p>Deze test werd uitgevoerd met bevestigde schriftelijke toestemming van de
sitebeheerder, binnen het hierboven vermelde testbereik.</p>

<p class="conf">Dit document bevat vertrouwelijke informatie over
beveiligingszwakheden en is enkel bestemd voor de beoogde ontvanger(s).
Verspreid dit rapport niet verder zonder toestemming.</p>
</body></html>'''
    return html_doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--skip", default="")
    ap.add_argument("--lang", default="nl")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--active", action="store_true")
    ap.add_argument("--date", default="")
    args = ap.parse_args()

    custom_items = parse_findings(os.path.join(args.out, "findings.txt"))
    auto_items = []
    auto_items += parse_zap(os.path.join(args.out, "zap-report.json"))
    auto_items += parse_nuclei(os.path.join(args.out, "nuclei.txt"))
    auto_items += parse_retire(os.path.join(args.out, "retire.json"))
    auto_items += parse_testssl(os.path.join(args.out, "testssl.json"))
    auto_items += parse_nmap(os.path.join(args.out, "nmap.nmap"))

    header_b64 = load_logo_b64(140)
    cover_b64 = load_logo_b64(500)

    html_doc = build_html(args, custom_items, auto_items, cover_b64)
    with open(os.path.join(args.out, "AegisProbe-Report.html"), "w", encoding="utf-8") as f:
        f.write(html_doc)
    with open(os.path.join(args.out, "AegisProbe-Report-header.html"), "w", encoding="utf-8") as f:
        f.write(build_header_html(header_b64))


if __name__ == "__main__":
    main()
PYEOF

  # ---- hoofdscript in de container ----
  cat > "$B/run-checks.sh" <<'INNER'
#!/usr/bin/env bash
set -u
OUT=/results
TARGET="${TARGET:?TARGET ontbreekt}"
ACTIVE="${ACTIVE:-0}"
ZAP_MIN="${ZAP_MIN:-3}"
RATELIMIT="${RATELIMIT:-0}"
SKIP="${SKIP:-}"
TEST_EMAIL="${TEST_EMAIL:-}"
TEST_PASSWORD="${TEST_PASSWORD:-}"
EXTRA_JS="${EXTRA_JS:-}"
USER_FIELD="${USER_FIELD:-}"
PASS_FIELD="${PASS_FIELD:-}"
PAYMENT_PATH_EXCLUDE="${PAYMENT_PATH_EXCLUDE:-}"
FEROX_WORDLIST_URL="${FEROX_WORDLIST_URL:-}"
REPORT_LANG="${REPORT_LANG:-nl}"
REPORT_PASSWORD="${REPORT_PASSWORD:-}"
FEROX_WORDLIST_PATH="/cache/wordlists/ferox-wordlist.txt"

SCHEME="${TARGET%%://*}"
HOST="$(echo "$TARGET" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
ORIGIN="$(echo "$TARGET" | sed -E 's#^([a-zA-Z]+://[^/]+).*#\1#')"
PORT="$(echo "$TARGET" | sed -nE 's#^[a-zA-Z]+://[^/:]+:([0-9]+).*#\1#p')"
if [ -z "$PORT" ]; then [ "$SCHEME" = "https" ] && PORT=443 || PORT=80; fi
LOGIN_URL="${TARGET%%\?*}"
UA="Mozilla/5.0 (compatible; AuthorizedSecurityAudit/1.0)"

want()    { [[ ",${SKIP}," != *",$1,"* ]]; }
banner()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
cu()      { curl -sS --max-time 25 -A "$UA" "$@"; }
finding() { printf '[%s] %s\n' "$1" "$2" | tee -a "$OUT/findings.txt"; }
run_tool() {
  local n="$1"; shift
  banner "$n"
  "$@" > "$OUT/$n.log" 2>&1
  echo "    klaar (exit $?) -> $n.log"
}

is_payment_path() {
  local p; p="$(echo "$1" | tr 'A-Z' 'a-z')"
  local ex; IFS=',' read -r -a ex <<< "$(echo "$PAYMENT_PATH_EXCLUDE" | tr 'A-Z' 'a-z')"
  for e in "${ex[@]}"; do
    [ -n "$e" ] && [[ "$p" == *"$e"* ]] && return 0
  done
  return 1
}

: > "$OUT/findings.txt"
echo "AegisProbe | doel: $TARGET | host=$HOST poort=$PORT | actief=$ACTIVE | overslaan=${SKIP:-niets}"
if is_payment_path "$LOGIN_URL"; then
  finding INFO "LET OP: doel-URL matcht een PAYMENT_PATH_EXCLUDE-term; actieve fuzzing-tools worden overgeslagen voor dit doel"
fi

# ------------------------------------------------------------- voorbereiding
prepare_tools() {
  banner "Voorbereiding: nuclei-templates bijwerken (gecachet, met herpogingen)"
  mkdir -p /root/.local/nuclei-templates
  local ok=0 i
  for i in 1 2 3; do
    if nuclei -ut -silent > "$OUT/prep-nuclei-templates.log" 2>&1; then ok=1; break; fi
    echo "    poging $i mislukt, nieuwe poging over 5s..."; sleep 5
  done
  if [ "$ok" = 1 ]; then
    finding OK "nuclei-templates succesvol bijgewerkt (gecachet voor volgende runs)"
  else
    finding WARN "nuclei-templates konden niet bijgewerkt worden (geen netwerk tijdens voorbereiding?); eerder gecachete templates (indien aanwezig) worden gebruikt"
  fi

  banner "Voorbereiding: wordlist voor feroxbuster (gecachet)"
  mkdir -p "$(dirname "$FEROX_WORDLIST_PATH")"
  if [ ! -s "$FEROX_WORDLIST_PATH" ]; then
    cu -o "$FEROX_WORDLIST_PATH" "$FEROX_WORDLIST_URL" 2>/dev/null || true
  fi
  [ -s "$FEROX_WORDLIST_PATH" ] && finding OK "feroxbuster-wordlist beschikbaar (gecachet)" \
    || finding INFO "feroxbuster-wordlist kon niet opgehaald worden; feroxbuster wordt later overgeslagen"

  banner "Voorbereiding: nikto-signatuurdatabase bijwerken"
  git -C /opt/nikto pull --ff-only > "$OUT/prep-nikto.log" 2>&1 || true

  banner "Voorbereiding: sqlmap bijwerken"
  git -C /opt/sqlmap pull --ff-only > "$OUT/prep-sqlmap.log" 2>&1 || true

  if command -v wpscan >/dev/null 2>&1; then
    banner "Voorbereiding: wpscan-database bijwerken"
    wpscan --update > "$OUT/prep-wpscan.log" 2>&1 || true
  fi
}

# ------------------------------------------------------------------ helpers
parse_login() {
  python3 /opt/formscan.py "$1" "$LOGIN_URL" > "$1.json" 2>/dev/null
  local sel='[.forms[]|select(any(.inputs[];.type=="password"))][0]'
  ACTION="$(jq -r "($sel.action) // empty" "$1.json")"; ACTION="${ACTION:-$LOGIN_URL}"
  USERF="${USER_FIELD:-$(jq -r "([$sel.inputs[]|select(.type==\"email\" or .type==\"text\")][0].name) // \"email\"" "$1.json")}"
  PASSF="${PASS_FIELD:-$(jq -r "([$sel.inputs[]|select(.type==\"password\")][0].name) // \"password\"" "$1.json")}"
  TOK_ARGS=()
  while IFS= read -r l; do [ -n "$l" ] && TOK_ARGS+=(--data-urlencode "$l"); done < <(
    jq -r "($sel.inputs[]|select(.type==\"hidden\" and .name!=null)|\"\(.name)=\(.value // \"\")\")" "$1.json" 2>/dev/null)
  if [ ${#TOK_ARGS[@]} -eq 0 ]; then
    local m; m="$(jq -r '.csrf_meta // empty' "$1.json")"
    [ -n "$m" ] && TOK_ARGS+=(--data-urlencode "_token=$m")
  fi
}

login_attempt() {
  local jar; jar="$(mktemp)"
  cu -c "$jar" -o "$3.get" "$LOGIN_URL"
  parse_login "$3.get"
  local follow="-L"; [ "${4:-}" = "nofollow" ] && follow=""
  cu -b "$jar" -c "$jar" $follow -D "$3.hdr" -o "$3.body" \
     -w '%{http_code} %{size_download} %{time_total} %{url_effective}' \
     "${TOK_ARGS[@]}" --data-urlencode "$USERF=$1" --data-urlencode "$PASSF=$2" "$ACTION" > "$3.meta" 2>/dev/null
  cp "$jar" "$3.jar"; rm -f "$jar"
}

hdr_check() {
  local f; f="$(mktemp)"
  local code; code="$(cu -o /dev/null -D "$f" -w '%{http_code}' "$1" 2>/dev/null)"
  local miss=""
  for h in strict-transport-security x-content-type-options content-security-policy; do
    grep -qi "^$h:" "$f" || miss="$miss $h"
  done
  if [ -z "$miss" ]; then finding OK "$2 (HTTP $code): kernheaders aanwezig"
  else finding WARN "$2 (HTTP $code): ontbrekende headers:$miss"; fi
  rm -f "$f"
}

custom_checks() {
  banner "Eigen controles (headers, cookies, formulier, paden, enumeratie)"
  local H="$OUT/headers.txt" PAGE="$OUT/login.html"
  cu -c "$OUT/jar.txt" -D "$H" -o "$PAGE" "$TARGET"

  echo "--- Headers op de loginpagina"
  for h in strict-transport-security x-content-type-options content-security-policy referrer-policy permissions-policy; do
    if grep -qi "^$h:" "$H"; then finding OK "header aanwezig: $h"; else finding WARN "header ontbreekt: $h"; fi
  done
  grep -qi '^content-security-policy:.*\(default-src\|script-src\)' "$H" \
    || finding WARN "CSP bevat geen default-src/script-src (enkel frame-ancestors of niets)"
  grep -qi '^x-powered-by:' "$H" && finding WARN "X-Powered-By header lekt technologie"
  grep -iE '^server:.*[0-9]' "$H" >/dev/null && finding WARN "Server header bevat versienummer"
  grep -qi '^x-xss-protection: *1' "$H" && finding INFO "X-XSS-Protection is verouderd; verwijder of zet op 0"
  grep -qi '^referrer-policy: *no-referrer-when-downgrade' "$H" && finding WARN "Referrer-Policy no-referrer-when-downgrade lekt volledige URL's"
  grep -qi '^cache-control:.*no-store' "$H" || finding WARN "Loginpagina zonder Cache-Control: no-store"

  echo "--- Headers op andere responses (nginx add_header-overerving / 'always')"
  hdr_check "$ORIGIN/zz-$RANDOM-bestaat-niet" "404-pagina"
  hdr_check "$ORIGIN/robots.txt" "robots.txt"
  local firstjs; firstjs="$(grep -oP "<script[^>]*\ssrc=[\"']\K[^\"']+" "$PAGE" 2>/dev/null | grep -E '^/[^/]' | head -1)"
  [ -n "$firstjs" ] && hdr_check "$ORIGIN$firstjs" "statisch bestand $firstjs"

  echo "--- Cookies"
  grep -i '^set-cookie:' "$H" | while IFS= read -r line; do
    local name l; name="$(echo "$line" | sed -E 's/^[Ss]et-[Cc]ookie: *([^=]+)=.*/\1/')"
    l="$(echo "$line" | tr 'A-Z' 'a-z')"
    [[ "$l" == *secure* ]]    || finding WARN "cookie $name zonder Secure"
    [[ "$l" == *samesite* ]]  || finding WARN "cookie $name zonder SameSite"
    if [[ "$l" != *httponly* ]]; then
      if [ "$name" = "XSRF-TOKEN" ]; then finding INFO "cookie XSRF-TOKEN zonder HttpOnly (Laravel-standaard, OK)"
      else finding WARN "cookie $name zonder HttpOnly"; fi
    fi
  done

  echo "--- Loginformulier"
  parse_login "$PAGE"
  local nf; nf="$(jq '.forms|length' "$PAGE.json" 2>/dev/null)"
  finding INFO "formulieren op pagina: ${nf:-0}; login-actie: $ACTION; velden: $USERF / $PASSF"
  case "$ACTION" in https://*) finding OK "loginformulier post naar HTTPS";; *) finding WARN "loginformulier post niet naar HTTPS: $ACTION";; esac
  [ ${#TOK_ARGS[@]} -gt 0 ] && finding OK "CSRF-/hidden-token aanwezig in loginformulier" || finding WARN "geen CSRF-token in loginformulier gevonden"
  local ac; ac="$(jq -r '([.forms[].inputs[]|select(.type=="password")][0].autocomplete) // "niet gezet"' "$PAGE.json")"
  finding INFO "autocomplete op wachtwoordveld: $ac"

  echo "--- HTTP -> HTTPS"
  local r; r="$(cu -o /dev/null -w '%{http_code} %{redirect_url}' "http://$HOST/" 2>/dev/null)"
  case "$r" in 301*https://*|308*https://*) finding OK "HTTP redirect naar HTTPS ($r)";; *) finding WARN "HTTP->HTTPS redirect onduidelijk: $r";; esac

  echo "--- HTTP-methodes"
  local allow; allow="$(cu -X OPTIONS -D - -o /dev/null "$LOGIN_URL" 2>/dev/null | grep -i '^allow:' | tr -d '\r')"
  finding INFO "OPTIONS: ${allow:-geen Allow-header}"
  [ "$(cu -X TRACE -o /dev/null -w '%{http_code}' "$LOGIN_URL" 2>/dev/null)" = "200" ] && finding FAIL "TRACE is toegestaan"

  echo "--- Reflectie en open redirect via target_url (zonder login)"
  cu -D "$OUT/redir.hdr" -o "$OUT/redir.body" "${LOGIN_URL}?target_url=https%3A%2F%2Fevil.example%2F" 2>/dev/null
  grep -qi '^location:.*evil\.example' "$OUT/redir.hdr" && finding FAIL "target_url veroorzaakt directe redirect naar extern domein"
  grep -q 'evil.example' "$OUT/redir.body" && finding INFO "target_url wordt in de HTML gereflecteerd: controleer escaping en redirect na login (zie testaccount-test)"
  cu -o "$OUT/xss.body" "${LOGIN_URL}?target_url=%22%3E%3Csvg%20onload%3Dalert(1)%3E" 2>/dev/null
  grep -q '"><svg onload' "$OUT/xss.body" && finding FAIL "XSS-probe ongeëncodeerd gereflecteerd in target_url" || finding OK "XSS-probe in target_url niet ongeëncodeerd gereflecteerd"

  echo "--- Blootgestelde paden"
  local base; base="$(cu -o /dev/null -w '%{http_code}:%{size_download}' "$ORIGIN/zz-$RANDOM-nope" 2>/dev/null)"
  for p in /admin /admin/login /.env /.git/HEAD /storage/logs/laravel.log /telescope /horizon /phpinfo.php \
           /vendor/composer/installed.json /composer.lock /artisan /server-status /phpmyadmin/ /adminer.php \
           /backup.sql /.DS_Store /sitemap.xml /.well-known/security.txt /api /api/documentation; do
    local tmp; tmp="$(mktemp)"
    local res code size; res="$(cu -o "$tmp" -w '%{http_code}:%{size_download}' "$ORIGIN$p" 2>/dev/null)"
    code="${res%%:*}"; size="${res##*:}"
    if [ "$code" = "200" ] && [ "$res" != "$base" ]; then
      case "$p" in
        /.env) grep -qE 'APP_KEY=|DB_PASSWORD=' "$tmp" && finding FAIL "$p LEKT CONFIGURATIE" || finding INFO "$p geeft 200 (geen .env-inhoud)";;
        /.git/HEAD) grep -q 'ref: refs' "$tmp" && finding FAIL "$p: .git is publiek bereikbaar" || finding INFO "$p geeft 200";;
        /storage/logs/laravel.log) finding FAIL "$p bereikbaar (${size}B)";;
        /sitemap.xml|/.well-known/security.txt) finding INFO "$p bereikbaar";;
        *) finding WARN "$p bereikbaar (HTTP 200, ${size}B)";;
      esac
    elif [ "$code" = "302" ] || [ "$code" = "301" ]; then
      [[ "$p" == /admin* ]] && finding INFO "$p -> redirect ($code)"
    fi
    rm -f "$tmp"
  done

  if [ -n "$TEST_EMAIL" ]; then
    echo "--- Gebruikersenumeratie (1 foute poging per adres)"
    login_attempt "$TEST_EMAIL" "Fout-Wachtwoord-123!" "$OUT/enum_known"
    login_attempt "nietbestaand-$RANDOM@example.invalid" "Fout-Wachtwoord-123!" "$OUT/enum_unknown"
    local a b
    a="$(awk '{print $1, $2}' "$OUT/enum_known.meta")"; b="$(awk '{print $1, $2}' "$OUT/enum_unknown.meta")"
    echo "    bekend: $(cat "$OUT/enum_known.meta") | onbekend: $(cat "$OUT/enum_unknown.meta")"
    local ka ub
    ka="$(sed -E 's/value="[^"]*"//g; s/content="[^"]{20,}"//g' "$OUT/enum_known.body" | tr -s ' \n' ' ' | sed -E "s/$TEST_EMAIL//g" | md5sum)"
    ub="$(sed -E 's/value="[^"]*"//g; s/content="[^"]{20,}"//g' "$OUT/enum_unknown.body" | tr -s ' \n' ' ' | sed -E 's/nietbestaand-[0-9]+@example.invalid//g' | md5sum)"
    if [ "$ka" != "$ub" ] || [ "$a" != "$b" ]; then finding WARN "mogelijke gebruikersenumeratie: antwoord verschilt tussen bestaand en onbestaand adres (controleer handmatig, ook bij 'wachtwoord vergeten')"
    else finding OK "geen zichtbaar verschil tussen bestaand en onbestaand adres"; fi
  else
    finding INFO "gebruikersenumeratie overgeslagen (geef TEST_EMAIL op)"
  fi

  if [ -n "$TEST_EMAIL" ] && [ -n "$TEST_PASSWORD" ]; then
    echo "--- Sessie-regeneratie en redirect na login (testaccount)"
    local jar; jar="$(mktemp)"
    cu -c "$jar" -o "$OUT/auth.get" "${LOGIN_URL}?target_url=https%3A%2F%2Fevil.example%2F"
    parse_login "$OUT/auth.get"
    local before after
    before="$(awk '$6 ~ /session/ {print $7}' "$jar")"
    cu -b "$jar" -c "$jar" -D "$OUT/auth.hdr" -o /dev/null \
       "${TOK_ARGS[@]}" --data-urlencode "$USERF=$TEST_EMAIL" --data-urlencode "$PASSF=$TEST_PASSWORD" "$ACTION"
    after="$(awk '$6 ~ /session/ {print $7}' "$jar")"
    if [ -n "$before" ] && [ "$before" != "$after" ]; then finding OK "sessie-cookie wordt vernieuwd na login"
    else finding WARN "sessie-cookie lijkt niet te veranderen na login (session fixation?)"; fi
    grep -qi '^location:.*evil\.example' "$OUT/auth.hdr" && finding FAIL "OPEN REDIRECT: na login redirect naar extern domein via target_url" \
      || finding OK "geen redirect naar extern domein na login"
    rm -f "$jar"
  fi

  if [ "$RATELIMIT" = "1" ]; then
    echo "--- Rate limiting: 15 foute logins met nep-adres"
    local codes="" i
    for i in $(seq 1 15); do
      login_attempt "ratelimit-$RANDOM@example.invalid" "Fout-Wachtwoord-123!" "$OUT/rl" nofollow
      codes="$codes $(awk '{print $1}' "$OUT/rl.meta")"
      sleep 1
    done
    echo "    statuscodes:$codes"
    if echo "$codes" | grep -q '429'; then finding OK "rate limiting actief (HTTP 429 gezien)"
    else finding WARN "geen HTTP 429 na 15 pogingen: controleer throttling/lockout ($codes )"; fi
  fi
}

js_audit() {
  banner "retire.js (kwetsbare JavaScript-bibliotheken)"
  mkdir -p "$OUT/js"
  local base="${LOGIN_URL%/*}/"
  { grep -oP "<script[^>]*\ssrc=[\"']\K[^\"']+" "$OUT/login.html" 2>/dev/null
    for u in $EXTRA_JS; do echo "$u"; done; } | sort -u | while read -r u; do
    case "$u" in //*) u="$SCHEME:$u";; http*) ;; /*) u="$ORIGIN$u";; *) u="$base$u";; esac
    d="$OUT/js/$(echo "$u" | md5sum | cut -c1-6)"; mkdir -p "$d"
    f="$d/$(basename "${u%%\?*}")"
    if cu -f -o "$f" "$u" 2>/dev/null; then echo "$u -> $f" >> "$OUT/js/INDEX.txt"; else echo "mislukt: $u"; fi
  done
  retire --path "$OUT/js" --exitwith 0 2>&1 | tee "$OUT/retire.txt" | tail -n 40
  retire --path "$OUT/js" --exitwith 0 --outputformat json --outputpath "$OUT/retire.json" >/dev/null 2>&1
}

cors_check() {
  banner "CORS-misconfiguratie"
  local EVIL="https://evil-cors-test.example"
  local f; f="$(mktemp)"
  cu -H "Origin: $EVIL" -D "$f" -o /dev/null "$TARGET" 2>/dev/null
  local aco acc
  aco="$(grep -i '^access-control-allow-origin:' "$f" | tr -d '\r' | awk '{print $2}')"
  acc="$(grep -i '^access-control-allow-credentials:' "$f" | tr -d '\r' | awk '{print $2}')"
  if [ "$aco" = "$EVIL" ] || [ "$aco" = "*" ]; then
    if [ "$aco" = "*" ]; then finding INFO "CORS: Access-Control-Allow-Origin=* (geen credentials mogelijk, meestal onschuldig op publieke data)"
    else finding FAIL "CORS: willekeurige Origin wordt teruggespiegeld ($aco)$( [ "$acc" = "true" ] && echo ' MET Allow-Credentials: true (ernstig, sessie-diefstal mogelijk)')"; fi
  else
    finding OK "CORS: geen reflectie van een willekeurige Origin gezien op dit endpoint"
  fi
  rm -f "$f"
}

clickjack_check() {
  banner "Clickjacking (X-Frame-Options / CSP frame-ancestors)"
  local H="$OUT/headers.txt"
  [ -s "$H" ] || cu -D "$H" -o /dev/null "$TARGET" 2>/dev/null
  if grep -qi '^x-frame-options:' "$H" || grep -qi '^content-security-policy:.*frame-ancestors' "$H"; then
    finding OK "framing wordt beperkt (X-Frame-Options en/of CSP frame-ancestors aanwezig)"
  else
    finding WARN "geen X-Frame-Options en geen CSP frame-ancestors: pagina kan mogelijk ge-iframed worden (clickjacking)"
  fi
}

jwt_check() {
  banner "JWT structurele check"
  local H="$OUT/headers.txt"
  local tok
  tok="$(grep -oE '[eE][yY][A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$H" "$OUT/login.html" 2>/dev/null | head -1)"
  if [ -z "$tok" ]; then finding INFO "geen JWT gevonden in headers/pagina (mogelijk pas na login aanwezig; handmatig controleren)"; return; fi
  finding INFO "JWT gevonden, structurele analyse wordt uitgevoerd"
  local hdr_b64 pl_b64
  hdr_b64="$(echo "$tok" | cut -d. -f1)"; pl_b64="$(echo "$tok" | cut -d. -f2)"
  python3 - "$hdr_b64" "$pl_b64" > "$OUT/jwt.json" 2>/dev/null <<'PYEOF'
import sys, base64, json
def pad(s):
    return s + "=" * (-len(s) % 4)
h = json.loads(base64.urlsafe_b64decode(pad(sys.argv[1])))
p = json.loads(base64.urlsafe_b64decode(pad(sys.argv[2])))
print(json.dumps({"header": h, "payload": p}, indent=1))
PYEOF
  if [ -s "$OUT/jwt.json" ]; then
    local alg exp
    alg="$(jq -r '.header.alg // "onbekend"' "$OUT/jwt.json")"
    exp="$(jq -r '.payload.exp // "geen"' "$OUT/jwt.json")"
    finding INFO "JWT alg=$alg, exp=$exp"
    [ "$alg" = "none" ] && finding FAIL "JWT gebruikt alg=none (handtekening kan worden weggelaten)"
    [ "$exp" = "geen" ] && finding WARN "JWT heeft geen exp-claim (verloopt nooit)"
    echo "$tok" > "$OUT/jwt.token"
    jwt_tool "$tok" -M pb > "$OUT/jwt_tool.log" 2>&1 || true
  else
    finding WARN "JWT gevonden maar kon niet gedecodeerd worden (niet-standaard formaat?)"
  fi
}

cspeval_check() {
  banner "CSP-evaluator (Google)"
  local H="$OUT/headers.txt"
  local csp; csp="$(grep -i '^content-security-policy:' "$H" | sed -E 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: *//' | tr -d '\r')"
  if [ -z "$csp" ]; then finding INFO "geen CSP-header aanwezig, csp-evaluator overgeslagen"; return; fi
  python3 - "$csp" > "$OUT/cspeval.txt" 2>&1 <<'PYEOF' || true
import sys
try:
    from csp_evaluator.evaluator import CSPEvaluator
    from csp_evaluator.parser import CSPParser
    csp = sys.argv[1]
    parsed = CSPParser(csp).parse()
    ev = CSPEvaluator(parsed)
    findings = ev.evaluate()
    for f in findings:
        print(f)
except Exception as e:
    print(f"csp-evaluator kon niet draaien: {e}")
PYEOF
  if [ -s "$OUT/cspeval.txt" ]; then
    local n; n="$(wc -l < "$OUT/cspeval.txt")"
    finding INFO "csp-evaluator: $n regel(s) output, zie cspeval.txt"
  fi
}

graphql_check() {
  banner "GraphQL-detectie"
  local found=""
  for p in /graphql /api/graphql /graphiql /graphql/console; do
    local code; code="$(cu -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      -d '{"query":"query{__typename}"}' "$ORIGIN$p" 2>/dev/null)"
    if [ "$code" = "200" ]; then found="$ORIGIN$p"; finding INFO "mogelijk GraphQL-endpoint: $ORIGIN$p (HTTP 200)"; break; fi
  done
  if [ -n "$found" ]; then
    graphql-cop -t "$found" -o "$OUT/graphql-cop.json" > "$OUT/graphql-cop.log" 2>&1 || true
    grep -qi 'introspection' "$OUT/graphql-cop.log" && finding WARN "GraphQL introspectie lijkt (gedeeltelijk) ingeschakeld, zie graphql-cop.log"
  else
    finding INFO "geen GraphQL-endpoint gevonden op de gangbare paden"
  fi
}

param_discovery() {
  banner "arjun (verborgen parameters ontdekken)"
  if is_payment_path "$TARGET"; then finding INFO "arjun overgeslagen: doel valt onder PAYMENT_PATH_EXCLUDE"; return; fi
  arjun -u "$TARGET" -m GET,POST -o "$OUT/arjun.json" > "$OUT/arjun.log" 2>&1 || true
  if [ -s "$OUT/arjun.json" ]; then
    finding INFO "arjun vond mogelijke parameters, zie arjun.json/arjun.log"
  fi
}

sqlmap_scan() {
  banner "sqlmap (SQL-injectie op loginformulier)"
  if is_payment_path "$ACTION"; then finding INFO "sqlmap overgeslagen: form-actie valt onder PAYMENT_PATH_EXCLUDE"; return; fi
  local data="${USERF}=sqlmaptest&${PASSF}=sqlmaptest"
  sqlmap -u "$ACTION" --data="$data" --batch --level=2 --risk=1 \
    --technique=BEUSTQ --time-sec=3 --random-agent --output-dir="$OUT/sqlmap" \
    > "$OUT/sqlmap.log" 2>&1 || true
  if grep -qi 'is vulnerable' "$OUT/sqlmap.log"; then
    finding FAIL "sqlmap meldt mogelijke SQL-injectie, zie sqlmap.log en sqlmap/"
  else
    finding OK "sqlmap vond geen injectie op het loginformulier (level=2/risk=1; overweeg handmatig dieper te testen)"
  fi
}

dalfox_scan() {
  banner "dalfox (reflected/DOM XSS)"
  if is_payment_path "$TARGET"; then finding INFO "dalfox overgeslagen: doel valt onder PAYMENT_PATH_EXCLUDE"; return; fi
  dalfox url "$TARGET" --silence --format json -o "$OUT/dalfox.json" > "$OUT/dalfox.log" 2>&1 || true
  if [ -s "$OUT/dalfox.json" ] && grep -q '"type"' "$OUT/dalfox.json" 2>/dev/null; then
    finding FAIL "dalfox vond mogelijke XSS, zie dalfox.json"
  else
    finding OK "dalfox vond geen XSS op het directe doel-URL"
  fi
}

feroxbuster_scan() {
  banner "feroxbuster (content/directory discovery)"
  command -v feroxbuster >/dev/null 2>&1 || { finding INFO "feroxbuster niet beschikbaar, overgeslagen"; return; }
  if [ ! -s "$FEROX_WORDLIST_PATH" ]; then finding INFO "feroxbuster-wordlist kon niet opgehaald worden, overgeslagen"; return; fi
  feroxbuster -u "$ORIGIN" -w "$FEROX_WORDLIST_PATH" --silent -t 20 -d 2 \
    -o "$OUT/feroxbuster.txt" --json-file "$OUT/feroxbuster.json" > "$OUT/feroxbuster.log" 2>&1 || true
  if [ -s "$OUT/feroxbuster.txt" ]; then
    local excl_removed=0
    : > "$OUT/feroxbuster.filtered.txt"
    while IFS= read -r line; do
      if is_payment_path "$line"; then excl_removed=$((excl_removed+1)); else echo "$line" >> "$OUT/feroxbuster.filtered.txt"; fi
    done < "$OUT/feroxbuster.txt"
    finding INFO "feroxbuster: $(wc -l < "$OUT/feroxbuster.filtered.txt") resultaten (zie feroxbuster.filtered.txt); $excl_removed resultaat/resultaten onder PAYMENT_PATH_EXCLUDE verborgen in het verslag"
  fi
}

secrets_scan() {
  banner "gitleaks (lekken van keys/tokens in gedownloade bestanden)"
  command -v gitleaks >/dev/null 2>&1 || { finding INFO "gitleaks niet beschikbaar, overgeslagen"; return; }
  gitleaks detect --no-git --source "$OUT" --report-format json --report-path "$OUT/gitleaks.json" \
    --exit-code 0 > "$OUT/gitleaks.log" 2>&1 || true
  local n; n="$(jq 'length' "$OUT/gitleaks.json" 2>/dev/null || echo 0)"
  if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
    finding FAIL "gitleaks vond $n mogelijk(e) lek(ken), zie gitleaks.json"
  else
    finding OK "gitleaks vond geen secrets in de gedownloade JS/pagina's"
  fi
}

wpscan_optional() {
  command -v wpscan >/dev/null 2>&1 || return
  local PAGE="$OUT/login.html"
  if grep -qi 'wp-content\|wp-includes\|name="generator" content="WordPress' "$PAGE" 2>/dev/null \
     || [ "$(cu -o /dev/null -w '%{http_code}' "$ORIGIN/wp-login.php" 2>/dev/null)" = "200" ]; then
    banner "wpscan (WordPress gedetecteerd)"
    wpscan --url "$ORIGIN" --no-banner --random-user-agent -o "$OUT/wpscan.txt" > "$OUT/wpscan.log" 2>&1 || true
    finding INFO "WordPress gedetecteerd: wpscan uitgevoerd, zie wpscan.txt"
  else
    finding INFO "geen WordPress gedetecteerd, wpscan overgeslagen"
  fi
}

zap_scan() {
  banner "OWASP ZAP ($( [ "$ACTIVE" = 1 ] && echo full/actief || echo baseline/passief ))"
  mkdir -p /zap/wrk; cd /zap/wrk || return
  if [ "$ACTIVE" = 1 ]; then
    timeout 30m /zap/zap-full-scan.py -T 10 -d -t "$TARGET" -m "$ZAP_MIN" -r zap-report.html -J zap-report.json -w zap-report.md -I
  else
    timeout 30m /zap/zap-baseline.py -T 10 -d  -t "$TARGET" -m "$ZAP_MIN" -r zap-report.html -J zap-report.json -w zap-report.md -I
  fi > "$OUT/zap.log" 2>&1
  cp -f /zap/wrk/zap-report.* "$OUT/" 2>/dev/null
  tail -n 8 "$OUT/zap.log"
  cd / || true
}

# ------------------------------------------------------------------ uitvoer
prepare_tools
want custom && custom_checks
want retire && js_audit
want cors && cors_check
want clickjack && clickjack_check
want jwt && jwt_check
want cspeval && cspeval_check
want graphql && graphql_check
want wpscan && wpscan_optional
want nmap && run_tool nmap nmap -Pn -sT -sV --top-ports 1000 -T3 --open -oA "$OUT/nmap" "$HOST"
want testssl && run_tool testssl testssl.sh --quiet --warnings batch --color 0 --htmlfile "$OUT/testssl.html" --jsonfile "$OUT/testssl.json" "$HOST:$PORT"
want sslyze && run_tool sslyze sslyze --json_out="$OUT/sslyze.json" "$HOST:$PORT"
if want observatory; then
  if command -v mdn-http-observatory-scan >/dev/null 2>&1; then run_tool observatory mdn-http-observatory-scan "$HOST"
  else echo "observatory niet beschikbaar, overgeslagen"; fi
fi
want nuclei && run_tool nuclei nuclei -u "$TARGET" -severity info,low,medium,high,critical -etags dos -rl 10 -c 10 -nc -stats -timeout 10 -retries 1 -duc -o "$OUT/nuclei.txt"
want zap && zap_scan
if [ "$ACTIVE" = 1 ]; then
  want nikto       && run_tool nikto  perl /opt/nikto/program/nikto.pl -h "$ORIGIN" -Tuning 1234abce -maxtime 15m -ask no -nointeractive -o "$OUT/nikto.txt" -Format txt
  want wapiti      && run_tool wapiti wapiti -u "$TARGET" --scope folder -f html -o "$OUT/wapiti" --max-scan-time 900 --flush-session -v 1
  want secrets     && secrets_scan
  want feroxbuster && feroxbuster_scan
  want arjun       && param_discovery
  want sqlmap      && sqlmap_scan
  want dalfox      && dalfox_scan
fi

# ---------------------------------------------------------------- samenvatting (technisch, snel overzicht)
{
  echo "# AegisProbe - Auditsamenvatting (technisch)"
  echo "- Doel: $TARGET"
  echo "- Datum: $(date -u +%Y-%m-%dT%H:%M:%SZ) | modus: $([ "$ACTIVE" = 1 ] && echo actief || echo basis)"
  echo "- Uitgesloten paden (fuzzing/injectie): ${PAYMENT_PATH_EXCLUDE:-geen}"
  echo; echo "## Eigen controles: FAIL en WARN"
  grep -E '^\[(FAIL|WARN)\]' "$OUT/findings.txt" 2>/dev/null | sed 's/^/- /' || true
  echo; echo "## ZAP-bevindingen"
  jq -r '.site[]?.alerts[]? | "- \(.riskdesc) | \(.name) (\(.instances|length)x)"' "$OUT/zap-report.json" 2>/dev/null | sort || true
  echo; echo "## Nuclei-bevindingen"
  [ -s "$OUT/nuclei.txt" ] && sed 's/^/- /' "$OUT/nuclei.txt" || echo "- geen bevindingen"
  echo; echo "## retire.js"
  [ -s "$OUT/retire.txt" ] && sed 's/^/    /' "$OUT/retire.txt" | head -n 40 || echo "- geen output"
  echo; echo "## Rapporten"
  ls -1 "$OUT" | sed 's/^/- /'
} > "$OUT/SUMMARY.md"

# ---------------------------------------------------------------- pdf-rapport
banner "AegisProbe-rapport opstellen (AegisProbe-Report-Protected.pdf)"
python3 /opt/report_build.py \
  --out "$OUT" --target "$TARGET" \
  --mode "$([ "$ACTIVE" = 1 ] && echo actief || echo basis)" \
  --skip "$SKIP" --lang "$REPORT_LANG" --exclude "$PAYMENT_PATH_EXCLUDE" \
  --date "$(date -u +%Y-%m-%d)" \
  $( [ "$ACTIVE" = 1 ] && echo --active ) \
  > "$OUT/report_build.log" 2>&1 || echo "rapportgenerator gaf een fout, zie report_build.log"

if [ -s "$OUT/AegisProbe-Report.html" ]; then
  wkhtmltopdf --enable-local-file-access --quiet --page-size A4 \
    --margin-top 30mm --margin-bottom 15mm --margin-left 15mm --margin-right 15mm \
    --header-html "$OUT/AegisProbe-Report-header.html" --header-spacing 6 \
    --footer-center "Pagina [page] van [topage]" --footer-font-size 8 \
    "$OUT/AegisProbe-Report.html" "$OUT/AegisProbe-Report.pdf" >> "$OUT/report_build.log" 2>&1 || true
fi

if [ -s "$OUT/AegisProbe-Report.pdf" ]; then
  GEN_PW=0
  if [ -z "$REPORT_PASSWORD" ]; then
    REPORT_PASSWORD="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
    GEN_PW=1
  fi
  OWNER_PW="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
  if qpdf --encrypt "$REPORT_PASSWORD" "$OWNER_PW" 256 --print=full --modify=none --extract=n \
       -- "$OUT/AegisProbe-Report.pdf" "$OUT/AegisProbe-Report-Protected.pdf" >> "$OUT/report_build.log" 2>&1; then
    rm -f "$OUT/AegisProbe-Report.pdf"
    echo "$REPORT_PASSWORD" > "$OUT/AegisProbe-Report-Password.txt"
    chmod 600 "$OUT/AegisProbe-Report-Password.txt"
    finding INFO "beveiligd PDF-rapport aangemaakt: AegisProbe-Report-Protected.pdf (wachtwoord in AegisProbe-Report-Password.txt)"
  else
    finding WARN "PDF kon niet versleuteld worden (qpdf-fout); AegisProbe-Report.pdf staat onbeveiligd in de resultaten, zie report_build.log"
  fi
else
  finding WARN "PDF-rapport kon niet gegenereerd worden, zie report_build.log en AegisProbe-Report.html (indien aanwezig)"
fi

banner "Klaar. Zie SUMMARY.md en AegisProbe-Report-Protected.pdf"
sed -n '1,40p' "$OUT/SUMMARY.md"
[ -n "${HOST_UID:-}" ] && chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$OUT" 2>/dev/null
exit 0
INNER

  echo ">> Docker-image bouwen (eenmalig, duurt enkele minuten door de extra tools)..."
  docker build --pull -t "$IMAGE" "$B"
}

if [[ $REBUILD -eq 1 ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  build_image
fi

if [[ "$MODE" == "shell" ]]; then
  exec docker run --rm -it --entrypoint bash \
    -v "$RESULTS_ROOT:/results" \
    -v "$CACHE_ROOT/nuclei-templates:/root/.local/nuclei-templates" \
    -v "$CACHE_ROOT/wordlists:/cache/wordlists" \
    -v "$CACHE_ROOT/wpscan:/root/.wpscan" \
    "$IMAGE"
fi

# ------------------------------ bevestiging ----------------------------------
echo "Doel      : $TARGET"
echo "Modus     : $([[ $ACTIVE -eq 1 ]] && echo 'ACTIEF (ZAP full, Wapiti, Nikto, sqlmap, dalfox, feroxbuster, arjun: stuurt payloads naar formulieren/paden)' || echo 'basis (grotendeels passief)')"
echo "Uitgesloten van fuzzing/injectie (PAYMENT_PATH_EXCLUDE): ${PAYMENT_PATH_EXCLUDE:-geen}"
echo "Er wordt na afloop één beveiligd PDF-rapport (AegisProbe-Report-Protected.pdf) aangemaakt, met het AegisProbe-logo op elke pagina."
[[ $RATELIMIT -eq 1 ]] && echo "Rate-limit: 15 foute logins worden verstuurd"
if [[ $YES -ne 1 ]]; then
  read -r -p "Heb je schriftelijke toestemming van de eigenaar voor deze test (en dekt dit NIET de betaalprovider-endpoints)? (ja/nee): " ANS
  [[ "$ANS" == "ja" || "$ANS" == "JA" || "$ANS" == "Ja" ]] || { echo "Afgebroken."; exit 1; }
fi

HOST="$(echo "$TARGET" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
RUN_DIR="$RESULTS_ROOT/${HOST}_$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"

echo ">> Container starten. Resultaten: $RUN_DIR"
docker run --rm --name "aegisprobe-$$" \
  -v "$RUN_DIR:/results" \
  -v "$CACHE_ROOT/nuclei-templates:/root/.local/nuclei-templates" \
  -v "$CACHE_ROOT/wordlists:/cache/wordlists" \
  -v "$CACHE_ROOT/wpscan:/root/.wpscan" \
  -e TARGET="$TARGET" -e ACTIVE="$ACTIVE" -e ZAP_MIN="$ZAP_MIN" \
  -e RATELIMIT="$RATELIMIT" -e SKIP="$SKIP" \
  -e TEST_EMAIL="$TEST_EMAIL" -e TEST_PASSWORD="$TEST_PASSWORD" \
  -e EXTRA_JS="$EXTRA_JS" -e USER_FIELD="${USER_FIELD:-}" -e PASS_FIELD="${PASS_FIELD:-}" \
  -e PAYMENT_PATH_EXCLUDE="$PAYMENT_PATH_EXCLUDE" -e FEROX_WORDLIST_URL="$FEROX_WORDLIST_URL" \
  -e REPORT_LANG="$REPORT_LANG" -e REPORT_PASSWORD="$REPORT_PASSWORD" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  "$IMAGE" 2>&1 | tee "$RUN_DIR/run.log"

echo
echo "Klaar. Open $RUN_DIR/SUMMARY.md voor de technische samenvatting."
if [ -s "$RUN_DIR/AegisProbe-Report-Protected.pdf" ]; then
  echo
  echo "================================================================"
  echo " AegisProbe-rapport (beveiligd, wachtwoord vereist):"
  echo " $RUN_DIR/AegisProbe-Report-Protected.pdf"
  if [ -s "$RUN_DIR/AegisProbe-Report-Password.txt" ]; then
    echo " Wachtwoord: $(cat "$RUN_DIR/AegisProbe-Report-Password.txt")"
    echo " Bewaar dit wachtwoord veilig en deel het via een ANDER kanaal dan het"
    echo " PDF-bestand zelf (bv. telefonisch of een apart bericht) — anders heeft"
    echo " de versleuteling weinig zin."
  fi
  echo "================================================================"
fi
