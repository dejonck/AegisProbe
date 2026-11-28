<p align="center">
  <img src="./assets/AegisProbe_Cyber_Falcon_Logo.png" alt="AegisProbe Logo" width="420" />
</p>
<p align="center"><sub>This PNG is only here so the logo renders in this README on GitHub — the script itself does not need it (see §8).</sub></p>

# AegisProbe — Red Team Web Security Toolkit

> **Use only with prior written authorization from the system owner.**
> AegisProbe performs active security testing against web applications.
> Unauthorized use is illegal in most jurisdictions (including the EU
> Cybercrime Directive, the U.S. CFAA, and the UK Computer Misuse Act)
> and can lead to criminal prosecution and civil liability.

AegisProbe is a single, self-contained Bash script (`aegisprobe.sh` — the
AegisProbe logo is baked into the script itself as base64, so there is no
separate asset to lose or forget) that builds one Docker image once, then
runs a battery of free and open-source security tools plus a set of custom
checks against a **login page** — or, with `--domain-scan`, the **entire
website** — of a web shop. At the end of a run it produces **one
password-protected PDF report** (`AegisProbe-Report-Protected.pdf`),
carrying the AegisProbe logo on every page, written for a mixed audience of
management and IT staff, **with the supporting evidence for each finding
included directly in the report** — you should not need to open the raw
technical tool output to understand what was found.

---

## Table of contents

1. [Who is this for?](#1-who-is-this-for)
2. [What's new in this version](#2-whats-new-in-this-version)
3. [What it does — in plain language](#3-what-it-does--in-plain-language)
4. [Why it adds value](#4-why-it-adds-value)
5. [Requirements](#5-requirements)
6. [Installation](#6-installation)
7. [Usage](#7-usage)
8. [The logo (embedded, no external file needed)](#8-the-logo-embedded-no-external-file-needed)
9. [The SSL/TLS score, explained](#9-the-ssltls-score-explained)
10. [Tool isolation & the gitleaks false-positive fix](#10-tool-isolation--the-gitleaks-false-positive-fix)
11. [Security & operational warnings](#11-security--operational-warnings)
12. [Legal considerations](#12-legal-considerations)
13. [Troubleshooting](#13-troubleshooting)
14. [Disclaimer](#14-disclaimer)

---

## 1. Who is this for?

| Audience | What you get |
|---|---|
| **Business owner / manager** | A non-technical, plain-language PDF that explains what was tested, what was found (with the concrete evidence shown inline), how serious each finding is, and what to ask your developer or hosting provider to do. |
| **Developer / IT / hosting** | The same PDF (its evidence and appendix section are written for you too), plus the full raw tool output (ZAP, Nuclei, sqlmap, testssl, …) in the results folder and a technical summary in `SUMMARY.md`, for when you need to dig deeper than the report. |
| **Security professional** | A reproducible, containerized starting point for authorized red-team engagements, including a local, offline SSL Labs-style grade. **It is not a replacement for a full manual penetration test.** |

---

## 2. What's new in this version

- **`--domain-scan`**: the broad scanners (ZAP, Nuclei, Nikto, Wapiti,
  feroxbuster, retire.js) now cover the **entire website/domain**, not just
  the single `--target` page. The invasive, login-specific tests (sqlmap,
  dalfox, arjun) deliberately stay scoped to `--target` — see
  [§3](#3-what-it-does--in-plain-language).
- **Local, offline SSL/TLS score (A+ to F)**, modeled on the Qualys SSL
  Labs methodology but computed entirely from `testssl.sh`'s own output.
  Nothing about your server is sent anywhere — it even works for
  internal/non-public hosts that the real SSL Labs service could never
  reach. See [§9](#9-the-ssltls-score-explained).
- **Evidence embedded directly in the PDF.** sqlmap, dalfox, gitleaks,
  arjun, feroxbuster, the CSP check, OWASP ZAP and retire.js findings now
  carry their concrete proof (the matched parameter, payload, file, line,
  URL, or instance) in the report card itself, labeled "Bewijs" ("Evidence"),
  instead of pointing you to a separate technical file.
- **Fixed a gitleaks false-positive root cause**: `gitleaks` was scanning
  AegisProbe's own intermediate capture files (such as `headers.txt`),
  where it occasionally misidentified a high-entropy value — like a
  Laravel-encrypted `XSRF-TOKEN` cookie — as a leaked "Generic API Key".
  See [§10](#10-tool-isolation--the-gitleaks-false-positive-fix) for the
  full explanation and the fix.
- **The logo is now embedded in the script itself** (base64), so
  `aegisprobe.sh` is a single, self-contained file. `--logo PATH` /
  `LOGO_PATH` can still override it with a different image.
- The CSP check no longer depends on a Python package that, it turns out,
  doesn't actually exist on PyPI under the name earlier versions assumed
  (`csp-evaluator`). It's now a small, dependency-free check built into the
  script itself, with its findings (which specific directives are weak)
  shown as evidence in the report.

---

## 3. What it does — in plain language

1. Builds a Docker image containing ~20 security tools (only once; rebuilds
   only when you pass `--rebuild`).
2. Prepares cached data on your **host machine** (Nuclei templates,
   feroxbuster wordlist, Nikto signatures, sqlmap, WPScan DB) so repeated
   runs are faster and never silently fail because a download was missed.
3. Runs **passive/baseline checks by default** (headers, cookies, form
   fields, HTTPS redirect, exposed paths, JWT structure, CORS,
   clickjacking, a built-in CSP analysis, GraphQL detection, JS library
   audit, HTTP Observatory, SSL/TLS incl. the AegisProbe grade, Nmap, OWASP
   ZAP baseline).
4. With `--active` adds **active scanners**: OWASP ZAP full, Nikto, Wapiti,
   sqlmap, dalfox, feroxbuster, arjun, gitleaks (secrets).
5. With `--domain-scan`, the scanners that are inherently about breadth —
   ZAP, Nuclei, Nikto, Wapiti, feroxbuster, and retire.js's JavaScript
   inventory — point at the whole site (ZAP's and feroxbuster's own
   crawling already does much of this; `--domain-scan` makes it explicit,
   deepens feroxbuster, switches Wapiti to domain scope, and adds a small
   built-in crawl of a handful of internal pages so retire.js and gitleaks
   see JavaScript from more than one page). The login-specific, invasive
   tests (sqlmap, dalfox, arjun) are deliberately **not** widened to the
   whole domain — blasting every page of a live webshop with injection
   payloads is both noisier and riskier than the breadth scan needs to be.
   TLS/SSL and open-port checks (testssl, sslyze, Nmap) are already
   host-wide regardless of this flag.
6. Optionally with `--ratelimit` sends **15 deliberately failed logins** to
   check whether rate limiting / lockout is in place.
7. Consolidates everything into a **single PDF**, with the AegisProbe logo
   on every page, the evidence for each finding inline, and a dedicated
   SSL/TLS score section — then protects it with AES-256 (via `qpdf`) and
   writes the generated password to a separate file
   (`AegisProbe-Report-Password.txt`, `chmod 600`).

### Supported tools

**Baseline (always on unless `--skip`):** OWASP ZAP (baseline), Nuclei,
Nmap, testssl.sh (+ the built-in AegisProbe SSL/TLS score), sslyze,
retire.js, MDN HTTP Observatory, and a set of custom checks (security
headers, cookies, form inspection, HTTPS redirect, HTTP methods, exposed
paths, user enumeration, session regeneration, open redirect, rate
limiting, CORS, clickjacking, JWT structure, a built-in CSP analysis,
GraphQL detection).

**Active (with `--active`):** OWASP ZAP (full), Nikto, Wapiti, sqlmap,
dalfox, feroxbuster, arjun, gitleaks, GraphQL-cop, jwt_tool, WPScan (only
if WordPress is detected).

**Deliberately *not* included:** anything that attacks a payment provider
(Mollie, Stripe, PayPal, Adyen, …). Their terms of service almost always
forbid testing without the provider's own written consent. AegisProbe
enforces this with `PAYMENT_PATH_EXCLUDE` — fuzzing and injection tools
will skip any path matching those keywords, in both single-page and
`--domain-scan` mode.

---

## 4. Why it adds value

- **One command, one report.** You no longer have to stitch together
  ZAP HTML, Nikto text, sqlmap logs and testssl JSON into something a
  non-technical stakeholder can read — and now the report carries the
  evidence itself, so even the technical reader rarely needs to open the
  raw files.
- **Two audiences, one document.** The PDF opens with a management
  summary in plain language, including a one-glance SSL/TLS grade, then a
  technical appendix pointing at the raw artefacts in the same folder for
  anyone who wants to go deeper.
- **Reproducible.** Everything runs inside Docker. The tools, template
  sets and wordlists are version-pinned/cached, so a run today and a run
  next month test the same thing.
- **Safe by default.** Baseline mode is largely passive. Active mode and
  domain-wide scope are both opt-in. Payment paths are excluded
  automatically, in both scopes. Rate-limit testing is opt-in.
- **No third-party data sharing for the SSL grade.** Unlike the public
  SSL Labs service, AegisProbe's score is computed locally from your own
  `testssl.sh` run, so it works for internal, staging, or firewalled hosts
  too, and nothing about your server's configuration leaves your machine.
- **Compliance-friendly.** Findings are mapped to severity (Kritiek /
  Hoog / Gemiddeld / Laag) and each has a "why it matters", "what to do",
  and "evidence" entry — useful when reporting to a board, an auditor, or
  a cyber-insurance questionnaire.

---

## 5. Requirements

### Host machine

- **Linux or macOS** with Bash ≥ 4.4 (the script uses `[[ … ]]`,
  associative arrays and `set -Eeuo pipefail`).
- **Docker** (Engine ≥ 20.10, or Docker Desktop ≥ 4.x). The script only
  needs the `docker` CLI in `PATH`.
- **~6 GB free disk** for the image and the per-run results, plus
  **~500 MB** for the cache directory. A `--domain-scan` run produces more
  crawl/evidence data per run than a single-page scan — budget accordingly
  for long-running or repeated engagements.
- **Outbound internet access** from both host and container for:
  - the Docker registry (`ghcr.io/zaproxy/zaproxy`, Debian mirrors,
    npm, pip, GitHub releases, RubyGems),
  - the target website,
  - the cache refresh endpoints (Nuclei templates, feroxbuster wordlist, …).
- **(Optional)** `chafa` for the ANSI-art banner. If absent, the banner
  falls back to ASCII.
- **(Optional)** `openssl` for generating the PDF password locally (the
  script also generates it inside the container — this is fine for most
  use cases).

### Target website

- A publicly reachable page over HTTPS — a login page for the default
  scope, or any page on the site when combined with `--domain-scan`
  (internal, non-public hosts work fine for the TLS/SSL checks, but the
  website itself still needs to be reachable from wherever the container
  runs).
- **Written authorization from the owner** covering the exact scope
  (domain, subpaths, test window — and explicitly whether the whole domain
  or just one page is in scope if you plan to use `--domain-scan`). This
  is a legal requirement, not a formality — see §12.
- If you want the session and rate-limit tests, a **dedicated test
  account** (`TEST_EMAIL` / `TEST_PASSWORD`). Never use a real customer
  account.
- Confirm in writing that **payment provider endpoints are out of scope**
  (they almost certainly are).

---

## 6. Installation

```bash
git clone https://github.com/<dejonck>/aegisprobe.git
cd aegisprobe
chmod +x aegisprobe.sh
```

That's it — the AegisProbe logo is already embedded in `aegisprobe.sh`,
so there is no separate asset file to place next to it (see
[§8](#8-the-logo-embedded-no-external-file-needed) if you want to use a
different logo).

Build the image once (takes 5–15 minutes depending on your connection):

```bash
./aegisprobe.sh --help      # prints the banner (builds nothing yet)
./aegisprobe.sh -t https://shop.example.com/nl/login --yes
# ↑ first run also triggers the one-time image build
```

---

## 7. Usage

### Quick reference

```bash
./aegisprobe.sh                                       # safe mode, 1 page, mostly passive
./aegisprobe.sh --active                              # + ZAP full, Wapiti, Nikto,
                                                       #   sqlmap, dalfox, feroxbuster, arjun
./aegisprobe.sh --domain-scan --active                # whole website/domain, active mode
./aegisprobe.sh -t https://shop.example.com/nl/login --skip nmap,wapiti,sqlmap
TEST_EMAIL=test@example.com TEST_PASSWORD='...' \
  ./aegisprobe.sh --ratelimit
REPORT_PASSWORD='My-Strong-Password!' ./aegisprobe.sh --active
./aegisprobe.sh --uninstall                           # removes the image
```

### Options

| Flag | Meaning |
|---|---|
| `-t`, `--target URL` | Page to test in depth, e.g. the login page (default: `https://www.example.com/nl/login`) |
| `--active` | Enables active scanners (see §3) |
| `--domain-scan` | Widens the broad scanners (ZAP, Nuclei, Nikto, Wapiti, feroxbuster, retire.js) to the whole website/domain; sqlmap/dalfox/arjun stay scoped to `--target` |
| `--zap-minutes N` | ZAP spider time in minutes (default 3; consider raising this for `--domain-scan`) |
| `--ratelimit` | Send 15 failed logins to test rate limiting |
| `--skip a,b,c` | Skip named steps (`nmap,testssl,sslyze,observatory,retire,custom,nuclei,zap,nikto,wapiti,sqlmap,dalfox,feroxbuster,arjun,cors,clickjack,jwt,cspeval,secrets,graphql,wpscan`) |
| `--logo PATH` | Use this PNG instead of the logo embedded in the script |
| `--rebuild` | Rebuild the image (newest tools/templates/logo) |
| `--shell` | Open an interactive shell in the container |
| `--uninstall` | Remove the Docker image (results and cache remain) |
| `-y`, `--yes` | Skip the consent prompt |
| `-h`, `--help` | Show help |

### Environment variables

| Variable | Purpose |
|---|---|
| `TEST_EMAIL`, `TEST_PASSWORD` | Dedicated test account (enables session-regeneration & user-enumeration tests) |
| `EXTRA_JS` | Extra JavaScript URLs to audit with retire.js |
| `USER_FIELD`, `PASS_FIELD` | Override form field names if auto-detection fails |
| `PAYMENT_PATH_EXCLUDE` | Comma-separated keywords of paths never to fuzz (default: `checkout,pay,payment,mollie,stripe,paypal,bancontact,ideal,order/confirm,cart`) |
| `FEROX_WORDLIST_URL` | Override the feroxbuster wordlist |
| `CACHE_ROOT` | Where the on-host cache lives (default: `./aegisprobe-cache`) |
| `LOGO_PATH` | Use a different logo file than the one embedded in the script (same as `--logo`) |
| `DOMAIN_SCAN` | `1` = same as `--domain-scan` |
| `REPORT_LANG` | Report language (`nl` only at present) |
| `REPORT_PASSWORD` | Fixed PDF password; if unset, a random one is generated |

### What you end up with

Every run creates a timestamped folder:

```
aegisprobe-results/<host>_<YYYYMMDD-HHMMSS>/
├── AegisProbe-Report-Protected.pdf     ← the deliverable (AES-256, logo on every page)
├── AegisProbe-Report-Password.txt      ← the PDF password (chmod 600)
├── SUMMARY.md                          ← quick technical overview
├── findings.txt                        ← custom-check findings (incl. scan scope, CSP analysis)
├── login.html, headers.txt, jar.txt, crawl/   ← AegisProbe's own capture files
├── js/                                 ← JavaScript downloaded from the site itself (gitleaks' only scope)
├── zap-report.{html,json,md}
├── nuclei.txt
├── nikto.txt, wapiti/, sqlmap/, dalfox.json
├── feroxbuster.filtered.txt
├── testssl.html, testssl.json, sslyze.json
├── nmap.nmap
├── retire.txt, retire.json
├── gitleaks.json, arjun.json
└── run.log                             ← full container console log
```

> **The password file is written with `chmod 600` and lives *next to the
> PDF*.** Share it via a different channel (phone call, an internal
> password manager, or a signed message) — sending both in the same
> e-mail defeats the encryption.

---

## 8. The logo (embedded, no external file needed)

`aegisprobe.sh` carries the AegisProbe logo baked in as a base64-encoded
PNG (the `EMBEDDED_LOGO_B64` heredoc near the top of the script). You do
**not** need to place a `.png` file next to the script for the branded
report — the script is self-contained.

The PDF is generated in three steps:

1. `report_build.py` builds `AegisProbe-Report.html` (cover page + body)
   and a separate `AegisProbe-Report-header.html` (the running header).
2. `wkhtmltopdf` renders the body and, because of `--header-html …`, also
   repeats the header on **every page**. The logo sits at the top of that
   header bar, next to the "AegisProbe" wordmark.
3. `qpdf --encrypt` produces `AegisProbe-Report-Protected.pdf` with
   AES-256. The embedded image survives encryption.

**Using a different logo:** pass `--logo PATH` or set `LOGO_PATH=/path/to/
logo.png`. If that file exists, it's used instead of the embedded one for
that build; if it doesn't, AegisProbe warns and falls back to the embedded
logo automatically — nothing breaks either way.

**Re-embedding a new logo yourself** (e.g. after a rebrand): generate the
base64 and replace the content between the `LOGO_B64_EOF` markers near the
top of `aegisprobe.sh`:

```bash
base64 your-new-logo.png > logo.b64
# then paste logo.b64's content between the two LOGO_B64_EOF lines
```

Keep the source image reasonably small (the shipped logo is resized to
700 px wide) so the script stays a manageable size and diff-friendly in
Git.

---

## 9. The SSL/TLS score, explained

AegisProbe computes a single letter grade (A+ down to F) for the target's
TLS/SSL configuration, in the same spirit as the well-known Qualys SSL
Labs test — but entirely from your own `testssl.sh` run, with **no data
sent to Qualys or anyone else**. This also means it works against internal
or firewalled hosts that the public SSL Labs service could never reach.

What it checks (each one can cap the maximum achievable grade):

| Factor | Impact on grade |
|---|---|
| SSLv2 / SSLv3 still offered | capped at **F** |
| No TLS 1.2 or 1.3 available | capped at **F** |
| A known attack applies (Heartbleed, POODLE, FREAK, DROWN, ROBOT, LOGJAM, SWEET32, BEAST, Lucky13, …) | capped at **F** |
| Certificate problem (expired, untrusted chain, hostname mismatch) | capped at **F** |
| RC4 ciphers still supported | capped at **C** |
| TLS 1.0 or 1.1 still offered (alongside 1.2/1.3) | capped at **B** |
| Insufficient forward secrecy | capped at **B** |
| No HSTS header, or HSTS with a too-short `max-age` | capped at **A-** |
| None of the above | **A** or **A+** |

Each finding that lowered the grade is listed as a plain-language reason
directly under the score in the PDF. If `testssl.sh` didn't produce usable
data (e.g. it was skipped or couldn't reach the host), the report says so
honestly instead of guessing a grade.

**This is an approximation, not an official SSL Labs score** — Qualys'
real methodology is proprietary and more detailed. Treat the AegisProbe
grade as a fast, private, repeatable indicator, and use `testssl.html` in
the results folder (or the real SSL Labs test, for public hosts) for the
full cipher-by-cipher detail.

---

## 10. Tool isolation & the gitleaks false-positive fix

Every tool AegisProbe runs writes to its own, uniquely named output
file(s), and tools run strictly one at a time — never in parallel, never
sharing a working directory.

**The one place this previously broke down:** `gitleaks` (the secrets
scanner) was pointed at the *entire* results folder (`$OUT`) instead of
just the website's own downloaded JavaScript. That folder also contains
AegisProbe's own intermediate capture files — `headers.txt`, cookie jars,
`login.html` — which legitimately contain high-entropy, Base64-looking
values such as session tokens and Laravel's encrypted `XSRF-TOKEN` cookie.
Gitleaks' generic "Generic API Key" rule, which flags any sufficiently
random-looking string, occasionally matched one of those and reported it
as a leaked credential — a false positive, since an encrypted CSRF cookie
is not a secret at all, let alone one belonging to the server operator.

**The fix**, now in `secrets_scan()`:

1. `--source` is hard-limited to `$OUT/js` — the directory that holds
   only the JavaScript files AegisProbe downloaded **from the website
   itself** (via `retire.js`'s own crawl). AegisProbe's own capture files
   are never handed to gitleaks, so this class of false positive cannot
   occur anymore, by construction.
2. A small allowlist (`/opt/gitleaks.toml`, baked into the image) adds a
   second, defense-in-depth layer: it recognizes the Laravel encrypted-
   cookie pattern (`eyJpdiI6…`) and common session/XSRF cookie names, and
   explicitly excludes AegisProbe's own file names, in case a future
   change ever widens the scan surface again.
3. `--redact` is now passed to gitleaks, so even a genuine finding never
   has the actual secret value written to `gitleaks.json` or the PDF —
   only the file, line, and rule that matched, which is enough evidence to
   locate and fix the leak without further spreading it.
4. The report now shows that evidence (file + line + rule) inline, so you
   don't need to open `gitleaks.json` to understand a finding.

---

## 11. Security & operational warnings

> **AegisProbe sends real traffic to a real website.** Even in baseline
> mode it reads cookies, follows forms, and probes for exposed paths.
> In active mode it will submit payloads that look like attacks. In
> `--domain-scan` mode, that traffic is spread across more of the site.
> Treat every run as a production-impacting change window unless you are
> testing a staging clone.

- **Never point it at a site you don't own or aren't authorized to test.**
- **Never test payment provider endpoints** (Mollie, Stripe, PayPal,
  Adyen, Buckaroo, …). Their terms forbid it. If you *do* need to test
  them, get the provider's own written approval first — this applies in
  both single-page and `--domain-scan` mode.
- **Do not use `--active` or `--domain-scan` against production without a
  change window.** sqlmap, dalfox and feroxbuster can trigger WAF bans,
  generate large logs, and (rarely) cause timeouts on fragile back-ends;
  `--domain-scan` means more pages are touched, for longer.
- **Do not use real customer accounts.** Use a dedicated test account.
- **`--ratelimit` sends 15 failed logins.** Some providers auto-lock
  accounts after N failures. Use a throwaway test address, not a real
  customer.
- **Treat raw outputs as confidential.** `zap-report.json`, `sqlmap.log`
  may contain PII, tokens, or pre-auth cookies. `gitleaks.json` is
  redacted by default, but other raw files are not. The PDF is encrypted;
  the raw files in the results folder are **not**.
- **Result files inherit your user's UID/GID** (the container chowns
  `/results` back to `HOST_UID:HOST_GID`). Keep the results folder off
  shared volumes unless you understand the exposure.
- **Cache directory** (`./aegisprobe-cache`) contains the Nuclei
  template DB (~1 GB), a wordlist, and the WPScan DB. It is safe to
  delete; it is not encrypted.
- **Container image** is rebuilt from floating tags (`zaproxy:stable`,
  npm, pip, GitHub releases). Pin digests if you need reproducible
  audits for compliance.
- **The AegisProbe SSL/TLS grade is an approximation** (see §9) —
  don't present it as an official SSL Labs certification to a client or
  auditor.

---

## 12. Legal considerations

### Before you run — checklist

- [ ] **Written authorization** from the domain owner. E-mail is
      usually enough if it explicitly says "I authorize … to perform
      security testing on … from … to …". Keep it archived.
- [ ] **Scope document** listing the exact domains/subpaths in scope,
      whether `--domain-scan` is authorized or only a single page, and
      the test window.
- [ ] **Contact point** to notify if the test causes an incident.
- [ ] **Payment provider exclusion** confirmed in writing (or the
      provider's own pentest-approval on file).
- [ ] **GDPR/data-processing** angle: AegisProbe does not exfiltrate
      customer data, but raw outputs can contain pre-auth cookies and
      form tokens. Store them on encrypted media and delete when done.
- [ ] **Insurance / contract**: check whether your general liability
      or cyber-insurance policy requires notification before a pentest.

### What can happen if you skip these steps

| Jurisdiction | Instrument | Typical consequence |
|---|---|---|
| EU | Directive 2013/40/EU (Cybercrime), implemented nationally | Criminal offense for unauthorized access / interference; fines, imprisonment, civil damages. |
| Netherlands | Art. 138ab Sr (computervredebreuk) | Up to 4 years imprisonment or a fine of the 4th category. |
| Belgium | Art. 550bis Sw. (informaticabedrog) | Up to 5 years imprisonment. |
| U.S. | Computer Fraud and Abuse Act (18 U.S.C. § 1030) | Civil liability and, in aggravated cases, criminal charges. |
| UK | Computer Misuse Act 1990 | Up to 10 years imprisonment. |

Even with authorization, exceeding the agreed **scope** (a different
subdomain, a different port, a payment endpoint, or running
`--domain-scan` when only one page was approved) can nullify the
authorization. AegisProbe's `PAYMENT_PATH_EXCLUDE` is there to reduce
that risk automatically — **do not** set it to empty unless your
authorization explicitly covers payment endpoints **and** the provider
itself has approved. Likewise, only use `--domain-scan` when your written
authorization actually covers the whole domain.

### If an incident occurs during a run

1. Stop the run (`Ctrl-C`).
2. Notify the contact point in your scope document immediately.
3. Preserve `run.log`, the exact command line, and the timestamp.
4. Do not delete results until the incident is closed — they are your
   evidence of intent and scope.

---

## 13. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Docker is niet geïnstalleerd` | Install Docker; make sure `docker` is on `PATH`. |
| Build fails at `ghcr.io/zaproxy/zaproxy` | Docker Hub / GHCR outage; retry, or pin a digest. |
| `nuclei-templates konden niet bijgewerkt worden` | The run still proceeds with the cached templates. Re-run with internet to refresh. |
| PDF logo looks wrong / outdated | You passed `--logo`/`LOGO_PATH` pointing at an old file, or edited the embedded blob incorrectly. Run with `--rebuild` after fixing it. |
| PDF is not produced | Check `report_build.log`. Usually a missing `wkhtmltopdf` dependency inside the image; rebuild with `--rebuild`. |
| `qpdf` failure → unprotected PDF remains | The script warns and keeps `AegisProbe-Report.pdf`. Encrypt manually with `qpdf --encrypt …`. |
| Permission denied on results | Results are chowned to `HOST_UID:HOST_GID`. On SELinux hosts, add `:Z` to the `-v` mounts. |
| `arjun`/`sqlmap` skipped | The target path matched `PAYMENT_PATH_EXCLUDE`. Override with `PAYMENT_PATH_EXCLUDE=""` **only** if your authorization covers it. |
| SSL/TLS score says "insufficient data" | `testssl` was skipped (`--skip testssl`) or couldn't reach the host. Re-run without skipping it. |
| gitleaks reports a finding from a legitimate third-party script | Check the file/line in the evidence; add a path or regex exception to `/opt/gitleaks.toml` (rebuild the image afterwards) if it's a confirmed false positive specific to your site. |

---

## 14. Disclaimer

AegisProbe is provided **as-is, without warranty of any kind**. The
authors accept no liability for damage, data loss, downtime, legal
consequences, or contractual violations resulting from its use. You are
solely responsible for obtaining the necessary authorization and for
complying with all applicable laws, regulations, and third-party terms
of service. **If you are not sure whether you are allowed to test a
target — or whether your authorization covers a full-domain scan — you
are not allowed to run it.**
