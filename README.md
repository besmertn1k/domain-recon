<div align="center">

# 🔍 domain-recon

**OSINT domain reconnaissance in a single file. Zero dependencies.**

[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-E01030.svg)](LICENSE)
[![No Dependencies](https://img.shields.io/badge/Dependencies-0-333.svg)]()

</div>

---

## What is this?

A single-file Node.js script that performs passive reconnaissance on any domain using only **free public APIs** and built-in modules. No API keys, no packages to install, no configuration.

Run it against any domain and get a full report in seconds:

```
node domain-recon.js github.com
```

---

## What it finds

| Module | Source | Data |
|--------|--------|------|
| **DNS Records** | Node.js `dns` | A, AAAA, MX, NS, TXT, CNAME, SOA |
| **IP & Reverse DNS** | Node.js `dns` | IPv4, IPv6, PTR records |
| **WHOIS** | rdap.org | Registrar, created/updated/expires, status |
| **SSL Certificate** | Node.js `tls` | Issuer, validity, SANs |
| **HTTP Headers** | Direct request | Server, X-Powered-By, Content-Type |
| **Security Audit** | Direct request | 9 security headers with severity |
| **Tech Detection** | Header analysis | Nginx, Cloudflare, Vercel, PHP, Next.js, etc. |
| **Subdomains** | crt.sh | Certificate Transparency logs |
| **Open Ports** | HackerTarget | nmap scan via public API |

---

## Installation

No installation needed. Just clone and run:

```bash
git clone https://github.com/besmertn1k/domain-recon.git
cd domain-recon
node domain-recon.js example.com
```

Requirements: **Node.js 18+** (uses built-in `dns.promises`)

---

## Usage

### Interactive report (colored terminal output)

```bash
node domain-recon.js github.com
```

### JSON output (pipe to file or another tool)

```bash
node domain-recon.js github.com --json > report.json
```

### No colors (for logging or piping)

```bash
node domain-recon.js github.com --no-color
```

---

## Example output

```
╔═══════════════════════════════════════════╗
║  DOMAIN RECON  github.com                 ║
╚═══════════════════════════════════════════╝

┌─ DNS Records
│  A        140.82.121.4
│  MX       alt3.aspmx.l.google.com (priority: 10)
│  NS       dns1.p08.nsone.net, dns2.p08.nsone.net
│  TXT      v=spf1 ip4:192.30.252.0/22 ...
└──

┌─ SSL Certificate
│  Subject   github.com
│  Issuer    DigiCert Inc
│  Valid To  2026-03-15T23:59:59.000Z
│  SANs      github.com, www.github.com
└──

┌─ Security Headers (7/9)
│  ✓ Strict-Transport-Security  max-age=31536000; includeSubdomains
│  ✓ Content-Security-Policy    default-src 'none'; base-uri 'self' ...
│  ✓ X-Frame-Options            DENY
│  ✓ X-Content-Type-Options     nosniff
│  ✓ Referrer-Policy            origin-when-cross-origin
│  ✗ MISSING Permissions-Policy
│  ○ not set Cross-Origin-Embedder-Policy
└──

┌─ Subdomains — crt.sh (142 found)
│  api.github.com
│  docs.github.com
│  education.github.com
│  gist.github.com
│  ... and 138 more
└──
```

---

## How it works

The script uses only **passive reconnaissance** — it never touches the target server with anything beyond a single HTTPS request and standard DNS queries.

```
┌─────────────────────────────────────────────────────┐
│  domain-recon.js                                    │
│                                                     │
│  1. DNS resolve  →  Node.js dns module (local)      │
│  2. WHOIS        →  rdap.org public API             │
│  3. SSL cert     →  TLS handshake to port 443       │
│  4. HTTP headers →  Single GET request              │
│  5. Subdomains   →  crt.sh (Certificate Transparency│
│  6. Port scan    →  api.hackertarget.com            │
│                                                     │
│  No API keys. No auth. All public data.             │
└─────────────────────────────────────────────────────┘
```

### Data sources

| Source | What it provides | Rate limit |
|--------|-----------------|------------|
| **rdap.org** | WHOIS / registration data | ~1000/day |
| **crt.sh** | Certificate Transparency logs | No hard limit |
| **api.hackertarget.com** | Port scanning (nmap) | 100/day (free) |
| **DNS** | All DNS records | Unlimited |
| **Target server** | Headers + SSL cert | 1 request |

---

## Security headers explained

The script checks for 9 security headers and rates them by severity:

| Header | Why it matters |
|--------|---------------|
| `Strict-Transport-Security` | Forces HTTPS, prevents downgrade attacks |
| `Content-Security-Policy` | Prevents XSS, injection, clickjacking |
| `X-Frame-Options` | Blocks embedding in iframes (clickjacking) |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `Referrer-Policy` | Controls what URL info is shared |
| `Permissions-Policy` | Restricts browser APIs (camera, mic, etc.) |
| `Cross-Origin-Opener-Policy` | Isolates browsing context |
| `Cross-Origin-Embedder-Policy` | Controls cross-origin embedding |
| `X-XSS-Protection` | Legacy XSS filter (mostly deprecated) |

---

## How to defend against this scan

If you found issues on your own domain, here's how to fix them:

```nginx
# Nginx — hide server info
server_tokens off;
more_clear_headers 'Server';
more_clear_headers 'X-Powered-By';

# Add security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Only scan domains you own or have explicit permission to test. The author is not responsible for misuse.

---

## License

[MIT](LICENSE)

---

<div align="center">

**Made by [A.Shultz](https://t.me/besmertn1k)**

</div>
