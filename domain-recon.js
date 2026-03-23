#!/usr/bin/env node

// ═══════════════════════════════════════════════════════════
//  domain-recon.js — OSINT Domain Reconnaissance Tool
//  Zero dependencies. Node.js only. No API keys required.
//
//  Usage: node domain-recon.js <domain> [--json] [--no-color]
//
//  Author: A.Shultz (@besmertn1k)
//  License: MIT
// ═══════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const tls = require('tls');
const { URL } = require('url');

// ── Args ──
const args = process.argv.slice(2);
const domain = args.find(a => !a.startsWith('--'));
const jsonMode = args.includes('--json');
const noColor = args.includes('--no-color') || jsonMode;

if (!domain) {
  console.log(`
  domain-recon — OSINT Domain Reconnaissance

  Usage:
    node domain-recon.js <domain>              Interactive report
    node domain-recon.js <domain> --json       JSON output
    node domain-recon.js <domain> --no-color   No ANSI colors

  Examples:
    node domain-recon.js github.com
    node domain-recon.js example.com --json > report.json
  `);
  process.exit(1);
}

// ── Colors ──
const c = noColor
  ? { r: '', g: '', c: '', y: '', b: '', w: '', dim: '' }
  : { r: '\x1b[31m', g: '\x1b[32m', c: '\x1b[36m', y: '\x1b[33m', b: '\x1b[1m', w: '\x1b[0m', dim: '\x1b[2m' };

// ── JSON collector ──
const report = { domain, timestamp: new Date().toISOString(), sections: {} };

function section(name, data) {
  report.sections[name] = data;
  if (jsonMode) return;

  console.log(`\n${c.r}┌─${c.w} ${c.b}${name}${c.w}`);
  if (typeof data === 'string') {
    data.split('\n').forEach(l => console.log(`${c.r}│${c.w}  ${l}`));
  } else if (Array.isArray(data)) {
    data.forEach(l => console.log(`${c.r}│${c.w}  ${l}`));
  } else if (typeof data === 'object') {
    Object.entries(data).forEach(([k, v]) => {
      const val = Array.isArray(v) ? v.join(', ') : String(v);
      console.log(`${c.r}│${c.w}  ${c.dim}${k}${c.w}  ${val}`);
    });
  }
  console.log(`${c.r}└──${c.w}`);
}

// ── HTTP helpers ──
function fetch(url, timeout = 8000) {
  return new Promise((resolve) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'DomainRecon/1.0' }, timeout }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve(body); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

function headRequest(target) {
  return new Promise((resolve) => {
    const req = https.request(`https://${target}`, { method: 'GET', timeout: 8000 }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function getSSLCert(host) {
  return new Promise((resolve) => {
    const sock = tls.connect(443, host, { servername: host, timeout: 5000 }, () => {
      const cert = sock.getPeerCertificate();
      sock.destroy();
      resolve(cert);
    });
    sock.on('error', () => resolve(null));
    sock.on('timeout', () => { sock.destroy(); resolve(null); });
  });
}

// ── Security headers config ──
const SECURITY_HEADERS = [
  { name: 'strict-transport-security', label: 'Strict-Transport-Security', critical: true },
  { name: 'content-security-policy', label: 'Content-Security-Policy', critical: true },
  { name: 'x-frame-options', label: 'X-Frame-Options', critical: true },
  { name: 'x-content-type-options', label: 'X-Content-Type-Options', critical: true },
  { name: 'referrer-policy', label: 'Referrer-Policy', critical: false },
  { name: 'permissions-policy', label: 'Permissions-Policy', critical: false },
  { name: 'cross-origin-opener-policy', label: 'Cross-Origin-Opener-Policy', critical: false },
  { name: 'cross-origin-embedder-policy', label: 'Cross-Origin-Embedder-Policy', critical: false },
  { name: 'x-xss-protection', label: 'X-XSS-Protection', critical: false },
];

// ── Tech patterns ──
const TECH_RULES = [
  { header: 'server', match: /nginx/i, tag: 'Nginx' },
  { header: 'server', match: /apache/i, tag: 'Apache' },
  { header: 'server', match: /cloudflare/i, tag: 'Cloudflare' },
  { header: 'server', match: /microsoft-iis/i, tag: 'IIS' },
  { header: 'server', match: /litespeed/i, tag: 'LiteSpeed' },
  { header: 'server', match: /caddy/i, tag: 'Caddy' },
  { header: 'server', match: /openresty/i, tag: 'OpenResty' },
  { header: 'x-powered-by', match: /express/i, tag: 'Express.js' },
  { header: 'x-powered-by', match: /php/i, tag: 'PHP' },
  { header: 'x-powered-by', match: /asp\.net/i, tag: 'ASP.NET' },
  { header: 'x-powered-by', match: /next/i, tag: 'Next.js' },
  { header: 'cf-ray', match: /.+/, tag: 'Cloudflare CDN' },
  { header: 'x-vercel-id', match: /.+/, tag: 'Vercel' },
  { header: 'x-amz-cf-id', match: /.+/, tag: 'AWS CloudFront' },
  { header: 'x-github-request-id', match: /.+/, tag: 'GitHub Pages' },
  { header: 'alt-svc', match: /h3/i, tag: 'HTTP/3' },
];

// ═══════════════════════════════════════
//  Main scan
// ═══════════════════════════════════════
(async () => {
  const start = Date.now();

  if (!jsonMode) {
    console.log(`\n${c.r}╔═══════════════════════════════════════════╗${c.w}`);
    console.log(`${c.r}║${c.w}  ${c.b}DOMAIN RECON${c.w}  ${c.c}${domain}${c.w}`);
    console.log(`${c.r}╚═══════════════════════════════════════════╝${c.w}`);
  }

  // ── 1. DNS Records ──
  const dnsRecords = {};
  for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']) {
    try {
      const result = await dns.resolve(domain, type);
      if (type === 'MX') {
        dnsRecords[type] = result.map(r => `${r.exchange} (priority: ${r.priority})`);
      } else if (type === 'SOA') {
        dnsRecords[type] = [`${result.nsname} | ${result.hostmaster} | serial: ${result.serial}`];
      } else {
        dnsRecords[type] = result;
      }
    } catch {
      // Record type not found — skip silently
    }
  }
  section('DNS Records', dnsRecords);

  // ── 2. IP + Reverse DNS ──
  const ip = dnsRecords.A?.[0];
  if (ip) {
    let rdns = 'N/A';
    try { rdns = (await dns.reverse(ip)).join(', '); } catch {}
    section('IP Address', { 'IPv4': ip, 'Reverse DNS': rdns, 'IPv6': dnsRecords.AAAA?.[0] || 'N/A' });
  }

  // ── 3. WHOIS ──
  const whoisData = await fetch(`https://rdap.org/domain/${domain}`);
  if (whoisData && whoisData.events) {
    const events = {};
    whoisData.events.forEach(e => { events[e.eventAction] = e.eventDate; });
    const registrar = whoisData.entities?.find(e => e.roles?.includes('registrar'));
    section('WHOIS', {
      'Registrar': registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || whoisData.entities?.[0]?.handle || 'N/A',
      'Created': events.registration || 'N/A',
      'Updated': events['last changed'] || 'N/A',
      'Expires': events.expiration || 'N/A',
      'Status': (whoisData.status || []).join(', '),
    });
  }

  // ── 4. SSL Certificate ──
  const cert = await getSSLCert(domain);
  if (cert && cert.subject) {
    section('SSL Certificate', {
      'Subject': cert.subject.CN || 'N/A',
      'Issuer': cert.issuer?.O || cert.issuer?.CN || 'N/A',
      'Valid From': cert.valid_from,
      'Valid To': cert.valid_to,
      'Serial': cert.serialNumber,
      'SANs': (cert.subjectaltname || '').replace(/DNS:/g, '').split(', ').slice(0, 10).join(', '),
    });
  }

  // ── 5. HTTP Headers + Security Audit ──
  const response = await headRequest(domain);
  if (response) {
    const h = response.headers;

    section('HTTP Response', {
      'Status': response.status,
      'Server': h['server'] || 'Hidden',
      'X-Powered-By': h['x-powered-by'] || 'Hidden',
      'Content-Type': h['content-type'] || 'N/A',
    });

    // Security headers check
    const present = [];
    const missing = [];
    SECURITY_HEADERS.forEach(sh => {
      if (h[sh.name]) {
        present.push(`${c.g}✓${c.w} ${sh.label}  ${c.dim}${(h[sh.name] || '').substring(0, 60)}${c.w}`);
      } else {
        const severity = sh.critical ? `${c.r}✗ MISSING` : `${c.y}○ not set`;
        missing.push(`${severity}${c.w} ${sh.label}`);
      }
    });
    section(`Security Headers (${SECURITY_HEADERS.filter(sh => h[sh.name]).length}/${SECURITY_HEADERS.length})`, [...present, ...missing]);

    // Tech detection
    const techs = new Set();
    TECH_RULES.forEach(rule => {
      const val = h[rule.header];
      if (val && rule.match.test(val)) techs.add(rule.tag);
    });
    if (techs.size) section('Technologies Detected', [...techs]);
  }

  // ── 6. Subdomains via Certificate Transparency ──
  const crtData = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
  if (Array.isArray(crtData) && crtData.length) {
    const subs = [...new Set(
      crtData.map(e => e.name_value).flatMap(n => n.split('\n'))
    )].filter(s => s.endsWith(domain) && s !== domain && !s.includes('*')).sort();

    const display = subs.slice(0, 30);
    if (subs.length > 30) display.push(`... and ${subs.length - 30} more`);
    section(`Subdomains — crt.sh (${subs.length} found)`, display);
  }

  // ── 7. Open Ports ──
  const portsRaw = await fetch(`https://api.hackertarget.com/nmap/?q=${domain}`);
  if (portsRaw && typeof portsRaw === 'string' && !portsRaw.includes('error') && !portsRaw.includes('API count')) {
    const portLines = portsRaw.trim().split('\n').filter(l => l.includes('/tcp') || l.includes('/udp'));
    if (portLines.length) {
      section('Open Ports', portLines);
    }
  }

  // ── Done ──
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  report.elapsed_seconds = parseFloat(elapsed);

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n${c.dim}Completed in ${elapsed}s${c.w}`);
    console.log(`${c.r}═══════════════════════════════════════════${c.w}\n`);
  }
})();
