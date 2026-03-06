/**
 * FISHos Node.js Proxy Server
 * Hardened equivalent of the PHP proxy with full SSRF protection.
 *
 * Usage:
 *   node fishos-proxy.js
 *
 * Requires Node.js 18+ (for built-in fetch).
 * For older Node, run: npm install node-fetch and uncomment the import below.
 */

'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const http   = require('http');
const https  = require('https');
const dns    = require('dns').promises;
const url    = require('url');
const net    = require('net');

// ─── Configuration ────────────────────────────────────────────────────────────
const PORT             = process.env.PORT || 3000;
const ALLOWED_SCHEMES  = ['http:', 'https:'];
const ALLOWED_PORTS    = [80, 443, 8080, 8443];
const PROXY_TIMEOUT_MS = 60_000;          // 60 seconds (LLM APIs can be slow)
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB

// Origins allowed to use this proxy.
// Set to '*' to allow any origin, or list specific origins e.g:
//   ['https://mysite.com', 'http://localhost:8080']
const ALLOWED_ORIGINS  = '*';
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the IP is private, loopback, link-local, or reserved.
 * Covers IPv4 and IPv6.
 */
function isPrivateIP(ip) {
  // Reject loopback
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;

  // Reject IPv6 loopback / unspecified
  if (ip === '::' || ip.startsWith('::ffff:127.')) return true;

  // IPv4 private ranges
  const privateRanges = [
    /^10\./,                          // 10.0.0.0/8
    /^172\.(1[6-9]|2\d|3[01])\./,    // 172.16.0.0/12
    /^192\.168\./,                    // 192.168.0.0/16
    /^127\./,                         // 127.0.0.0/8 (loopback)
    /^169\.254\./,                    // 169.254.0.0/16 (link-local)
    /^0\./,                           // 0.0.0.0/8
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 (CGNAT)
    /^192\.0\.0\./,                   // 192.0.0.0/24 (IETF protocol)
    /^192\.0\.2\./,                   // 192.0.2.0/24 (TEST-NET-1)
    /^198\.51\.100\./,                // 198.51.100.0/24 (TEST-NET-2)
    /^203\.0\.113\./,                 // 203.0.113.0/24 (TEST-NET-3)
    /^(22[4-9]|23\d|240|241|242|243|244|245|246|247|248|249|250|251|252|253|254|255)\./, // 224.0.0.0+ (multicast/reserved)
  ];

  // IPv6 private / link-local
  const privateIPv6 = [
    /^fe[89ab][0-9a-f]:/i,   // link-local fe80::/10
    /^fc/i,                   // unique local fc00::/7
    /^fd/i,                   // unique local fd00::/8
  ];

  if (net.isIPv4(ip)) return privateRanges.some(r => r.test(ip));
  if (net.isIPv6(ip)) return privateIPv6.some(r => r.test(ip));

  return true; // unknown format — block it
}

/**
 * Resolve hostname to IP, check it's public, return the resolved IP.
 * Throws an error string if blocked.
 */
async function resolveAndValidate(hostname) {
  // If already an IP, validate directly
  if (net.isIP(hostname)) {
    if (isPrivateIP(hostname)) throw new Error('Blocked: private/reserved IP address.');
    return hostname;
  }

  let addresses;
  try {
    // dns.lookup resolves using OS resolver (same as curl / gethostbyname)
    const result = await dns.lookup(hostname, { all: true });
    addresses = result.map(r => r.address);
  } catch {
    throw new Error('Could not resolve hostname.');
  }

  if (!addresses || addresses.length === 0) throw new Error('Could not resolve hostname.');

  // Check ALL resolved addresses — block if any is private (DNS rebinding defence)
  for (const ip of addresses) {
    if (isPrivateIP(ip)) throw new Error('Blocked: hostname resolves to private/reserved IP.');
  }

  // Return the first resolved address to use for the pinned request
  return addresses[0];
}

/**
 * Fetch the target URL with the hostname pinned to a pre-resolved IP.
 * This prevents DNS rebinding (TOCTOU) between validation and request.
 */
function fetchWithPinnedDNS(targetUrl, resolvedIP, timeoutMs, originalUrl, method = 'GET', forwardHeaders = {}, body = null) {
  return new Promise((resolve, reject) => {
    const parsed   = new URL(targetUrl);
    const isHttps  = parsed.protocol === 'https:';
    const port     = parsed.port || (isHttps ? 443 : 80);
    const lib      = isHttps ? https : http;

    // Build safe forwarded headers — strip hop-by-hop and host
    const hopByHop = new Set(['host', 'connection', 'keep-alive', 'proxy-authenticate',
      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']);
    const safeForwardedHeaders = {};
    for (const [k, v] of Object.entries(forwardHeaders)) {
      if (!hopByHop.has(k.toLowerCase())) safeForwardedHeaders[k] = v;
    }

    const options = {
      hostname: resolvedIP,
      port,
      path: parsed.pathname + parsed.search,
      method: method,
      headers: {
        'Host':            parsed.hostname,
        'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Cache-Control':   'no-cache',
        'Pragma':          'no-cache',
        'Upgrade-Insecure-Requests': '1',
        ...safeForwardedHeaders,  // forward API keys, content-type, etc.
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
      rejectUnauthorized: isHttps,
      servername: isHttps ? parsed.hostname : undefined,
    };

    const timer = setTimeout(() => {
      req.destroy(new Error('Request timed out.'));
    }, timeoutMs);

    const req = lib.request(options, res => {
      clearTimeout(timer);

      // Handle redirects safely — re-validate the new location before following
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.destroy();
        const location = res.headers['location'];
        if (!location) return reject(new Error('Redirect with no location header.'));

        let redirectUrl;
        try { redirectUrl = new URL(location, originalUrl); }
        catch { return reject(new Error('Invalid redirect URL.')); }

        // Only allow http/https redirects
        if (!['http:', 'https:'].includes(redirectUrl.protocol)) {
          return reject(new Error('Redirect to non-HTTP scheme blocked.'));
        }

        // Re-validate the redirect target IP (prevent redirect to private IP)
        resolveAndValidate(redirectUrl.hostname)
          .then(redirectIP => fetchWithPinnedDNS(redirectUrl.href, redirectIP, timeoutMs, redirectUrl.href, method, forwardHeaders, body))
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode >= 400) {
        // Don't swallow API errors — stream them back so the client can read them
        const errChunks = [];
        res.on('data', c => errChunks.push(c));
        res.on('end', () => resolve({
          body: Buffer.concat(errChunks).toString('utf-8'),
          contentType: res.headers['content-type'] || 'application/json',
          statusCode: res.statusCode,
        }));
        return;
      }

      const chunks = [];
      let totalBytes = 0;

      res.on('data', chunk => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          res.destroy();
          return reject(new Error('Response too large (limit: 5 MB).'));
        }
        chunks.push(chunk);
      });

      res.on('end', () => {
        let body = Buffer.concat(chunks).toString('utf-8');
        const contentType = res.headers['content-type'] || 'text/html';

        // If HTML, rewrite relative URLs so assets (images, CSS, JS) load correctly
        // and strip tags that would break rendering
        if (contentType.includes('text/html')) {
          const base = new URL(originalUrl);
          const origin = base.origin;
          const baseHref = `<base href="${origin}/">`;

          // Inject <base> tag so relative URLs resolve against the original site
          body = body.replace(/<head([^>]*)>/i, `<head$1>${baseHref}`);

          // Strip Content-Security-Policy meta tags (they block inline content)
          body = body.replace(/<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi, '');

          // Rewrite absolute links to route back through this proxy
          // so clicking links stays within FISHos browser
          body = body.replace(/href=["'](https?:\/\/[^"']+)["']/gi, (match, url) => {
            return `href="/proxy?url=${encodeURIComponent(url)}"`;
          });
        }

        resolve({
          body,
          contentType,
          statusCode:  res.statusCode,
        });
      });

      res.on('error', reject);
    });

    req.on('error', err => { clearTimeout(timer); reject(err); });
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Sanitize a Content-Type header value to prevent header injection.
 */
function sanitizeContentType(ct) {
  return ct.replace(/[^\w\/;=\-. ]/g, '').slice(0, 200) || 'text/html';
}

// ─── Request Handler ──────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ── CORS headers — set on every response so fetch() works from any origin ──
  // ALLOWED_ORIGINS is set to '*' by default which permits the local HTML file,
  // hosted pages, and any other origin. Tighten this in production if needed.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, Authorization, x-api-key, anthropic-version, anthropic-dangerous-direct-browser-access');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Only allow GET and POST requests
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method not allowed.');
    return;
  }

  // ── Route: / — simple status page ─────────────────────────────────
  if (pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('FISHos Proxy v4.0 — running.\nUsage: /proxy?url=https://example.com');
    return;
  }

  // ── Route: /proxy ──────────────────────────────────────────────────
  if (pathname === '/proxy') {
    const rawTarget = parsed.query.url;

    if (!rawTarget) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Missing ?url= parameter.');
      return;
    }

    // 1. Parse and validate URL structure
    let targetUrl;
    try {
      targetUrl = new URL(rawTarget);
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Invalid URL.');
      return;
    }

    // 2. Scheme check
    if (!ALLOWED_SCHEMES.includes(targetUrl.protocol)) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Only HTTP/HTTPS allowed.');
      return;
    }

    // 3. Port check
    const port = parseInt(targetUrl.port) || (targetUrl.protocol === 'https:' ? 443 : 80);
    if (!ALLOWED_PORTS.includes(port)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Blocked: port not allowed.');
      return;
    }

    // 4. DNS resolve + private IP check (SSRF protection)
    let resolvedIP;
    try {
      resolvedIP = await resolveAndValidate(targetUrl.hostname);
    } catch (err) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end(err.message);
      return;
    }

    // 5. Collect request body (for POST)
    let requestBody = null;
    if (req.method === 'POST') {
      requestBody = await new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
        req.on('error', reject);
      });
    }

    // Forward relevant request headers (API keys, content-type, etc.)
    const forwardHeaders = {};
    const headersToForward = ['content-type', 'authorization', 'x-api-key',
      'anthropic-version', 'anthropic-dangerous-direct-browser-access'];
    for (const h of headersToForward) {
      if (req.headers[h]) forwardHeaders[h] = req.headers[h];
    }

    // 6. Fetch with pinned DNS (TOCTOU / rebinding fix)
    let result;
    try {
      result = await fetchWithPinnedDNS(rawTarget, resolvedIP, PROXY_TIMEOUT_MS, rawTarget, req.method, forwardHeaders, requestBody);
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Proxy error: ' + err.message);
      return;
    }

    // 6. Send safe response headers + body
    //    Intentionally omit X-Frame-Options and CSP frame-ancestors so the
    //    content can render inside FISHos's browser div.
    const safeContentType = sanitizeContentType(result.contentType);
    res.writeHead(result.statusCode, {
      'Content-Type':           safeContentType + (safeContentType.includes('text') ? '; charset=utf-8' : ''),
      'X-Content-Type-Options': 'nosniff',
      // Never forward cookies from proxied sites
    });
    res.end(result.body);
    return;
  }

  // ── 404 fallback ───────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found.');
});

server.listen(PORT, () => {
  console.log(`FISHos Proxy v4.0 running at http://localhost:${PORT}`);
  console.log(`Proxy endpoint: http://localhost:${PORT}/proxy?url=https://example.com`);
});

// Graceful shutdown
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT',  () => server.close(() => process.exit(0)));