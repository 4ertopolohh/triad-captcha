import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const temporaryDirectory = mkdtempSync(join(tmpdir(), 'triadcaptcha-browser-'));
const keyPath = join(temporaryDirectory, 'key.pem');
const certificatePath = join(temporaryDirectory, 'certificate.pem');
execFileSync('openssl', [
  'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', keyPath,
  '-out', certificatePath,
  '-days', '1',
  '-subj', '/CN=triad.test',
  '-addext', 'subjectAltName=DNS:*.triad.test,DNS:*.other.test,IP:127.0.0.1',
], { stdio: 'ignore' });

const allowedOrigins = new Set([
  'https://app.triad.test:9443',
  'https://trusted.other.test:9443',
]);
const counters = { business: 0, sink: 0 };

function corsHeaders(origin) {
  return allowedOrigins.has(origin)
    ? {
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type, X-TriadCAPTCHA-Site-Key',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Origin': origin,
        Vary: 'Origin',
      }
    : {};
}

const server = createServer(
  {
    key: readFileSync(keyPath),
    cert: readFileSync(certificatePath),
  },
  (request, response) => {
    const url = new URL(request.url ?? '/', 'https://api.triad.test:9443');
    const origin = request.headers.origin ?? '';
    if (url.pathname === '/health') {
      response.writeHead(200).end('ok');
      return;
    }
    if (url.pathname === '/app') {
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'none'; connect-src https://api.triad.test:9443",
      }).end('<!doctype html><title>browser contract</title>');
      return;
    }
    if (url.pathname === '/set-cookie') {
      const sameSite = url.searchParams.get('mode') === 'none' ? 'None' : 'Lax';
      response.writeHead(200, {
        'Set-Cookie': `triad_context=context; Domain=.triad.test; Path=/; HttpOnly; Secure; SameSite=${sameSite}`,
      }).end('cookie set');
      return;
    }
    if (url.pathname === '/stats') {
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(counters));
      return;
    }
    if (url.pathname === '/reset') {
      counters.business = 0;
      counters.sink = 0;
      response.writeHead(204).end();
      return;
    }
    if (url.pathname === '/redirect') {
      response.writeHead(302, {
        ...corsHeaders(origin),
        Location: 'https://untrusted.other.test:9443/sink',
      }).end();
      return;
    }
    if (url.pathname === '/sink') {
      counters.sink += 1;
      response.writeHead(200, { 'Content-Type': 'application/json' }).end('{"ok":true}');
      return;
    }
    if (url.pathname === '/business' && request.method === 'OPTIONS') {
      response.writeHead(204, corsHeaders(origin)).end();
      return;
    }
    if (url.pathname === '/business' && request.method === 'POST') {
      const hasContext = /(?:^|;\s*)triad_context=context(?:;|$)/u.test(
        request.headers.cookie ?? '',
      );
      if (!allowedOrigins.has(origin) || !hasContext) {
        response.writeHead(403, {
          ...corsHeaders(origin),
          'Content-Type': 'application/json',
        }).end('{"ok":false}');
        return;
      }
      counters.business += 1;
      response.writeHead(200, {
        ...corsHeaders(origin),
        'Content-Type': 'application/json',
      }).end('{"ok":true}');
      return;
    }
    response.writeHead(404).end('not found');
  },
);

server.listen(9443, '0.0.0.0');

function shutdown() {
  server.close(() => {
    rmSync(temporaryDirectory, { recursive: true, force: true });
    process.exit(0);
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
