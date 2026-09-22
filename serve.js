// serve.js — lightweight dev server (Node.js built-ins only, no dependencies)
// Run: node serve.js
// Then open: http://localhost:3000

import http from 'http';
import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.ico':  'image/x-icon',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
};

// Security: only serve files within the project directory
const ROOT = path.resolve(__dirname);

http.createServer((req, res) => {
  // Only allow GET
  if (req.method !== 'GET') {
    res.writeHead(405); res.end('Method Not Allowed'); return;
  }

  // Sanitize URL — strip query/hash, prevent traversal
  let urlPath = req.url.split('?')[0].split('#')[0];
  urlPath = decodeURIComponent(urlPath).replace(/\\/g, '/');

  if (urlPath === '/') urlPath = '/index.html';

  // Resolve to absolute path
  const resolved = path.resolve(ROOT, '.' + urlPath);

  // Ensure the resolved path is strictly inside ROOT (prevent path traversal)
  if (!resolved.startsWith(ROOT + path.sep) && resolved !== ROOT) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  const ext = path.extname(resolved).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(resolved, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') { res.writeHead(404); res.end('Not Found'); }
      else { res.writeHead(500); res.end('Internal Server Error'); }
      return;
    }
    // Security headers
    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; worker-src 'self'; object-src 'none';",
      'Cache-Control': 'no-store',
    });
    res.end(data);
  });
}).listen(PORT, '127.0.0.1', () => {
  console.log(`\n  ZipUnlock dev server running\n  → http://localhost:${PORT}\n`);
  console.log('  Press Ctrl+C to stop.\n');
});
