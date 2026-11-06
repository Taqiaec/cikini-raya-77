const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cikini77';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

fs.mkdirSync(DATA_DIR, { recursive: true });
const dbPath = path.join(DATA_DIR, 'leads.db');
const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nama TEXT NOT NULL,
    whatsapp TEXT NOT NULL,
    pesan TEXT DEFAULT '',
    status TEXT DEFAULT 'baru',
    catatan_admin TEXT DEFAULT '',
    utm_source TEXT DEFAULT '',
    utm_medium TEXT DEFAULT '',
    utm_campaign TEXT DEFAULT '',
    utm_content TEXT DEFAULT '',
    halaman TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    waktu_kirim TEXT NOT NULL
  )
`);

function makeToken(password) {
  return crypto.createHmac('sha256', 'cikini77-secret-salt').update(password).digest('hex');
}

function isAuthorized(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  return token && token === makeToken(ADMIN_PASSWORD);
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1e5) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400'
    });
    res.end(content);
  });
}

const insertLeadStmt = db.prepare(`
  INSERT INTO leads (
    nama, whatsapp, pesan, utm_source, utm_medium, utm_campaign, utm_content, halaman, ip, user_agent, waktu_kirim
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const listLeadsStmt = db.prepare(`SELECT * FROM leads ORDER BY id DESC`);
const updateLeadStmt = db.prepare(`UPDATE leads SET status = ?, catatan_admin = ? WHERE id = ?`);
const deleteLeadStmt = db.prepare(`DELETE FROM leads WHERE id = ?`);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // 1. Public Lead Submission API
  if (pathname === '/api/leads' && req.method === 'POST') {
    try {
      const body = await readJsonBody(req);
      if (body.situs) {
        return sendJson(res, 200, { ok: true }); // Honeypot triggered
      }
      const nama = String(body.nama || '').trim();
      const whatsapp = String(body.whatsapp || '').trim();
      const pesan = String(body.pesan || '').trim();

      if (!nama || !whatsapp) {
        return sendJson(res, 400, { error: 'Nama dan nomor WhatsApp wajib diisi.' });
      }

      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      const ua = String(req.headers['user-agent'] || '').slice(0, 300);
      const waktu = body.waktu_kirim || new Date().toISOString();

      insertLeadStmt.run(
        nama,
        whatsapp,
        pesan,
        String(body.utm_source || ''),
        String(body.utm_medium || ''),
        String(body.utm_campaign || ''),
        String(body.utm_content || ''),
        String(body.halaman || ''),
        ip,
        ua,
        waktu
      );

      return sendJson(res, 201, { ok: true });
    } catch (err) {
      return sendJson(res, 400, { error: 'Format data tidak valid.' });
    }
  }

  // 2. Admin Login API
  if (pathname === '/api/admin/login' && req.method === 'POST') {
    try {
      const body = await readJsonBody(req);
      if (String(body.password || '') === ADMIN_PASSWORD) {
        return sendJson(res, 200, { token: makeToken(ADMIN_PASSWORD) });
      }
      return sendJson(res, 401, { error: 'Password salah.' });
    } catch (err) {
      return sendJson(res, 400, { error: 'Permintaan tidak valid.' });
    }
  }

  // 3. Admin Protected Endpoints
  if (pathname === '/api/leads' && req.method === 'GET') {
    if (!isAuthorized(req)) return sendJson(res, 401, { error: 'Unauthorized' });
    const rows = listLeadsStmt.all();
    return sendJson(res, 200, { leads: rows });
  }

  if (pathname.startsWith('/api/leads/') && (req.method === 'PATCH' || req.method === 'DELETE')) {
    if (!isAuthorized(req)) return sendJson(res, 401, { error: 'Unauthorized' });
    const id = Number(pathname.split('/').pop());
    if (!Number.isInteger(id) || id <= 0) {
      return sendJson(res, 400, { error: 'ID tidak valid.' });
    }

    if (req.method === 'DELETE') {
      deleteLeadStmt.run(id);
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'PATCH') {
      try {
        const body = await readJsonBody(req);
        const status = String(body.status || 'baru');
        const catatan = String(body.catatan_admin ?? '');
        updateLeadStmt.run(status, catatan, id);
        return sendJson(res, 200, { ok: true });
      } catch (err) {
        return sendJson(res, 400, { error: 'Format tidak valid.' });
      }
    }
  }

  // 4. HTML Pages & Static Assets
  if (req.method === 'GET' || req.method === 'HEAD') {
    if (pathname === '/' || pathname === '/index.html') {
      return serveFile(res, path.join(__dirname, 'index.html'));
    }
    if (pathname === '/admin' || pathname === '/admin/' || pathname === '/admin.html') {
      return serveFile(res, path.join(__dirname, 'admin.html'));
    }
    if (pathname.startsWith('/img/')) {
      const safeName = path.basename(pathname);
      return serveFile(res, path.join(__dirname, 'img', safeName));
    }
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('404 Not Found');
});

server.listen(PORT, () => {
  console.log(`Server Cikini Raya 77 berjalan di http://localhost:${PORT}`);
  console.log(`Halaman Admin: http://localhost:${PORT}/admin (Password default: ${ADMIN_PASSWORD})`);
});

