
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import bcrypt from 'bcryptjs';

const scrypt = promisify(scryptCallback);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 10000;

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET } = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SESSION_SECRET) {
  console.error('Missing required environment variables.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// Provera sesije
function requireSession(req, res, next) {
  try {
    if (!req.cookies.mo_session) throw new Error('No session');

    req.session = jwt.verify(req.cookies.mo_session, SESSION_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: 'Sesija je istekla. Prijavite se ponovo.'
    });
  }
}

// Učitavanje podataka iz Supabase baze
async function readState() {
  const { data, error } = await supabase
    .from('app_state')
    .select('data')
    .eq('id', 1)
    .single();

  if (error) throw error;

  return data.data;
}

// Provera lozinki: bcrypt, scrypt i stare obične lozinke
async function verifyPassword(password, user) {
  if (typeof user.passwordHash === 'string') {
    const hash = user.passwordHash;

    // bcrypt
    if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(hash)) {
      return await bcrypt.compare(password, hash);
    }

    // scrypt
    if (hash.startsWith('scrypt$')) {
      const parts = hash.split('$');

      if (parts.length !== 3) return false;

      const salt = parts[1];
      const expectedHex = parts[2];

      if (!salt || !/^[0-9a-fA-F]{128}$/.test(expectedHex)) {
        return false;
      }

      const actual = Buffer.from(await scrypt(password, salt, 64));
      const expected = Buffer.from(expectedHex, 'hex');

      return (
        actual.length === expected.length &&
        expected.length === 64 &&
        timingSafeEqual(actual, expected)
      );
    }
  }

  // Stare obične lozinke
  return (
    typeof user.password === 'string' &&
    user.password === password
  );
}

// Prijava korisnika
app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!username || !password) {
      return res.status(400).json({
        error: 'Unesite korisničko ime i lozinku.'
      });
    }

    const state = await readState();

    if (!state || !Array.isArray(state.users)) {
      throw new Error('Invalid users data in database');
    }

    const user = state.users.find(
      u => String(u.username || '').trim().toLowerCase() === username
    );

    if (!user || !(await verifyPassword(password, user))) {
      return res.status(401).json({
        error: 'Pogrešno korisničko ime ili lozinka.'
      });
    }

    const safeUser = {
      id: user.id,
      username: user.username,
      display: user.display,
      role: user.role,
      permissions: user.permissions || [],
      soldierId: user.soldierId || null
    };

    const token = jwt.sign(safeUser, SESSION_SECRET, {
      expiresIn: '12h'
    });

    res.cookie('mo_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 43200000,
      path: '/'
    });

    res.json({ user: safeUser });

  } catch (err) {
    console.error('[LOGIN_ERROR]', err);

    res.status(500).json({
      error: 'Greška pri prijavi na server.'
    });
  }
});

// Odjava
app.post('/api/logout', (_req, res) => {
  res.clearCookie('mo_session', {
    httpOnly: true,
    sameSite: 'lax',
    path: '/'
  });

  res.json({ ok: true });
});

// Učitavanje stanja
app.get('/api/state', requireSession, async (_req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    res.json(await readState());
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Ne mogu da učitam podatke iz Supabase baze.'
    });
  }
});

// Čuvanje stanja
app.put('/api/state', requireSession, async (req, res) => {
  try {
    const data = req.body;

    if (
      !data ||
      !Array.isArray(data.users) ||
      !Array.isArray(data.soldiers)
    ) {
      return res.status(400).json({
        error: 'Neispravan format podataka.'
      });
    }

    const { error } = await supabase
      .from('app_state')
      .upsert(
        {
          id: 1,
          data,
          updated_at: new Date().toISOString()
        },
        { onConflict: 'id' }
      );

    if (error) throw error;

    res.json({ ok: true });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Čuvanje u Supabase bazi nije uspelo.'
    });
  }
});

// Statički fajlovi
app.use(express.static(__dirname));

// Pokretanje servera
app.listen(PORT, () => {
  console.log(`App listening on ${PORT}`);
});
