import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scrypt as scryptCallback, timingSafeEqual, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import bcrypt from 'bcryptjs';

const scrypt = promisify(scryptCallback);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 10000;
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET, MAIN_ADMIN_USER_ID } = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SESSION_SECRET || !MAIN_ADMIN_USER_ID) {
  console.error('Missing required environment variables: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET, MAIN_ADMIN_USER_ID.');
  process.exit(1);
}
if (SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET must contain at least 32 characters.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Cache-Control', 'no-store');
  next();
});

async function readState() {
  const { data, error } = await supabase.from('app_state').select('data').eq('id', 1).single();
  if (error) throw error;
  if (!data?.data || !Array.isArray(data.data.users) || !Array.isArray(data.data.soldiers)) {
    throw new Error('Invalid app_state data structure.');
  }
  return data.data;
}
async function writeState(data) {
  const { error } = await supabase.from('app_state').upsert({ id: 1, data, updated_at: new Date().toISOString() }, { onConflict: 'id' });
  if (error) throw error;
}
function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    display: user.display || user.username,
    role: user.role || 'Staff',
    permissions: Array.isArray(user.permissions) ? user.permissions : [],
    soldierId: user.soldierId || null,
    isMainAdmin: user.id === MAIN_ADMIN_USER_ID
  };
}
async function verifyPassword(password, user) {
  if (typeof user.passwordHash === 'string') {
    const hash = user.passwordHash;
    if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(hash)) return bcrypt.compare(password, hash);
    if (hash.startsWith('scrypt$')) {
      const parts = hash.split('$');
      if (parts.length !== 3 || !/^[0-9a-fA-F]{128}$/.test(parts[2])) return false;
      const actual = Buffer.from(await scrypt(password, parts[1], 64));
      const expected = Buffer.from(parts[2], 'hex');
      return actual.length === expected.length && expected.length === 64 && timingSafeEqual(actual, expected);
    }
  }
  return typeof user.password === 'string' && user.password === password;
}
async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}
async function auth(req, res, next) {
  try {
    const token = req.cookies.bb_session || req.cookies.mo_session;
    if (!token) return res.status(401).json({ error: 'Please sign in.' });
    const payload = jwt.verify(token, SESSION_SECRET);
    const state = await readState();
    const user = state.users.find(u => u.id === payload.userId);
    if (!user) return res.status(401).json({ error: 'Account no longer exists. Please sign in again.' });
    req.state = state;
    req.user = publicUser(user);
    req.rawUser = user;
    req.isMainAdmin = user.id === MAIN_ADMIN_USER_ID;
    next();
  } catch (err) {
    if (err?.name !== 'JsonWebTokenError' && err?.name !== 'TokenExpiredError') console.error('[AUTH_ERROR]', err);
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}
function hasGlobalPermission(req, permission) {
  return req.isMainAdmin || req.user.permissions.includes('*') || req.user.permissions.includes(permission);
}
function ministryPermission(state, userId, ministry, permission, isAdmin) {
  if (isAdmin) return true;
  const membership = (state.ministryMembers || []).find(x => x.userId === userId && x.ministry === ministry);
  return !!membership && (membership.permissions || []).some(p => p === '*' || p === permission);
}
function jsonEqual(a, b) { return JSON.stringify(a ?? null) === JSON.stringify(b ?? null); }
function changedKeys(oldState, newState) {
  const keys = new Set([...Object.keys(oldState || {}), ...Object.keys(newState || {})]);
  return [...keys].filter(k => !jsonEqual(oldState?.[k], newState?.[k]));
}
function validateNonAdminChanges(req, nextState) {
  const old = req.state;
  const changed = changedKeys(old, nextState);
  for (const key of changed) {
    if (key === 'audit') continue;
    if (key === 'soldiers' && hasGlobalPermission(req, 'soldiers.manage')) continue;
    if (key === 'trainings' && hasGlobalPermission(req, 'trainings.manage')) continue;
    if (key === 'deployments' && hasGlobalPermission(req, 'deployments.manage')) continue;
    if (key === 'brigades' && hasGlobalPermission(req, 'brigades.manage')) continue;
    if ((key === 'ranks' || key === 'promotionPoints') && hasGlobalPermission(req, 'ranks.manage')) continue;
    if (key === 'users') {
      const stripCredentials = u => { const { password, passwordHash, ...safe } = u; return safe; };
      const oldUsers = new Map(old.users.map(u => [u.id, stripCredentials(u)]));
      const newUsers = new Map(nextState.users.map(u => [u.id, stripCredentials(u)]));
      const removedOrChanged = [...oldUsers].some(([id, user]) => !newUsers.has(id) || !jsonEqual(user, newUsers.get(id)));
      const added = [...newUsers].filter(([id]) => !oldUsers.has(id)).map(([id]) => nextState.users.find(u => u.id === id));
      if (!removedOrChanged && added.length && hasGlobalPermission(req, 'soldiers.manage') && added.every(u => u.role === 'Soldier' && u.soldierId && u.id && u.username)) continue;
      return 'Only the main administrator can edit existing accounts. Staff may create Soldier accounts when authorised.';
    }
    if (key === 'announcements') {
      const oldRows = new Map((old.announcements || []).map(a => [a.id, a]));
      const newRows = new Map((nextState.announcements || []).map(a => [a.id, a]));
      if ([...oldRows].some(([id, a]) => !newRows.has(id) || !jsonEqual(a, newRows.get(id)))) return 'Only the main administrator can delete or edit announcements.';
      const additions = [...newRows].filter(([id]) => !oldRows.has(id)).map(([, a]) => a);
      if (additions.every(a => ministryPermission(old, req.user.id, a.ministry, a.ministry === 'propaganda' ? 'propaganda.manage' : 'announcements.manage', false) || (a.ministry === 'government' && ministryPermission(old, req.user.id, 'government', 'government.internal', false)))) continue;
      return 'You do not have permission to publish in this ministry.';
    }
    if (key === 'salaryRecords') {
      if (!ministryPermission(old, req.user.id, 'finance', 'finance.manage', false)) return 'You do not have Finance payroll permission.';
      const oldRows = new Map((old.salaryRecords || []).map(x => [x.id, x]));
      const newRows = new Map((nextState.salaryRecords || []).map(x => [x.id, x]));
      if ([...oldRows].some(([id, x]) => !newRows.has(id) || !jsonEqual(x, newRows.get(id)))) return 'Salary records cannot be edited or deleted by this account.';
      continue;
    }
    return `You are not authorised to change ${key}.`;
  }
  return null;
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'balkan-borders-rp' }));
app.get('/api/public', async (_req, res) => {
  try {
    const state = await readState();
    const announcements = (state.announcements || [])
      .filter(a => a.visibility !== 'internal')
      .map(a => ({ id: a.id, ministry: a.ministry, title: a.title, body: a.body, description: a.description, url: a.url, kind: a.kind, createdAt: a.createdAt }));
    res.json({ announcements });
  } catch (err) {
    console.error('[PUBLIC_FEED_ERROR]', err);
    res.status(500).json({ error: 'Public announcements are temporarily unavailable.' });
  }
});
app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!username || !password) return res.status(400).json({ error: 'Enter username and password.' });
    const state = await readState();
    const user = state.users.find(u => String(u.username || '').trim().toLowerCase() === username);
    if (!user || !(await verifyPassword(password, user))) return res.status(401).json({ error: 'Incorrect username or password.' });
    // Upgrade legacy plaintext credentials on successful login. Existing users keep the same password.
    if (typeof user.password === 'string' && !user.passwordHash) {
      user.passwordHash = await hashPassword(password);
      delete user.password;
      await writeState(state);
    }
    const safe = publicUser(user);
    const token = jwt.sign({ userId: user.id }, SESSION_SECRET, { expiresIn: '12h', issuer: 'balkan-borders-rp' });
    res.cookie('bb_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 43200000, path: '/' });
    // Legacy cookie is cleared so old sessions cannot keep using the previous auth path.
    res.clearCookie('mo_session', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
    res.json({ user: safe });
  } catch (err) {
    console.error('[LOGIN_ERROR]', err);
    res.status(500).json({ error: 'Unable to sign in right now.' });
  }
});
app.post('/api/logout', (_req, res) => {
  const opts = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' };
  res.clearCookie('bb_session', opts); res.clearCookie('mo_session', opts); res.json({ ok: true });
});
app.get('/api/state', auth, (req, res) => {
  const copy = structuredClone(req.state);
  copy.users = copy.users.map(u => {
    if (req.isMainAdmin) return u;
    const { password, passwordHash, ...safe } = u;
    return safe;
  });
  res.json(copy);
});
app.put('/api/state', auth, async (req, res) => {
  try {
    const nextState = req.body;
    if (!nextState || !Array.isArray(nextState.users) || !Array.isArray(nextState.soldiers)) return res.status(400).json({ error: 'Invalid data format.' });
    if (JSON.stringify(nextState).length > 2_000_000) return res.status(413).json({ error: 'State payload is too large.' });
    if (!req.isMainAdmin) {
      const denied = validateNonAdminChanges(req, nextState);
      if (denied) return res.status(403).json({ error: denied });
      // Preserve server-side credential fields; a client must never erase or set another account's hashes.
      const incoming = new Map(nextState.users.map(u => [u.id, u]));
      const addedUsers = nextState.users.filter(u => !req.state.users.some(oldUser => oldUser.id === u.id));
      nextState.users = req.state.users.map(oldUser => {
        const updated = incoming.get(oldUser.id) || oldUser;
        return { ...updated, password: oldUser.password, passwordHash: oldUser.passwordHash };
      });
      for (const added of addedUsers) {
        if (typeof added.password === 'string' && added.password.length) {
          added.passwordHash = await hashPassword(added.password);
          delete added.password;
        }
      }
      nextState.users.push(...addedUsers);
      nextState.ministryMembers = req.state.ministryMembers || [];
    }
    if (req.isMainAdmin) {
      // Hash any newly supplied or changed password before persisting account data.
      const oldUsers = new Map(req.state.users.map(u => [u.id, u]));
      for (const user of nextState.users) {
        const oldUser = oldUsers.get(user.id);
        if (typeof user.password === 'string' && user.password.length) {
          if (!oldUser || user.password !== oldUser.password || user.passwordHash !== oldUser.passwordHash) {
            user.passwordHash = await hashPassword(user.password);
          }
          delete user.password;
        }
      }
    }
    await writeState(nextState);
    res.json({ ok: true });
  } catch (err) {
    console.error('[STATE_SAVE_ERROR]', err);
    res.status(500).json({ error: 'Saving changes failed.' });
  }
});
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

app.use(express.static(__dirname, { extensions: ['html'] }));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'NOVIindex.html')));
app.listen(PORT, () => console.log(`Balkan Borders RP server listening on ${PORT}`));