// In-memory session store with a per-user index, so Universal Logout can find and
// destroy every session (and refresh token) a user has in this app.
import crypto from 'node:crypto';

const sessions = new Map(); // sid -> { sid, user, tokens, createdAt }
const knownUsers = new Map(); // lowercased email or `${iss}|${sub}` -> last seen

export function createSession(user, tokens) {
  const sid = crypto.randomBytes(24).toString('base64url');
  sessions.set(sid, { sid, user, tokens, createdAt: new Date().toISOString() });
  knownUsers.set(user.email?.toLowerCase(), Date.now());
  knownUsers.set(`${user.iss}|${user.sub}`, Date.now());
  return sid;
}

export const getSession = (sid) => (sid ? sessions.get(sid) : undefined);
export const deleteSession = (sid) => sessions.delete(sid);
export const listSessions = () => [...sessions.values()];

function matches(session, subId) {
  const u = session.user;
  if (subId.format === 'email') return u.email?.toLowerCase() === subId.email.toLowerCase();
  if (subId.format === 'iss_sub') return u.sub === subId.sub && u.iss.replace(/\/+$/, '') === subId.iss.replace(/\/+$/, '');
  return false;
}

export function isKnownUser(subId) {
  if (subId.format === 'email') return knownUsers.has(subId.email.toLowerCase());
  if (subId.format === 'iss_sub') return knownUsers.has(`${subId.iss.replace(/\/+$/, '')}|${subId.sub}`);
  return false;
}

/** Destroy all sessions for the subject. Returns the number of sessions revoked. */
export function revokeUser(subId) {
  let count = 0;
  for (const s of sessions.values()) {
    if (matches(s, subId)) {
      // A production app would also revoke the refresh token at Okta's /revoke endpoint here.
      sessions.delete(s.sid);
      count++;
    }
  }
  return count;
}
