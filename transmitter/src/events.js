// Event catalogue: only the event types Okta's SSF receiver accepts.
//
// Source: Okta Management API, SSF Security Event Token schema
// (SecurityEventTokenRequestJwtEvents), as shipped in @okta/okta-sdk-nodejs.
// Okta accepts exactly these six event types on POST /security/api/v1/security-events:
//
//   https://schemas.okta.com/secevent/okta/event-type/user-risk-change
//   https://schemas.okta.com/secevent/okta/event-type/device-risk-change
//   https://schemas.okta.com/secevent/okta/event-type/ip-change
//   https://schemas.openid.net/secevent/caep/event-type/session-revoked
//   https://schemas.openid.net/secevent/caep/event-type/device-compliance-change
//   https://schemas.openid.net/secevent/risc/event-type/identifier-changed
//
// Every event carries `subject` and `event_timestamp` (UNIX seconds). The subject is
// a complex subject, {"user": {"format": "email", "email": "..."}}. The email must be
// a sign-in email of a user in the Okta org, or Okta silently drops the event.

export const EVENT_TYPES = {
  'user-risk-change': {
    uri: 'https://schemas.okta.com/secevent/okta/event-type/user-risk-change',
    label: 'User risk change (Okta)',
    recommended: true,
    build: (o) => ({
      previous_level: o.previousLevel || 'low',
      current_level: o.currentLevel || 'high',
    }),
  },
  'session-revoked': {
    uri: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
    label: 'Session revoked (CAEP)',
    build: (o) => clean({
      current_ip: o.currentIp,
      current_user_agent: o.currentUserAgent,
      last_known_ip: o.lastKnownIp,
      last_known_user_agent: o.lastKnownUserAgent,
    }),
  },
  'device-risk-change': {
    uri: 'https://schemas.okta.com/secevent/okta/event-type/device-risk-change',
    label: 'Device risk change (Okta)',
    build: (o) => ({
      previous_level: o.previousLevel || 'low',
      current_level: o.currentLevel || 'high',
    }),
  },
  'ip-change': {
    uri: 'https://schemas.okta.com/secevent/okta/event-type/ip-change',
    label: 'IP change (Okta)',
    build: (o) => ({
      previous_ip_address: o.previousIp || '203.0.113.10',
      current_ip_address: o.currentIp || '198.51.100.77',
    }),
  },
  'device-compliance-change': {
    uri: 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
    label: 'Device compliance change (CAEP)',
    build: (o) => ({
      previous_status: o.previousStatus || 'compliant',
      current_status: o.currentStatus || 'not-compliant',
    }),
  },
  'identifier-changed': {
    uri: 'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
    label: 'Identifier changed (RISC)',
    build: (o) => clean({ new_value: o.newValue }),
  },
};

export const RISK_LEVELS = ['none', 'secure', 'low', 'medium', 'high'];
export const INITIATING_ENTITIES = ['admin', 'user', 'policy', 'system'];

function clean(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== ''));
}

/**
 * Build the `events` claim for one event.
 * @param {string} key   One of the EVENT_TYPES keys.
 * @param {object} opts  { email, reason, initiatingEntity, ...type-specific fields }
 */
export function buildEvent(key, opts) {
  const def = EVENT_TYPES[key];
  if (!def) throw new Error(`Unsupported event type "${key}". Use one of: ${Object.keys(EVENT_TYPES).join(', ')}`);
  if (!opts.email) throw new Error('email is required (the Okta sign-in email of the user)');

  const body = {
    subject: { user: { format: 'email', email: opts.email } },
    event_timestamp: Math.floor(Date.now() / 1000),
    initiating_entity: opts.initiatingEntity || 'policy',
    ...def.build(opts),
  };
  if (opts.reason) {
    body.reason_admin = { en: opts.reason };
    body.reason_user = { en: opts.reasonUser || opts.reason };
  }
  return { [def.uri]: body };
}
