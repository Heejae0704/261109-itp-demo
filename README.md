# Okta ITP + custom SSF transmitter demo

This demo shows Okta Identity Threat Protection (ITP) acting on a risk signal from a third-party security tool:

1. A **custom SSF transmitter** (your "security vendor") detects a threat and pushes a signed Security Event Token (SET) to Okta.
2. **Okta** verifies the SET, raises the user's entity risk, and the **entity risk policy** signs the user out of Okta and fires **Universal Logout**.
3. A **custom OIDC web app** receives Okta's Universal Logout call and kills the user's session. The open browser tab notices within 3 seconds and shows a "you were logged out" banner.

```
 ┌───────────────────────┐   SET (RS256, secevent+jwt)     ┌──────────────────────┐
 │ transmitter/          │ ──────────────────────────────▶ │ Okta org (ITP)       │
 │  /.well-known/        │  POST /security/api/v1/         │  SSF receiver        │
 │   ssf-configuration   │       security-events           │  Entity risk policy  │
 │  /.well-known/jwks.json◀──── Okta fetches issuer + JWKS ─│  Universal Logout    │
 │  console (send SETs)  │                                 └──────────┬───────────┘
 └───────────────────────┘                                            │ POST /global-token-revocation
                                                                       │ Bearer JWT (global-token-revocation+jwt)
                           ┌───────────────────────┐                   │ {"sub_id":{"format":"email",...}}
       user's browser ───▶ │ webapp/ (Acme Portal) │ ◀─────────────────┘
          (OIDC login)     │  session store        │  → 204, all sessions for that user destroyed
                           └───────────────────────┘
```

| Folder | What it is |
| --- | --- |
| `transmitter/` | Node/Express SSF transmitter: SSF metadata, JWKS, SET signing, push to Okta, web console, CLI |
| `webapp/` | Node/Express OIDC web app (auth code + PKCE) with a Universal Logout endpoint |
| `test/` | Local end-to-end test with a fake Okta that applies Okta's documented SET checks |

---

## 1. How the SET is built (what Okta checks)

Everything below comes from Okta's Management API schema for the SSF receiver (`SecurityEventTokenRequestJwtHeader`, `SecurityEventTokenRequestJwtBody`, `SecurityEventTokenRequestJwtEvents`) and the [Configure SSF receiver guide](https://developer.okta.com/docs/guides/configure-ssf-receiver/main/).

**Delivery**

```
POST https://{yourOktaDomain}/security/api/v1/security-events
Content-Type: application/secevent+jwt
Accept: application/json

<compact signed JWT>
```

No API token is needed: the signature, checked against the provider's registered JWKS, is the authentication. Okta returns **202 Accepted** with no body on success, or **400** with `{"err": "...", "description": "..."}` where `err` is `authentication_failed`, `invalid_audience`, `invalid_issuer`, `invalid_key` or `invalid_request`.

**JOSE header**

```json
{ "alg": "RS256", "typ": "secevent+jwt", "kid": "<kid published in our JWKS>" }
```

**Claims**

| Claim | Value | Notes |
| --- | --- | --- |
| `iss` | The transmitter's issuer, e.g. `https://ssf-transmitter.up.railway.app` | Must match **exactly** the issuer Okta stored for the provider (the `issuer` in our `ssf-configuration`). |
| `aud` | Your Okta org URL, e.g. `https://acme.okta.com` | The org URL, not an authorization server URL. |
| `iat` | Now (UNIX seconds) | |
| `jti` | Random UUID | Must be unique. Okta **silently ignores** a repeated `jti`. |
| `events` | One event, keyed by its type URI | No top-level `sub`; the subject is inside the event. |

**Event types Okta accepts** (the complete list in Okta's schema):

| Console key | Event type URI | Required fields besides `subject`, `event_timestamp` |
| --- | --- | --- |
| `user-risk-change` ⭐ | `https://schemas.okta.com/secevent/okta/event-type/user-risk-change` | `previous_level`, `current_level` (`none`, `secure`, `low`, `medium`, `high`) |
| `session-revoked` | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | optional `current_ip`, `last_known_ip`, user agents |
| `device-risk-change` | `https://schemas.okta.com/secevent/okta/event-type/device-risk-change` | `previous_level`, `current_level` |
| `ip-change` | `https://schemas.okta.com/secevent/okta/event-type/ip-change` | `previous_ip_address`, `current_ip_address` |
| `device-compliance-change` | `https://schemas.openid.net/secevent/caep/event-type/device-compliance-change` | `previous_status`, `current_status` (`compliant`, `not-compliant`) |
| `identifier-changed` | `https://schemas.openid.net/secevent/risc/event-type/identifier-changed` | optional `new_value` |

All events also accept `initiating_entity` (`admin`, `user`, `policy`, `system`) and `reason_admin` / `reason_user` as `{"en": "..."}`. Generic CAEP events that aren't listed (for example `credential-change`, `assurance-level-change`, `risk-level-change`) are **not** in Okta's receiver schema, so the transmitter doesn't offer them.

**Subject**: always the complex `user` subject with email format:

```json
"subject": { "user": { "format": "email", "email": "jane.doe@acme.com" } }
```

The email must be a sign-in email of an existing Okta user. If it isn't, Okta still answers 202 but **silently drops** the event (nothing in the System Log).

**Full example** (what the console sends by default):

```json
{
  "iss": "https://ssf-transmitter.up.railway.app",
  "aud": "https://acme.okta.com",
  "iat": 1794205775,
  "jti": "51247df5-0996-4552-b1b7-8be2379634d2",
  "events": {
    "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
      "subject": { "user": { "format": "email", "email": "jane.doe@acme.com" } },
      "event_timestamp": 1794205775,
      "initiating_entity": "policy",
      "previous_level": "low",
      "current_level": "high",
      "reason_admin": { "en": "Impossible travel and credential stuffing detected by custom XDR" },
      "reason_user": { "en": "Impossible travel and credential stuffing detected by custom XDR" }
    }
  }
}
```

**Why `user-risk-change` → `high` is the demo trigger.** Okta turns a provider's SET into the ITP detection *Security events provider reported risk* (`SECURITY_EVENTS_PROVIDER_REPORTED_RISK`), logs `user.risk.detect`, and raises the user's entity risk. The entity risk policy then runs its matching rule, and that rule is where you choose Universal Logout.

**Metadata the transmitter publishes**

`GET /.well-known/ssf-configuration` (served as `application/json`):

```json
{
  "spec_version": "1_0",
  "issuer": "https://ssf-transmitter.up.railway.app",
  "jwks_uri": "https://ssf-transmitter.up.railway.app/.well-known/jwks.json",
  "delivery_methods_supported": ["urn:ietf:rfc:8935"],
  "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:7523" }],
  "default_subjects": "NONE"
}
```

`GET /.well-known/jwks.json` returns one RSA key with `use: sig`, `alg: RS256` and a `kid`.

---

## 2. Deploy on Railway

Push this folder to a GitHub repo, then in Railway create **one project with two services** from that repo.

**Service 1: transmitter**

1. New service from the repo, then **Settings → Root Directory** = `transmitter`.
2. **Settings → Networking → Generate Domain** (Railway then injects `RAILWAY_PUBLIC_DOMAIN`, which becomes the issuer).
3. Locally run `cd transmitter && npm install && npm run genkey`, and copy the one-line output.
4. **Variables**:
   - `OKTA_ORG_URL` = `https://your-org.okta.com`
   - `SIGNING_KEY_PEM` = the genkey output. This is important: without it the key changes on every deploy and Okta rejects SETs with `invalid_key`.
   - `ADMIN_PASSWORD` = a password for the console (HTTP Basic, any username)
   - optional `DEFAULT_SUBJECT_EMAIL` = your demo user's email
5. Open `https://<transmitter-domain>/.well-known/ssf-configuration` and check that `issuer` is the https Railway URL.

**Service 2: webapp**

1. New service from the same repo, **Root Directory** = `webapp`, **Generate Domain**.
2. **Variables**: `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET` (from step 3.2 below) and `SESSION_SECRET` (any long random string).
3. Keep it at **one replica**. Sessions are held in memory, so the Universal Logout call must reach the same instance as the browser.

Railway runs `npm start` in each folder and sets `PORT` itself. To run locally instead, copy each `.env.example` to `.env`, export the variables, and run `npm start` (transmitter on :4000, webapp on :3000). Okta must be able to reach the transmitter's metadata and the webapp's logout endpoint, so for local runs use a tunnel such as ngrok or cloudflared and set `PUBLIC_URL` / `APP_BASE_URL`.

---

## 3. Okta tenant setup

Prerequisites: an org with **Identity Threat Protection with Okta AI**, a super admin account, and a test user (for example `jane.doe@acme.com`) who is **not** an admin. Keep a separate admin browser session so you don't lock yourself out.

### 3.1 Register the transmitter as a security events provider

**Option A, Admin Console (simplest)**

1. **Security → Device Integrations → Receive shared signals** tab → **Create stream**.
2. **Integration name**: `Custom SSF Transmitter`.
3. Choose **Well-known URL** and enter `https://<transmitter-domain>/.well-known/ssf-configuration`.
   (Or choose **Issuer URL** + **JWKS URL** and paste the two values shown on the transmitter console.)
4. **Create**. The stream shows as **Active**.

**Option B, SSF Receiver API**

```bash
# SSF-compliant provider (Okta reads issuer + jwks_uri from the well-known URL)
curl -X POST "https://your-org.okta.com/api/v1/security-events-providers" \
  -H "Authorization: SSWS $OKTA_API_TOKEN" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{
        "name": "Custom SSF Transmitter",
        "type": "custom",
        "settings": { "well_known_url": "https://<transmitter-domain>/.well-known/ssf-configuration" }
      }'

# Non-SSF form: "settings": { "issuer": "https://<transmitter-domain>", "jwks_url": "https://<transmitter-domain>/.well-known/jwks.json" }
```

Or let the script do it (it reads our metadata so the values always match):

```bash
cd transmitter
OKTA_ORG_URL=https://your-org.okta.com OKTA_API_TOKEN=00x... \
TRANSMITTER_URL=https://<transmitter-domain> npm run register          # add -- --jwks for the issuer/JWKS form
OKTA_ORG_URL=... OKTA_API_TOKEN=... npm run register -- --list         # list providers
```

The SSF Receiver API endpoints are `GET/POST /api/v1/security-events-providers`, `GET/PUT/DELETE /api/v1/security-events-providers/{id}`, and `POST .../{id}/lifecycle/activate|deactivate`. A response has `id`, `name`, `type`, `status` (`ACTIVE` or `INACTIVE`) and `settings` (`issuer`, `jwks_url`, `well_known_url`). `type` is a free-form "application type" string; Okta's schema doesn't enumerate it, so `custom` is a placeholder. If your org rejects it, use the Admin Console path.

### 3.2 Create the OIDC web app

1. **Applications → Applications → Create App Integration** → **OIDC - OpenID Connect** → **Web Application**.
2. **Grant types**: Authorization Code and Refresh Token.
3. **Sign-in redirect URIs**: `https://<webapp-domain>/authorization-code/callback`
4. **Sign-out redirect URIs**: `https://<webapp-domain>/`
5. **Assignments**: assign the test user (or a group). Use **explicit assignments**; Universal Logout doesn't work for custom apps when Federation Broker Mode is on.
6. Save, then copy **Client ID** and **Client secret** into the webapp's Railway variables.

The app uses the **org authorization server** (issuer = your org URL). Okta signs the Universal Logout token with the org's SSO signing key and sets `iss` to the org URL, so this keeps both on one issuer.

### 3.3 Turn on Universal Logout for the app

1. Open the app → **Sign On** tab (called **Authentication** in some orgs) → **Logout** section → **Edit**.
2. Under **Global Token Revocation**, select **Okta system or admin initiates logout**.
3. **Logout endpoint URL**: `https://<webapp-domain>/global-token-revocation`
4. **Endpoint authentication type**: **Signed JWT** (the default).
5. **Subject format type**: **Email Identifier**. (The app also handles **Issuer and Subject Identifier**.)
6. **Save**.

What the app receives and checks:

```
POST /global-token-revocation
Authorization: Bearer <JWT>       header typ = global-token-revocation+jwt
{"sub_id": {"format": "email", "email": "jane.doe@acme.com"}}
```

It verifies the JWT against `https://your-org.okta.com/oauth2/v1/keys` with `iss` = org URL, `aud` = the logout endpoint URL, `sub` = the app's client ID, and `exp`/`nbf`/`iat` with 60 seconds of tolerance. It then destroys every session for that user and answers **204**. It answers 401 for a bad token, 400 for a malformed `sub_id` and 404 for a user who never signed in to the app.

### 3.4 Entity risk policy rule (this is what reacts to the SET)

1. **Security → Entity Risk Policy** (or **Security → Identity Threat Protection → Go to entity risk policy**) → **Add rule**.
2. **Rule name**: `High risk from SSF provider → Universal Logout`
3. **User's group membership includes**: Any group (or your demo group).
4. **Detection**: **Include** → *Security events provider reported risk*. (Or leave **Any detection**.)
5. **Entity risk level**: **High**.
6. **Take this action**: **Logout and revoke tokens** → **Universal Logout and Partial Universal Logout** (signs the user out of Okta and every app that supports Universal Logout, including the demo app).
7. **Save**, and drag the rule **above** the default catch-all rule (which only logs).

### 3.5 Session protection (optional)

Session protection evaluates risk on each active session and suits IP or session-level signals (such as `ip-change` or `session-revoked`).

1. **Security → Identity Threat Protection → Detection and Response** tab → **Session Protection**.
2. **Status**: **Enforced** (or **Monitoring** to only log).
3. **Session violation detection** → **Edit**: risk level **High** (or *Medium and above*).
4. **Enforcement settings**: keep **Okta logout**, and **Run an additional action** → **App logout**.
5. **Save**.

---

## 4. Run the demo

1. In a private browser window, open `https://<webapp-domain>`, click **Sign in with Okta** and sign in as the test user. Optionally open the Okta End-User Dashboard in another tab of the same window.
2. In your own browser, open `https://<transmitter-domain>` (log in with any username and `ADMIN_PASSWORD`).
3. Enter the test user's email, keep **User risk change (Okta)** with **low → high**, and click **Sign and send to Okta**. You should see **HTTP 202**, the decoded SET and the compact JWT.
4. Within a few seconds the Acme Portal tab switches to "Your session was ended by Okta Universal Logout", and the Okta dashboard tab asks for sign-in again. The portal's **Universal Logout requests from Okta** table shows the `204`.
5. In **Reports → System Log**, look for `security.events.provider.receive_event`, then `user.risk.detect`, then the entity risk policy's logout action.

From the command line instead: `TRANSMITTER_URL=https://<transmitter-domain> ADMIN_PASSWORD=... npm run send -- jane.doe@acme.com user-risk-change`

**Running it again.** The policy acts when risk *changes* to High, so a second "high" for a user who is already High may do nothing. Reset first: send `high → low` (or `none`) from the console, or reset the user's risk in the Admin Console, and then send `low → high` again.

---

## 5. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `400 invalid_issuer` | The SET `iss` doesn't exactly match the provider's issuer. Compare the console's **Issuer** with the provider in Okta (no trailing slash, https). If you changed the domain, update the provider. |
| `400 invalid_audience` | `OKTA_ORG_URL` is wrong (it must be the org URL, not `/oauth2/default`). If your org insists on a trailing slash, set `SET_AUDIENCE=https://your-org.okta.com/`. |
| `400 invalid_key` / `authentication_failed` | The key changed (`SIGNING_KEY_PEM` not set, so a new key was made at boot) or Okta can't reach the JWKS URL. |
| `202` but nothing in System Log | The email isn't a sign-in email of an Okta user, or the `jti` was reused. |
| Event logged but no logout | The entity risk rule isn't matching (check its level, detection and order), the user was already High, or the user is excluded by group. |
| Okta logs the user out but the app doesn't | Check the portal's Universal Logout table. **401**: token check failed; the reason is in the Railway logs (set `STRICT_LOGOUT_AUTH=false` briefly to see the decoded token). **404**: the user never signed in to this instance (for example after a redeploy). No entry: the logout endpoint URL in the app's Logout settings is wrong. |

---

## 6. Local end-to-end test

`test/` runs the whole chain against a fake Okta that applies the checks above (header, RS256 signature via the published JWKS, `iss` from the well-known config, `aud` = org URL, unique `jti`, accepted event types, email subject), simulates a "High → Universal Logout" policy, and sends a signed `global-token-revocation+jwt` to the app.

```bash
(cd transmitter && npm install) && (cd webapp && npm install) && (cd test && npm install)
bash test/e2e.sh     # ends with: PASS: SET -> Universal Logout ended the app session
```

The fake Okta only models what Okta documents. Real-tenant behavior (risk scoring, policy timing, System Log events) still needs the walkthrough in section 4.
