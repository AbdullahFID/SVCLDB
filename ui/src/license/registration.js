// ═══════════════════════════════════════════════════════════════
// registration.js — Device registration + MAX_DEVICES=1 enforcement.
//
// Ported from hooksdll/lumio/src/license/license.js registerDevice()
// plus MAX_DEVICES check the user asked for (hooksdll declares
// MAX_DEVICES=1 in config but never actually enforces it — svcldb does).
//
// Flow inside login():
//   1. queryUserDevices(userId, token) → array of {hardware_uuid, ...}
//   2. If the current HWID is ALREADY in the list → allow (re-login on
//      same box). Update last_seen_at.
//   3. If NOT in the list AND list.length < MAX_DEVICES → allow +
//      upsert. Standard first-device path.
//   4. If NOT in the list AND list.length >= MAX_DEVICES → return
//      {ok:false, reason:'device_limit_exceeded', devices}. Caller
//      shows the "Device limit reached" screen with options to remove
//      an old device.
//
// Client-side enforcement is defense in depth on top of any server-side
// RLS policy. Server-side is authoritative (a determined attacker
// could patch the Electron client to skip this check) but paying
// customers who share their credentials will hit the client-side check
// first + get clear UX telling them why.
// ═══════════════════════════════════════════════════════════════

const {
  SUPABASE_URL, SUPABASE_ANON_KEY, MAX_DEVICES, APP_VERSION,
} = require('./config');

/**
 * Query the user_devices table for all devices registered under this
 * account. Returns an array of {hardware_uuid, device_name, model,
 * platform, last_seen_at, created_at} — empty on transport failure OR
 * when the table is missing (both should be treated as "unknown, skip
 * enforcement" rather than blocking login).
 */
async function queryUserDevices(userId, accessToken) {
  if (!userId || !accessToken) return { ok: false, devices: [], err: 'missing_credentials' };
  const url = `${SUPABASE_URL}/rest/v1/user_devices?user_id=eq.${encodeURIComponent(userId)}&select=hardware_uuid,device_name,model,platform,last_seen_at,created_at&order=created_at.asc`;
  try {
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
        'User-Agent': `CloakGPT/${APP_VERSION}`,
      },
      signal: AbortSignal.timeout(15_000),
    });
    if (resp.ok) {
      const devices = await resp.json();
      return { ok: true, devices: Array.isArray(devices) ? devices : [] };
    }
    if (resp.status === 404) {
      // Table missing → open-permission (skip enforcement).
      return { ok: false, devices: [], err: 'table_missing_skip' };
    }
    const body = await resp.text().catch(() => '');
    return { ok: false, devices: [], err: `http_${resp.status}:${body.slice(0, 100)}` };
  } catch (e) {
    return { ok: false, devices: [], err: e.message };
  }
}

/**
 * Upsert this device into user_devices. Idempotent — if a row with
 * (user_id, hardware_uuid) already exists it's updated with the new
 * last_seen_at. Otherwise a fresh row is inserted.
 *
 * Fires AFTER we've already validated the device is allowed via
 * enforceDeviceLimit(). Callers should NOT call this if enforce
 * returned {ok:false} — the user needs to remove another device first.
 */
async function upsertDevice(session, deviceInfo) {
  if (!session || !session.access_token || !session.user_id) {
    return { ok: false, err: 'no_session' };
  }
  const now = new Date().toISOString();
  const url = `${SUPABASE_URL}/rest/v1/user_devices?on_conflict=user_id,hardware_uuid`;
  const body = {
    user_id:       session.user_id,
    hardware_uuid: deviceInfo.hardware_uuid,
    device_name:   deviceInfo.device_name || 'Windows PC',
    model:         deviceInfo.model || null,
    platform:      'windows',
    last_seen_at:  now,
  };
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${session.access_token}`,
        'Prefer': 'resolution=merge-duplicates',
        'User-Agent': `CloakGPT/${APP_VERSION}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    if (!resp.ok) {
      const t = await resp.text().catch(() => '');
      return { ok: false, err: `upsert http ${resp.status}: ${t.slice(0, 120)}` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, err: e.message };
  }
}

/**
 * Delete a specific device from the user's registered list. Called
 * from the "Device limit reached" screen when the user picks which
 * old device to unregister.
 */
async function deleteDevice(session, hardwareUuid) {
  if (!session || !session.access_token || !session.user_id) {
    return { ok: false, err: 'no_session' };
  }
  const url = `${SUPABASE_URL}/rest/v1/user_devices?user_id=eq.${encodeURIComponent(session.user_id)}&hardware_uuid=eq.${encodeURIComponent(hardwareUuid)}`;
  try {
    const resp = await fetch(url, {
      method: 'DELETE',
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${session.access_token}`,
        'User-Agent': `CloakGPT/${APP_VERSION}`,
      },
      signal: AbortSignal.timeout(15_000),
    });
    if (!resp.ok) {
      const t = await resp.text().catch(() => '');
      return { ok: false, err: `delete http ${resp.status}: ${t.slice(0, 120)}` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, err: e.message };
  }
}

/**
 * Enforce the MAX_DEVICES policy for this login attempt.
 *
 * @param {object} session       - freshly-obtained OAuth session
 * @param {object} deviceInfo    - result of device.collect()
 * @returns {object}
 *   { ok:true, action:'first_device'|'existing_device'|'upserted' }
 *     → caller should proceed with sub check + inject flow
 *   { ok:false, reason:'device_limit_exceeded', devices, currentHwid }
 *     → caller should show device-limit UI; devices is the list of
 *       already-registered devices to pick from for removal
 *   { ok:true, action:'skipped', reason } → table missing / network
 *     down / RLS denied read; enforcement disabled but login continues
 *     (defense in depth relies on server-side auth to block if actually
 *      wrong)
 */
async function enforceDeviceLimit(session, deviceInfo) {
  if (!deviceInfo || !deviceInfo.hardware_uuid) {
    return { ok: false, reason: 'no_hwid' };
  }
  const currentHwid = deviceInfo.hardware_uuid;

  const q = await queryUserDevices(session.user_id, session.access_token);
  if (!q.ok) {
    // Read failure (table missing, RLS blocking read for authed user,
    // network down). We upsert anyway — the write may fail server-side
    // but that's a UX issue not a security one.
    console.log('[registration] query failed, skipping limit enforcement:', q.err);
    const upsertRes = await upsertDevice(session, deviceInfo);
    return { ok: true, action: 'skipped', reason: q.err, upsertOk: upsertRes.ok };
  }

  // Is our HWID already registered?
  const alreadyRegistered = q.devices.some(
    (d) => (d.hardware_uuid || '').toLowerCase() === currentHwid.toLowerCase()
  );

  if (alreadyRegistered) {
    // Re-login on same box — just update last_seen_at and continue.
    const r = await upsertDevice(session, deviceInfo);
    console.log(`[registration] existing device confirmed (${q.devices.length}/${MAX_DEVICES} used)`);
    return { ok: true, action: 'existing_device', upsertOk: r.ok };
  }

  // This is a NEW device for this account. Check the limit.
  const limit = MAX_DEVICES || 1;
  if (q.devices.length >= limit) {
    console.log(`[registration] DEVICE LIMIT: user has ${q.devices.length} devices, limit=${limit}`);
    return {
      ok: false,
      reason: 'device_limit_exceeded',
      devices: q.devices,
      currentHwid,
      currentDeviceName: deviceInfo.device_name || 'This PC',
      currentModel: deviceInfo.model || null,
      limit,
    };
  }

  // Under limit — register this new device.
  const r = await upsertDevice(session, deviceInfo);
  console.log(`[registration] first device registered (${q.devices.length + 1}/${limit} used)`);
  return { ok: true, action: 'first_device', upsertOk: r.ok };
}

module.exports = {
  queryUserDevices,
  upsertDevice,
  deleteDevice,
  enforceDeviceLimit,
};
