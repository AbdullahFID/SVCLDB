// ═══════════════════════════════════════════════════════════════
// preload.js — contextBridge exposing a minimal, typed API to the
// renderer. No `nodeIntegration`, no raw ipcRenderer — every call
// goes through this shim, and everything the renderer can do is
// visible in one file for audit.
// ═══════════════════════════════════════════════════════════════

const { contextBridge, ipcRenderer } = require('electron');

// Whitelisted push events from main → renderer. The renderer registers a
// callback via svc.on(...) and gets a single string arg (the event name)
// plus whatever payload main.js sent. Anything not in EVENTS is silently
// dropped — no way for main to smuggle raw IPC events past this shim.
const EVENTS = new Set([
  'license:session-updated',
  'license:expired-lockout',
]);

contextBridge.exposeInMainWorld('svc', {
  license: {
    load:         ()    => ipcRenderer.invoke('license:load'),
    signIn:       ()    => ipcRenderer.invoke('license:sign-in'),
    signOut:      ()    => ipcRenderer.invoke('license:sign-out'),
    pendingUrl:   ()    => ipcRenderer.invoke('license:pending-url'),
    /* v4.7: remove a device from user_devices (MAX_DEVICES=1 policy).
     * Requires pendingAccessToken + pendingUserId because the caller
     * hasn't completed a full login yet (device limit blocked it). */
    removeDevice: (payload) => ipcRenderer.invoke('license:remove-device', payload),
  },
  on: (evt, cb) => {
    if (!EVENTS.has(evt) || typeof cb !== 'function') return () => {};
    const wrapped = (_e, ...args) => { try { cb(...args); } catch (err) { console.error(err); } };
    ipcRenderer.on(evt, wrapped);
    return () => ipcRenderer.removeListener(evt, wrapped);
  },
  apiKey: {
    /* Legacy single-key surface — kept for backward compat. */
    load:  ()   => ipcRenderer.invoke('api-key:load'),
    save:  (k)  => ipcRenderer.invoke('api-key:save', k),
    clear: ()   => ipcRenderer.invoke('api-key:clear'),
  },
  /* v4.4: multi-provider key bag + per-key live tester. */
  apiKeys: {
    /* Returns { openai, anthropic, google, openrouter } — always all 4 slots,
     * with empty strings for unconfigured providers. */
    load:  ()             => ipcRenderer.invoke('api-keys:load'),
    /* keys: { openai, anthropic, google, openrouter } object. Missing
     * slots default to empty string. Persists to DPAPI + AES fallback. */
    save:  (keys)         => ipcRenderer.invoke('api-keys:save', keys),
    clear: ()             => ipcRenderer.invoke('api-keys:clear'),
    /* Hits the provider's list-models endpoint. Returns:
     *   { ok, status, latency_ms, models?, err? }
     * Never charges tokens. 6s timeout. */
    test:  (provider, k)  => ipcRenderer.invoke('api-keys:test', provider, k),
  },
  /* v4.7: user-remappable hotkey overrides. */
  hotkeys: {
    /* Returns { defaults: [...], overrides: { [slotIndex]: packedUInt } }.
     * defaults is the DEFAULT_HOTKEYS array from injector.js (32 slots
     * indexed by svc_hotkey_action_t). overrides is the user's saved
     * customizations — merged on top of defaults at inject time. */
    load:  ()             => ipcRenderer.invoke('hotkeys:load'),
    /* overrides: { [slotIndex]: packedUInt }. Any slot not present
     * falls back to the default. */
    save:  (overrides)    => ipcRenderer.invoke('hotkeys:save', overrides),
    reset: ()             => ipcRenderer.invoke('hotkeys:reset'),
  },
  /* v4.7: first-run onboarding walkthrough. */
  onboarding: {
    get:      () => ipcRenderer.invoke('onboarding:get'),
    complete: () => ipcRenderer.invoke('onboarding:complete'),
    reset:    () => ipcRenderer.invoke('onboarding:reset'),
  },
  injector: {
    status:   ()      => ipcRenderer.invoke('injector:status'),
    inject:   (opts)  => ipcRenderer.invoke('injector:inject', opts),
    uninject: ()      => ipcRenderer.invoke('injector:uninject'),
    killAll:  ()      => ipcRenderer.invoke('injector:kill-all'),
  },
  window: {
    minimize: () => ipcRenderer.invoke('window:minimize'),
    close:    () => ipcRenderer.invoke('window:close'),
    quit:     () => ipcRenderer.invoke('window:quit'),
  },
  shell: {
    openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
  },
  logs: {
    export: () => ipcRenderer.invoke('logs:export'),
  },
});
