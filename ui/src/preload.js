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
    load:        ()    => ipcRenderer.invoke('license:load'),
    signIn:      ()    => ipcRenderer.invoke('license:sign-in'),
    signOut:     ()    => ipcRenderer.invoke('license:sign-out'),
    pendingUrl:  ()    => ipcRenderer.invoke('license:pending-url'),
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
