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
  /* v1.6.3: fired when the DWM respawn watchdog auto-re-injects the
   * payload after DWM crashed + respawned. Renderer displays a small
   * toast so the user knows recovery happened. */
  'injector:respawn-recovered',
  /* v2.0 (2026-09-10): user pressed Ctrl+Q inside the overlay (soft
   * user_quit) OR Ctrl+Shift+Alt+K panic (user_panic). Watchdog reads
   * either sentinel, disarms, and pushes this event so the renderer
   * navigates home / shows the "emergency stop" toast. Was fired by
   * main.js since v1.9.2 but silently dropped by preload's whitelist. */
  'injector:user-quit',
]);

contextBridge.exposeInMainWorld('svc', {
  license: {
    load:         ()    => ipcRenderer.invoke('license:load'),
    signIn:       ()    => ipcRenderer.invoke('license:sign-in'),
    signOut:      ()    => ipcRenderer.invoke('license:sign-out'),
    pendingUrl:   ()    => ipcRenderer.invoke('license:pending-url'),
    /* v4.9: lightweight force-recheck. Re-runs security + sub check
     * against Supabase (with token refresh if needed) but does NOT
     * clear the local session — cheaper than full license:load. Used
     * by the "Retry check" button on the nosub screen and by the
     * dashboard "Refresh subscription" action. Returns:
     *   { ok:true,  subscription }
     *   { ok:false, err, securityBlocked? } */
    revalidate:   ()    => ipcRenderer.invoke('license:revalidate'),
    /* v4.7: remove a device from user_devices (MAX_DEVICES=1 policy).
     * Requires pendingAccessToken + pendingUserId because the caller
     * hasn't completed a full login yet (device limit blocked it).
     *
     * v4.9: server-side has NO DELETE RLS policy for authenticated
     * users on user_devices, so this returns { ok:false, err:'...'}
     * with statusCode=403 until a service_role-side deletion is
     * scheduled. Renderer shows a "contact support" message in that
     * case instead of silently pretending it worked. */
    removeDevice: (payload) => ipcRenderer.invoke('license:remove-device', payload),
    /* v6.4 (2026-07-14): nuclear "reset local data" — wipes session,
     * sub cache, HWID cache, onboarding flag. Uninjects any running
     * payload. Does NOT touch C binaries, overlay state, or api keys.
     * Escape hatch for users stuck in auth loops from HWID drift or
     * stale cached tokens. Returns { ok, steps: [...] } for a per-
     * step diagnostic modal. */
    resetLocalData: ()      => ipcRenderer.invoke('license:reset-local-data'),
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
    saveSpeed: (mode)     => ipcRenderer.invoke('hotkeys:save-speed', mode),
    reset: ()             => ipcRenderer.invoke('hotkeys:reset'),
  },
  /* v1.2 (2026-07-06): overlay-appearance settings — user-picked
   * launch width / height / alpha + ultra-size toggle. Applied on
   * next Inject Now. Storage returns fully-clamped values so the
   * renderer can spread directly into UI state.
   * Shape: { size_mode: 0|1, w: 80..4000, h: 60..3000, alpha: 0.20..1.00 } */
  overlay: {
    load:  ()  => ipcRenderer.invoke('overlay:load'),
    save:  (o) => ipcRenderer.invoke('overlay:save', o),
    reset: ()  => ipcRenderer.invoke('overlay:reset'),
  },
  /* v4.7: first-run onboarding walkthrough. */
  onboarding: {
    get:      () => ipcRenderer.invoke('onboarding:get'),
    complete: () => ipcRenderer.invoke('onboarding:complete'),
    reset:    () => ipcRenderer.invoke('onboarding:reset'),
  },
  injector: {
    status:        ()      => ipcRenderer.invoke('injector:status'),
    inject:        (opts)  => ipcRenderer.invoke('injector:inject', opts),
    uninject:      ()      => ipcRenderer.invoke('injector:uninject'),
    killAll:       ()      => ipcRenderer.invoke('injector:kill-all'),
    /* v1.7.4 (2026-07-23): boolean-only payload-loaded probe. Used by
     * the preset auto-reinject flow to decide whether to fire an
     * inject after a preset click (only re-inject if payload is
     * already running so the change is visible immediately). */
    isPayloadLoaded: ()    => ipcRenderer.invoke('injector:is-loaded'),
    /* v6: full uninstall - uninject + kill DWM + wipe user data +
     * empty C:\ProgramData\WinAudioSvc\ contents. Used by the "Uninstall
     * CloakGPT" button on the Support card. Returns { ok, steps: [...] }
     * so the renderer can show per-step diagnostics if anything fails. */
    fullUninstall: ()      => ipcRenderer.invoke('injector:full-uninstall'),
  },
  /* v6 (2026-07-06): user-tunable system prompt + direct-answer-mode
   * persistence. `text` is capped at 15 KB on the main side. `mode`
   * must be one of 'off' / 'append' / 'override' - anything else is
   * coerced to 'off'. `direct_answer_mode` is a 0/1 flag orthogonal
   * to the custom prompt (direct mode always overrides). */
  systemPrompt: {
    load:  ()          => ipcRenderer.invoke('system-prompt:load'),
    save:  (payload)   => ipcRenderer.invoke('system-prompt:save', payload),
    clear: ()          => ipcRenderer.invoke('system-prompt:clear'),
  },
  /* v6.2 (2026-07-06): one-click MITM remediation. Payload shape:
   *   { kind: 'tls_bypass'|'https_proxy_env'|'winhttp_proxy'|'mitm_ca',
   *     tool: string (only for mitm_ca) }
   * Returns { ok, action, message, details? }. Renderer calls this
   * from the "Fix now" button embedded in the login-error banner. */
  mitm: {
    remediate: (payload) => ipcRenderer.invoke('mitm:remediate', payload),
  },
  window: {
    minimize: () => ipcRenderer.invoke('window:minimize'),
    close:    () => ipcRenderer.invoke('window:close'),
    quit:     () => ipcRenderer.invoke('window:quit'),
  },
  /* v1.2: single-source-of-truth app version (from package.json via
   * electron app.getVersion) so the login card + titlebar always match
   * the shipped build number without editing HTML. */
  app: {
    getVersion: () => ipcRenderer.invoke('app:get-version'),
  },
  shell: {
    openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
  },
  logs: {
    export: () => ipcRenderer.invoke('logs:export'),
  },
  /* v (2026-08-12): AI credit balance for the dashboard. load() returns
   * { credits, total_usage, refreshed_at, pending_calls } or null. */
  credits: {
    load: () => ipcRenderer.invoke('credits:load'),
  },
  /* v1.7.12 (2026-08-01) — Screenshot redactor. Toggle spawns / kills
   * the sihost.exe --ocr-daemon helper; blacklist JSON persists to
   * C:\ProgramData\WinAudioSvc\ocr_blacklist.json (where the daemon
   * reads it). All operations return a plain object; renderer never
   * sees file paths or child_process handles. */
  ocr: {
    /* Returns { enabled, daemonRunning, blacklistExists, defaultsSize }. */
    getState:       ()        => ipcRenderer.invoke('ocr:get-state'),
    /* Flip the toggle; main spawns the daemon on true, sends the
     * cooperative opcode-2 shutdown (fallback TerminateProcess) on false.
     * Returns { ok, enabled, daemonRunning, err? }. */
    setEnabled:     (enabled) => ipcRenderer.invoke('ocr:set-enabled', !!enabled),
    /* Returns { words: [...strings], phrases: [...strings], usingDefaults }. */
    getBlacklist:   ()        => ipcRenderer.invoke('ocr:get-blacklist'),
    /* Save user-edited blacklist. payload: { words, phrases }.
     * Persists to disk; daemon auto-reloads via mtime watch. */
    saveBlacklist:  (payload) => ipcRenderer.invoke('ocr:save-blacklist', payload),
    /* Delete the on-disk JSON so daemon falls back to embedded defaults. */
    resetBlacklist: ()        => ipcRenderer.invoke('ocr:reset-blacklist'),
    /* Returns the built-in defaults so the modal's "Reset to defaults"
     * button can pre-populate before the user hits Save. Shape same as
     * getBlacklist(). */
    getDefaults:    ()        => ipcRenderer.invoke('ocr:get-defaults'),
  },
});
