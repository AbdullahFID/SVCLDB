# CloakGPT — Setup Guide

Everything you need to install and run CloakGPT on Windows 10 or 11.
Read once, top to bottom — takes ~5 minutes.

---

## 1. What you got

Inside `CloakGPTWindowsMaxStealth.zip`:

```
CloakGPTWindowsMaxStealth.zip
├── install-cloakgpt.ps1          ← one-click installer (recommended)
└── CloakGPT/                     ← the app folder
    ├── svchelper.exe             ← the launcher you double-click
    ├── resources/                ← app resources + bundled C binaries
    ├── locales/                  ← Chromium locale packs
    └── ... (Chromium runtime files, ~280 MB total)
```

Setup instructions (this document) ship alongside the zip as
`CloakGPT Setup Instructions.md`. If you download from our site the
zip and this doc arrive together; if someone else forwarded you the
zip, ask them for this doc too.

**Total size unzipped**: ~280 MB. Zip is ~125 MB.

---

## 2. System requirements

- **Windows 10** (version 20H2 or newer) or **Windows 11** (any version)
- **64-bit CPU** with AVX2 support (any laptop from 2015 or later)
- **Local admin** on the machine — the installer self-elevates via UAC, so
  right-click → Run with PowerShell is enough. If your account isn't a
  local admin, the UAC prompt will ask for an admin's credentials; type
  YOUR admin creds, not a different account (see "Shortcut missing" in
  Troubleshooting for why).
- **~400 MB free disk space**
- **Internet on first launch** (Google OAuth + subscription check + one-time
  Windows symbol download — subsequent launches can work offline for up
  to 24 hours)
- A **Google account** with an active CloakGPT subscription
- An **AI provider API key** (OpenAI, Anthropic, Google, or OpenRouter —
  configure all 4 for automatic failover if one rate-limits)

---

## 3. Turn off / bypass Windows Defender protections

**This is required** because CloakGPT injects a compositor overlay into
`dwm.exe`, which Windows Defender flags as suspicious (it looks similar
to techniques malware uses). Our app is not malware — but Defender's
heuristics don't know that.

You have three options, listed from **safest** (targeted) to **easiest**
(kills all Defender):

### Option A (recommended) — Add exclusions only

Windows Defender lets you exclude specific folders and processes from
scanning without turning off Real-Time Protection globally.

The app tries to add these exclusions itself on first launch, but that
only works if Real-Time Protection isn't set to "tamper-protected" (a
setting many home installs enable). If your first launch fails or the
exclusions don't stick, add them manually:

1. Press **Win** and type `Windows Security` → press Enter.
2. Click **Virus & threat protection** in the left sidebar.
3. Under **Virus & threat protection settings**, click **Manage settings**.
4. Scroll to **Exclusions**, click **Add or remove exclusions**.
5. Click **Yes** on the UAC prompt.
6. Click **Add an exclusion → Folder** and choose:
   `C:\ProgramData\WinAudioSvc`
7. Click **Add an exclusion → Process**. Add each of these one at a time:
   - `svchelper.exe`
   - `sihost.exe`
   - `dllhost32.exe`
   - `dwmapiext.dll`

Restart CloakGPT and it should now inject without Defender interference.

### Option B — Temporarily turn off Real-Time Protection

Faster if Option A is being difficult. Only recommended for the
duration of your exam.

1. Same **Virus & threat protection settings** page as above.
2. Toggle **Real-time protection** to **Off**.
3. Windows will nag you every ~30 min to re-enable it. Ignore.
4. Re-enable after your exam ends by toggling back to **On**.

### Option C — Turn off Tamper Protection first (advanced)

If both Option A and Option B fail because Windows blocks changes to
Defender settings, you're hitting Tamper Protection. Turn it off:

1. **Virus & threat protection settings** page.
2. Scroll to **Tamper Protection**, toggle it to **Off**.
3. Now Options A and B will work.

### If you use a THIRD-PARTY antivirus (Kaspersky, Bitdefender, Norton, etc.)

- Add the same folder + process exclusions in your AV's settings.
- Or temporarily disable real-time protection.
- Every AV has its own name for exclusion settings — search their docs
  for `"folder exclusion"` or `"process exclusion"`.

---

## 4. Install (30 seconds)

### The one-click way (recommended)

1. Unzip `CloakGPTWindowsMaxStealth.zip` **anywhere you want** — Desktop,
   Documents, wherever. Just remember where.
2. Open the unzipped folder.
3. **Right-click `install-cloakgpt.ps1`** → **Run with PowerShell**.
4. **Accept the UAC prompt** — the script auto-elevates itself. A new
   elevated PowerShell window will open; the original one will close.
5. If prompted about execution policy inside the elevated window, type
   **Y** and press Enter.
6. The installer will:
   - Kill any running CloakGPT (if you're upgrading from a previous version)
   - Clean up any old C binaries (config + your login are preserved)
   - Create a **`Launch CloakGPT`** shortcut on your Desktop with the
     Run-as-Administrator flag pre-set. If your Desktop can't be written
     to (AV blocking, corporate policy, redirected share offline), the
     installer falls back to the **All-Users Desktop**
     (`C:\Users\Public\Desktop`) so the shortcut is still visible.
   - Print either **`INSTALL COMPLETE`** (green) if the shortcut landed,
     or **`INSTALL PARTIAL - SHORTCUT MISSING`** (yellow) with a clear
     "launch manually here" path if it didn't.
7. Press Enter to close the installer window.

### The manual way

1. Unzip `CloakGPTWindowsMaxStealth.zip` anywhere.
2. Open the unzipped `CloakGPT` folder.
3. Right-click `svchelper.exe` → **Send to → Desktop (create shortcut)**.
4. Right-click the new Desktop shortcut → **Properties** → **Advanced**
   → check **Run as administrator** → OK → OK.

Either way you end up with the same thing: a Desktop shortcut named
`Launch CloakGPT` that runs elevated when double-clicked.

---

## 5. First launch (2 minutes)

1. Double-click **Launch CloakGPT** on your Desktop.
2. **Accept the UAC prompt** (Yes button).
3. **Splash screen** appears for 1-2 seconds while:
   - The bundled C binaries copy themselves into `C:\ProgramData\WinAudioSvc\`
   - The Defender exclusion request fires (silently — may fail depending
     on your Defender settings; see Section 3 above)
   - Your hardware ID is collected
4. **Login screen** — click **"Sign in with Google"**. Your default
   browser opens.
5. Complete Google sign-in. The browser lands on a **"You're All Set"**
   card with a cyan check ring. You can close that browser tab.
6. The CloakGPT app window transitions to the **Dashboard**.
7. **Configure your AI keys.** In the Dashboard you'll see 4 provider rows:
   - **OpenAI**  — paste your `sk-...` or `sk-proj-...` key
   - **Anthropic** — paste your `sk-ant-...` key
   - **Google** — paste your `AIza...` key
   - **OpenRouter** — paste your `sk-or-v1-...` key
   Click **Test** next to each key you paste — you'll see a green
   `OK · 126 models · 988ms` badge if the key works.
   **Configure at least ONE, or multiple for automatic failover.**
8. Click **"Inject Now"**. First arm takes ~30 seconds (Windows symbol
   download); subsequent arms are instant.
9. Status flips to green **"Payload: Active"**.
10. **Launch LockDown Browser.** The "LockDown Browser" badge on the
    Dashboard flips to `Running` within 2 seconds.

You're done. The overlay is now active inside LDB.

---

## 6. Hotkeys (learn these before your exam!)

All hotkeys use 2 or 3 modifier keys so they don't collide with LDB
or any other app. Overlay must be **Injected** (green Dashboard status)
for any hotkey to work.

### The critical ones
- **Ctrl+U** — Take a screenshot + ask the AI about it
- **Ctrl+B** — Toggle overlay show/hide
- **Ctrl+T** — Chat mode: type a question, press Enter to submit
  (uses a fresh screenshot as context; **Shift+Enter** for a new
  paragraph if your question needs multiple lines)
- **Ctrl+Alt+T** — Have it type the answer for you. Types whatever is
  on your clipboard into whatever app has focus (essay box, exam
  field, chat window, code editor — anything). Feels like a person
  typing, with natural rhythm. Press **Esc** to stop mid-way.
- **Ctrl+Alt+Y** — Same as above, but types the AI's last answer
  directly — no clipboard step needed.
- **Ctrl+Shift+Alt+T** — Type the PREVIOUS thing you copied (press
  again within 2 s to go further back through the last 5 items).
- **Ctrl+Shift+Alt+N** — Open (or close) the reference-notes editor.
  Paste formulas / definitions / study material once, and every
  question you ask automatically considers them. Kept private on your
  device.
- **Ctrl+Alt+S** — **STOP** an in-flight AI response (use if the AI is
  taking forever and you want to try a different question)
- **Ctrl+Alt+C** — Copy the AI's full last reply
- **Ctrl+Alt+A** — Copy just the direct answer (first line)
- **Ctrl+Alt+M** — Cycle model tier: Strong → Medium → Cheap
- **Ctrl+Shift+Alt+P** — Cycle AI provider: OA → AN → GG → OR

### Layout / display
- **Ctrl+Alt+Arrows** — Nudge the overlay (hold for continuous)
- **Ctrl+Shift+Alt+Arrows** — Resize the overlay
- **Ctrl+Alt+Q** — Cycle corner (TL / TR / BR / BL)
- **Ctrl+Alt+R** — Reset overlay position + size to defaults
- **Ctrl+Alt+ [ / ]** — Font size down / up
- **Ctrl+Alt+ + / -** — Background opacity
- **Ctrl+Alt+J / K** — Scroll chat down / up

### Chat / config
- **Ctrl+N** — New chat (wipes ALL messages, DESTRUCTIVE)
- **Ctrl+Enter** — Regenerate last AI reply
- **Ctrl+Shift+T** — Toggle live-streaming vs batched display of the
  AI's reply
- **Ctrl+Shift+Alt+L** — Toggle LaTeX vs plain Unicode math
- **Ctrl+Shift+Alt+C** — Copy just code blocks (concatenated)

### Emergency
- **Ctrl+Alt+X** — Clear reply / quit overlay (2-press to fully close)
- **Ctrl+Shift+Alt+K** — EMERGENCY STOP: unload overlay + terminate
  DWM (Windows respawns DWM in ~2 seconds; overlay is fully gone)
- **Ctrl+Shift+Alt+H** — Summon the CloakGPT app window back (if
  you closed / minimized it)
- **Ctrl+Shift+Alt+S** — Debug capture: saves 3 diagnostic screenshots
  to your Desktop (for support tickets)

Full hotkey list is also shown inside the app under **Overlay hotkeys**
on the Dashboard.

---

## 7. Troubleshooting

### "Installer said INSTALL COMPLETE but there's no shortcut on my Desktop"

**This should not happen with the v2 installer** (2026-08-06 and later).
The installer now writes to your Desktop AND falls back to the All-Users
Desktop, and reports `INSTALL PARTIAL - SHORTCUT MISSING` (yellow banner)
when it truly fails. If you see a green `INSTALL COMPLETE` there IS a
shortcut somewhere — check these locations in order:

1. **Your own Desktop** (obvious): `C:\Users\<you>\Desktop\Launch CloakGPT.lnk`
   - If it's in OneDrive-synced Desktop instead, look in
     `C:\Users\<you>\OneDrive\Desktop\Launch CloakGPT.lnk`
2. **All-Users Desktop** (fallback for Defender/AV-blocked cases):
   `C:\Users\Public\Desktop\Launch CloakGPT.lnk` — this shows up on
   every user's Desktop via Windows merging, might be hidden by the
   "Show hidden files" toggle in Explorer.
3. **Someone else's Desktop** (over-the-shoulder UAC): if you elevated
   with a different admin account (e.g. typed `Administrator`'s
   credentials when your own account isn't admin), the shortcut landed
   on THAT account's Desktop. Look in `C:\Users\Administrator\Desktop\`
   with elevation. The v2 installer detects this and ALSO writes to
   Public Desktop, so you should see it there too.

If you see **`INSTALL PARTIAL - SHORTCUT MISSING`** (yellow banner),
scroll up in the installer window to see the exact `[WARN]` line — it
tells you WHY (AV quarantine, WSH disabled, denied write, etc.). Launch
manually from the path printed in the banner (right-click →
Run as administrator), and re-run the installer after fixing the
underlying cause to get the shortcut.

### "UAC accepts, but no window appears"
- Windows Defender likely quarantined `svchelper.exe`. Go back to
  Section 3 and add the exclusions, then try again.
- Check `C:\ProgramData\WinAudioSvc\launcher.log` exists — if not,
  the app crashed before writing any diag.

### "Inject Now" shows "launcher missing"
- The bundled binaries didn't copy to `C:\ProgramData\WinAudioSvc\`.
  Cause: ACL problem or Defender quarantine.
- Fix: make sure you Ran As Administrator. Add Defender exclusions.
  Delete `C:\ProgramData\WinAudioSvc` and re-launch — the first-run
  install will retry.

### "Inject fails with exit code 11: handshake_token mismatch"
- Your hardware ID changed since you last signed in (BIOS/mobo swap,
  Windows re-activation, HDD swap).
- Fix: click **Sign Out** on the Dashboard, then Sign In again.

### "Resolver takes >2 minutes on first arm"
- The first arm downloads the DWM debug symbols from Microsoft's
  symbol server (`msdl.microsoft.com`). If your network is slow OR a
  corporate proxy is blocking it, this can hang.
- Fix: try again on a different network (mobile hotspot works). Once
  the symbols are cached locally, subsequent arms are instant.

### "Overlay never appears in LDB after Inject succeeded"
- Your Windows was recently updated → new `dwm.exe` version → cached
  symbols are stale.
- Fix: delete `C:\ProgramData\WinAudioSvc\offsets.blob` and click
  **Inject Now** again.

### "Immediate auto-logout with subscription no longer active"
- Either your subscription actually lapsed server-side, OR your local
  clock is more than 5 minutes off from the Supabase server clock
  (drift = suspected replay attack, we reject the response).
- Fix: sync your Windows clock (**Settings → Time & language → Date &
  time → Sync now**). If sub is actually inactive, renew it at
  `cloakgpt.ca/dashboard`.

### "AI answer is taking forever" (5+ minutes with no output)
- You're using a reasoning model (o3, gpt-5.5-pro, Opus 4.8, Gemini
  3.1 Pro) on a hard question. These have a **15-minute** timeout
  built in — don't kill it.
- If you want a faster answer, press **Ctrl+Alt+S** to abort, then
  press **Ctrl+Alt+M** to cycle down to Medium tier and re-ask.

### "Emergency Stop" needed mid-exam
- Press **Ctrl+Shift+Alt+K** — DWM restarts in ~2 seconds, the overlay
  is fully gone. Your screen briefly flashes black. LDB stays running.

### Something else weird
- Click **Export logs** on the CloakGPT Dashboard. It creates
  `cloakgpt-logs-<timestamp>.zip` on your Desktop. **Email that zip
  to support** — the logs inside are securely encrypted and only the
  CloakGPT team can read them. Zero personal info leaves your machine
  in a readable form.

---

## 8. Uninstall

The app has no traditional uninstaller. To remove:

1. **Sign out** from the CloakGPT Dashboard (this cleanly uninjects
   the overlay from DWM).
2. **Quit** the app (title-bar power icon → Yes on the confirm dialog).
3. **Delete** the `CloakGPT` folder wherever you extracted it.
4. **Delete** the `Launch CloakGPT` shortcut from your Desktop.
5. **Delete** `C:\ProgramData\WinAudioSvc` (this wipes cached config,
   session, API keys, and logs).
6. Optionally, remove the Windows Defender exclusions you added in
   Section 3 (Virus & threat protection settings → Exclusions).

---

## 9. Updating to a new version

When you get a new zip:

1. **Extract the new zip on top of the existing `CloakGPT` folder**
   (or delete the old folder first if you prefer a clean install).
2. Run `install-cloakgpt.ps1` from the new folder — it auto-detects
   the previous install, kills any running processes, cleans stale
   C binaries, refreshes the Desktop shortcut, and preserves your
   login + API keys.
3. Double-click **Launch CloakGPT**. That's it.

Your saved API keys, session, and hotkey preferences carry over
between versions.

---

## 10. Privacy note

- Your **API keys** are securely encrypted and stay on this device.
  Never stored in plain text.
- Your **session token** (from Google login) is stored the same way.
  24-hour expiry — you re-sign-in daily.
- **Nothing you type or screenshot is uploaded to us.** It goes
  directly from your machine to the AI provider (OpenAI, Anthropic,
  Google, or OpenRouter) whose key you configured. We can't read it.
- **All logs** written by the app are securely encrypted so only the
  CloakGPT team can read them. When you send logs for support they
  arrive encrypted — nobody on the wire (your ISP, email provider,
  etc.) can read them.
- The app registers Windows Defender exclusions **for its own
  binaries only** — it does not disable Defender globally or exclude
  anything else on your system.

Have fun and don't get caught.
