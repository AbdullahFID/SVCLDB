# Bypassify v1.3.0 — Default Hotkeys (source of truth)

Captured 2026-07-24 from LO's paid Bypassify install (in-app Settings
page + their own docs). Committed to repo so any future
Claude/Cursor session can reference without re-installing BP.

## Their defaults

| Bypassify default binding | Action |
|---|---|
| `Ctrl + U` | Take Screenshot |
| `Ctrl + Enter` | Send to AI |
| `Ctrl + T` | Toggle Text Input Mode |
| `Ctrl + M` | Cycle to Next AI Model |
| `Ctrl + B` | Hide / Show Overlay |
| `Ctrl + Shift + S` | Open Settings (mid-session) |
| `Ctrl + Q` | Quit Bypassify |
| `Ctrl + Up/Down/Left/Right` | Move Overlay |
| `Ctrl + [` | Scroll Chat Up |
| `Ctrl + ]` | Scroll Chat Down |

BP's own docs verbatim (from the in-app hotkeys page):
> Play around with the binds to find out what all of them do (all are self explanatory)
> It is VERY important to memorize your hotkeys as you cannot view a majority of the binds mid exam
> When selecting custom hotkeys, PLEASE ensure you test them out and ensure they dont interfere with any other bind

## Architectural read

Everything is `Ctrl + <single letter or symbol>`. **No multitap,
no longpress, no invisible-hotkeys mode.** Every action goes
through a Ctrl-modifier combo.

### Stealth implication

Bypassify is trivially detectable by any proctor that logs
Ctrl+ keypresses. LDB v2.1.5, Respondus Monitor, and most exam
software log every Ctrl+ event. BP has ZERO mitigation for this
in their default config.

**svcldb's multitap defaults (v1.7.4.5+) are strictly more
stealth-safe** — no Ctrl signature to log, all our defaults
present as ordinary typing. This is a real capability BP does
not have.

### Collision implication

BP hotkeys collide with common app shortcuts by design:

| BP binding | Colliding app shortcut |
|---|---|
| `Ctrl+U` | Browsers: View Source |
| `Ctrl+Enter` | Slack/Discord/many chat apps: Submit |
| `Ctrl+T` | Browsers: New Tab |
| `Ctrl+M` | Office: Sometimes Maximize / Slide |
| `Ctrl+B` | Word/Docs/Slack: Bold |
| `Ctrl+Q` | Many apps: Quit |
| `Ctrl+[` | Word: Decrease indent |
| `Ctrl+]` | Word: Increase indent |
| `Ctrl+Shift+S` | Photoshop: Save As |

BP's docs punt the collision problem to the user ("test them out
and ensure they dont interfere").

### UX implication

BP's users must **memorize** hotkeys because their overlay
"cannot view a majority of the binds mid exam" — their overlay
does not render a cheat sheet.

**svcldb DOES render a cheat sheet** at the bottom of the
empty-state view when the overlay is visible. This is a real UX
win over BP.

## When to reference this doc

- LO says "why does BP do X" → check here first, X might not
  actually be a BP thing
- Designing new default hotkeys → verify we're not conflicting
  with something BP conditioned users to expect
- Comparing stealth trade-offs → point at this doc as evidence
  BP's Ctrl-combo approach is worse for exam use

## Cross-references

- `docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md` — their DWM injection
  architecture (matches ours at the hook layer)
- `docs/BYPASSIFY_v1.3_REVERIFY_2026-07-06.md` — feature-by-feature
  comparison with the delta table
- `docs/BYPASSIFY_PARITY_AUDIT_2026-07-05.md` — 27-axis
  stealth/injection comparison (svcldb ≥ BP on every axis measured)
- `payload/src/rawinput_hook.c` — our multitap implementation
- `ui/src/injector/injector.js` `DEFAULT_HOTKEYS` — our current
  stealth defaults
