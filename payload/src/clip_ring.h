/* ================================================================== *
 * clip_ring.h -- Small clipboard-history ring for the human autotyper. *
 *                                                                     *
 * v17 (2026-09-23). Tracks the last CLIP_RING_MAX (=5) unique text     *
 * clipboard entries the user has copied. Feeds two hotkeys:            *
 *                                                                     *
 *   Ctrl+Alt+T          -- autotype LATEST clipboard  (SVC_HK_AUTOTYPE_CLIP)
 *   Ctrl+Shift+Alt+T    -- autotype PREVIOUS entry, then previous-of-  *
 *                          previous, etc. Cycle resets after 2s idle.  *
 *                          (SVC_HK_CLIP_CYCLE = 43, added v17)         *
 *                                                                     *
 * Populated two ways:                                                  *
 *   1. Background poll thread ticks GetClipboardSequenceNumber() every  *
 *      500 ms; on change we read + push (dedupes consecutive dupes).   *
 *   2. `clip_ring_push_utf8()` is also called from human_type_start   *
 *      as a belt-and-suspenders (in case the user pasted in the       *
 *      middle of a session and the 500 ms poll hasn't fired yet).     *
 * ================================================================== */
#ifndef SVCLDB_CLIP_RING_H
#define SVCLDB_CLIP_RING_H

#ifdef __cplusplus
extern "C" {
#endif

#define CLIP_RING_MAX        5
#define CLIP_RING_ENTRY_MAX  8192   /* bytes per entry -- 8 KB fits most exam answers */

/* Start the background poll thread. Idempotent. Called once from
 * init_thread after hooks are up. */
void clip_ring_start(void);

/* v-audit-hardening (2026-09-23) -- shutdown-safe join.
 * Called from shutdown_watcher in dllmain.c before FreeLibraryAndExitThread
 * so the poll thread cannot outlive the payload's mapped pages.  Flips
 * a stop flag and joins with a bounded 1000ms wait.  Idempotent + safe
 * when never started (no-ops). */
void clip_ring_shutdown(void);

/* Push a UTF-8 string into the ring. Newest = index 0. Dedupes
 * consecutive duplicates so pasting the same text twice doesn't
 * waste a slot. Safe from any thread. Silently truncates entries
 * > CLIP_RING_ENTRY_MAX bytes. */
void clip_ring_push_utf8(const char *utf8);

/* Copy entry at `idx` (0=newest, 1=next-newest, ...) into `out`.
 * Returns bytes copied (excluding NUL); 0 if idx out of range or
 * that slot is empty. */
int  clip_ring_get(int idx, char *out, int cap);

/* Snapshot count of populated entries (1..CLIP_RING_MAX). */
int  clip_ring_count(void);

/* Cursor for the Ctrl+Shift+Alt+T "cycle" hotkey. Returns the current
 * cycle index [1..count-1], typing that entry into the target app.
 * The cycle resets to 1 after 2 s of no cycle-hotkey activity, so
 * pressing after a pause always starts at the second-newest entry. */
int  clip_ring_cycle_next(void);

/* Reset the cycle cursor immediately. Called by human_type_start on
 * a NON-cycle-hotkey run so the next Ctrl+Shift+Alt+T starts fresh. */
void clip_ring_cycle_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_CLIP_RING_H */
