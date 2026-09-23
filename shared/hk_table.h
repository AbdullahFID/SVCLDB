/* ==================================================================
 * hk_table.h -- Cross-process hotkey table shared between the payload
 * (dwm.exe, SYSTEM) and the winlogon helper (winlogon.exe, SYSTEM).
 *
 * WHY THIS EXISTS (v3.3 secure-desktop leak fix, 2026-09-23)
 *
 * The payload's local WH_KEYBOARD_LL fires on the Default desktop
 * BEFORE any app's window queue sees the event, so consuming a hotkey
 * (e.g. Ctrl+T = chat toggle) means the target app never sees it =
 * zero leak. On an isolated/secure desktop (SEB or any user-created
 * desktop) the payload cannot install its LL hook there -- DWM's
 * virtual account can't adopt the foreign desktop. So the winlogon
 * helper's LL hook is the ONLY thing that runs before the target
 * app's queue.
 *
 * The helper's LL hook needs to know which key events to swallow:
 *   - Chat-typing mode ON: swallow everything except the emergency
 *     kill chord.
 *   - Registered hotkey combo pressed: swallow the DOWN/UP for that
 *     vk so the target app never sees it.
 *   - "Deep hide" flag ON: swallow standalone Ctrl/Shift/Alt too.
 *
 * The chat-mode signal is a named event (see obf_event_iso_chat).
 * The hotkey list + flags live in THIS TABLE, written by the payload
 * to disk under a locked DACL, read by the helper each time the reader
 * attaches to an isolated desktop + refreshed on WM_TIMER cadence.
 *
 * DACL: SYSTEM + Admins full control, nothing else. Prevents a med-IL
 * hunter from (a) reading the hotkey binding IOC set OR (b) forging a
 * table that would make the helper swallow arbitrary keys as a DoS.
 *
 * On-disk path: C:\ProgramData\WinAudioSvc\_hk.bin
 * Total size: 20 bytes header + 64 * 4 bytes hotkeys = 276 bytes.
 *
 * Layout is #pragma pack(1) so the payload's writer + helper's reader
 * agree on offsets without regard to compiler default alignment.
 * ================================================================== */
#ifndef SVCLDB_HK_TABLE_H
#define SVCLDB_HK_TABLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic: 'HKTB' little-endian. Header stamp so a garbage read produces
 * an obviously-wrong value the reader rejects instead of misparsing. */
#define SVC_HK_TABLE_MAGIC       0x42544B48u

/* Version: bump on any layout change. Reader must match exactly. */
#define SVC_HK_TABLE_VERSION     1u

/* Fixed count -- matches svc_config_t::hotkeys[] slot count. If the
 * hotkey enum grows past 64 the config_types.h static_assert will fire
 * FIRST; bump this AND version together. */
#define SVC_HK_TABLE_COUNT       64u

/* Filesystem path -- must match the payload's writer + helper's reader
 * byte-for-byte. Kept as a compile-time literal so both TUs agree. */
#define SVC_HK_TABLE_PATH        "C:\\ProgramData\\WinAudioSvc\\_hk.bin"

/* Flag bits (helper-consumed). */
#define SVC_HK_TABLE_F_SILENT_MODS   0x1u    /* mirrors SVC_OVFLAG_SILENT_MODS */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;       /* == SVC_HK_TABLE_MAGIC        */
    uint32_t version;     /* == SVC_HK_TABLE_VERSION      */
    uint32_t count;       /* == SVC_HK_TABLE_COUNT        */
    uint32_t flags;       /* SVC_HK_TABLE_F_* bitfield    */
    uint32_t hotkeys[64]; /* packed (kind<<24)|(extra<<16)|vk, same
                           * format as svc_config_t::hotkeys[]. Zero
                           * = unbound slot. */
} svc_hk_table_t;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_HK_TABLE_H */
