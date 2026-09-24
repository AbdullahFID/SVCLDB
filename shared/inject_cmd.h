/* ================================================================== *
 * inject_cmd.h -- Wire protocol for the winlogon reverse-inject       *
 * channel used by the human autotyper (and any future                 *
 * cross-desktop injection needs).                                     *
 *                                                                     *
 * v17 (2026-09-23). Payload runs inside dwm.exe on winsta0\Default.    *
 * When the user is on a SECURE/ISOLATED desktop (SEB, LDB kiosk,       *
 * WinLogon's own screen-locker desktop) our SendInput does NOT reach  *
 * that desktop -- SendInput posts to the CALLING THREAD's desktop.    *
 * The winlogon helper (wl_input.c, hosted inside winlogon.exe, SYSTEM  *
 * session 0, non-PPL) attaches to whichever desktop is currently      *
 * active via SetThreadDesktop(OpenInputDesktop()), so any SendInput    *
 * it makes hits the app the user is actually looking at.              *
 *                                                                     *
 * We piggy-back on the EXISTING duplex request/reply pipe that        *
 * ground.cpp uses for UIA (obf_pipe_iso_cmd() = a GUID-derived        *
 * NetSvcCoord-style pipe name). Same header, new opcodes.             *
 *                                                                     *
 * The header magic value 'UAA\0' (0x00415155) is retained for wire    *
 * compat -- the pipe was originally UIA-only; opcodes 3..7 are the   *
 * INJECT extensions. Add new opcodes at the bottom, never renumber.  *
 * ================================================================== */
#ifndef SVCLDB_SHARED_INJECT_CMD_H
#define SVCLDB_SHARED_INJECT_CMD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Match the UIA header exactly. */
#ifndef CMD_MAGIC
#define CMD_MAGIC   0x00415155u   /* 'UAA\0' little-endian */
#endif

/* Opcodes 1-2 already claimed by UIA (SNAP + ENUM); see ground.cpp
 * / wl_input.c. Do not renumber. */
#define CMD_OP_UIA_SNAP       1u
#define CMD_OP_UIA_ENUM       2u
/* v17 additions: */
#define CMD_OP_INJ_KEY_VK     3u
#define CMD_OP_INJ_KEY_UNI    4u
#define CMD_OP_INJ_KEY_SCAN   5u   /* KEYEVENTF_SCANCODE -- HKL-aware autotyper */
#define CMD_OP_INJ_MOUSE_MOVE 6u   /* absolute-virtualdesk normalized 0..65535   */
#define CMD_OP_INJ_MOUSE_BTN  7u   /* MOUSEEVENTF_* mask                          */
#define CMD_OP_INJ_MOUSE_WHL  8u   /* WHEEL delta                                 */

#pragma pack(push, 1)

/* Fixed 12-byte header, sent both ways. */
typedef struct {
    uint32_t magic;
    uint32_t opcode;
    uint32_t payload_len;
} cmd_hdr_t;

/* --- INJECT_KEY_VK payload: virtual-key + down/up + extended flag ---
 * Reply payload is empty (payload_len=0); presence of a reply header
 * with matching magic+opcode is the ack. */
typedef struct {
    uint16_t vk;
    uint8_t  down;      /* 1 = down, 0 = up */
    uint8_t  extended;  /* 1 = KEYEVENTF_EXTENDEDKEY */
} cmd_inj_key_vk_t;

/* --- INJECT_KEY_UNI payload: UTF-16 code unit + down/up flag ---
 * Send one wScan UNICODE make, then a matching break. Surrogate pairs
 * are sent as two consecutive requests (hi then lo). */
typedef struct {
    uint16_t code_unit;
    uint8_t  up;        /* 0 = down, 1 = up */
    uint8_t  pad;
} cmd_inj_key_uni_t;

/* --- INJECT_KEY_SCAN payload: SCANCODE make/break for HKL-aware typing.
 * We resolve VK / SC on the payload side using GetForegroundWindow +
 * GetKeyboardLayout so the helper doesn't need per-request FG lookups.
 * The helper does NOT synthesize modifier presses -- caller is
 * responsible for sending the SHIFT/CTRL/ALT down/up frames. */
typedef struct {
    uint16_t scan;
    uint8_t  up;        /* 0 = down, 1 = up */
    uint8_t  extended;  /* 1 = KEYEVENTF_EXTENDEDKEY (arrow keys etc.) */
} cmd_inj_key_scan_t;

/* --- INJECT_MOUSE_MOVE payload: normalized 0..65535 virtual-desktop coords */
typedef struct {
    uint16_t nx;
    uint16_t ny;
} cmd_inj_mouse_move_t;

/* --- INJECT_MOUSE_BTN payload: raw MOUSEEVENTF_* mask (LEFTDOWN etc.) */
typedef struct {
    uint32_t mouseeventf;
} cmd_inj_mouse_btn_t;

/* --- INJECT_MOUSE_WHL payload: wheel delta (positive = up) */
typedef struct {
    int32_t delta;
} cmd_inj_mouse_whl_t;

/* Universal reply body for all INJECT ops: 1 = SendInput returned N events,
 * 0 = failure. Helper always writes ONE of these bytes back so the caller
 * can distinguish "helper accepted + fired" from "helper gone". */
typedef struct {
    uint8_t ok;
} cmd_inj_reply_t;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_SHARED_INJECT_CMD_H */
