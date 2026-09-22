/* ================================================================== *
 * inject.h -- Low-level input injection primitives (SendInput).        *
 *                                                                    *
 * These are the ONLY code paths in svcldb that synthesize input.      *
 * Everything is gated by the synth guard so the mouse-hold trigger,   *
 * the desktop watcher and the LL hooks never react to our own input.   *
 *                                                                    *
 * Stealth note: svcldb has no signed kernel driver, so injection uses  *
 * SendInput (sets LLKHF_INJECTED). Per the LDB RE (docs/imported/      *
 * ldb_full_re_detection_pipeline.md) LDB's detection is cookie-based   *
 * with NO synthetic-input detector, and browser proctors cannot read   *
 * the injected flag. The real constraints are: never steal focus       *
 * (rldbfocus) and humanize motion/timing (behavioral analysis) -- both *
 * handled above this layer (motion.c / actions.c). On a secure/        *
 * isolated desktop, calls route to the SYSTEM winlogon helper.         *
 * ================================================================== */
#ifndef SVCLDB_INPUT_INJECT_H
#define SVCLDB_INPUT_INJECT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Synthetic-input guard. Set 1 around all injection, 0 when done. */
void inj_set_synth(int on);
int  inj_is_synth(void);

/* Route injection through the winlogon SYSTEM helper (secure desktop). */
void inj_set_secure(int on);
int  inj_secure(void);

/* Raw mouse. Coordinates for inj_move_abs are 0..65535 over the virtual
 * desktop; inj_move_screen takes physical screen pixels. */
void inj_move_abs(int nx, int ny);
void inj_move_screen(int screen_x, int screen_y);
void inj_lbtn(int down);          /* 1 = down, 0 = up */
void inj_rbtn(int down);
void inj_mbtn(int down);
void inj_wheel(int delta);        /* +120 = up, -120 = down (per notch) */

/* Raw keyboard. inj_char emits a full down+up Unicode keystroke and
 * handles codepoints outside the BMP via surrogate pairs. */
void inj_char(unsigned int codepoint);
void inj_vk(unsigned short vk, int down, int extended);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_INPUT_INJECT_H */
