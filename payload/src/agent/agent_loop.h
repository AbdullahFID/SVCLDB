/* ================================================================== *
 * agent_loop.h -- Agent Mode: long-horizon screen-control loop.        *
 *                                                                    *
 * v1 uses the shared vision+JSON stack (capture -> grid -> ask model    *
 * for the next actions in image space -> dispatch -> repeat) with       *
 * budget / step / wall-clock / no-progress guards, reusing the exact    *
 * AutoSolver primitives (ai_ask, imgproc, ground, actions). Unlike      *
 * AutoSolver it MAY navigate/submit to complete the whole task.         *
 *                                                                    *
 * Upgrade path (documented in the plan doc): swap the per-turn call for  *
 * the vendor computer-use tools (Anthropic computer_20250124 / OpenAI    *
 * computer_use_preview / Gemini 2.5-computer-use) behind this same API.  *
 * ================================================================== */
#ifndef SVCLDB_AGENT_LOOP_H
#define SVCLDB_AGENT_LOOP_H

#ifdef __cplusplus
extern "C" {
#endif

void agent_start(void);          /* start with the pending/preset task */
void agent_stop(void);           /* stop (also ESC / Ctrl+Alt+S) */
void agent_pause_toggle(void);   /* pause <-> resume */
int  agent_is_active(void);
void agent_set_task(const char *utf8);   /* optional custom task (else preset) */

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_AGENT_LOOP_H */
