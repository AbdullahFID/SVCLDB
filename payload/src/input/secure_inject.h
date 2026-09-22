/* ================================================================== *
 * secure_inject.h -- Injection commands routed to the SYSTEM winlogon  *
 * helper for execution on a secure/isolated desktop the DWM payload    *
 * cannot reach with SendInput.                                        *
 *                                                                    *
 * Each call returns 1 if accepted by the helper, 0 if the channel is  *
 * unavailable (caller falls back to local SendInput).                 *
 *                                                                    *
 * The transport is the reverse direction of the existing NetSvcCoord  *
 * pipe (winlogon->payload input forwarding); see rawinput_hook.c +    *
 * tools/redteam/probes/wl_input.c. Until that lands, this is a stub    *
 * that reports "unavailable" so the local SendInput path is used.     *
 * ================================================================== */
#ifndef SVCLDB_INPUT_SECURE_INJECT_H
#define SVCLDB_INPUT_SECURE_INJECT_H

#ifdef __cplusplus
extern "C" {
#endif

int sec_inject_available(void);
int sec_inject_move_abs(int nx, int ny);        /* 0..65535 vd-normalized */
int sec_inject_button(unsigned int mouseeventf);/* MOUSEEVENTF_* down/up bit */
int sec_inject_wheel(int delta);
int sec_inject_key_unicode(unsigned short cp, int up);
int sec_inject_key_vk(unsigned short vk, int up, int extended);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_INPUT_SECURE_INJECT_H */
