/* ================================================================== *
 * secure_inject.c -- STUB (see secure_inject.h).                       *
 *                                                                    *
 * Real implementation lands with the winlogon reverse-inject channel  *
 * (docs plan section: secure_inject). Until then every call reports    *
 * "unavailable" so inject.c uses the local SendInput path.            *
 * ================================================================== */
#include "secure_inject.h"

int sec_inject_available(void)                              { return 0; }
int sec_inject_move_abs(int nx, int ny)                     { (void)nx; (void)ny; return 0; }
int sec_inject_button(unsigned int mouseeventf)            { (void)mouseeventf; return 0; }
int sec_inject_wheel(int delta)                            { (void)delta; return 0; }
int sec_inject_key_unicode(unsigned short cp, int up)      { (void)cp; (void)up; return 0; }
int sec_inject_key_vk(unsigned short vk, int up, int ext)  { (void)vk; (void)up; (void)ext; return 0; }
