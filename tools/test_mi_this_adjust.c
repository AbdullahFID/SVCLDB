/* v7.6.0 -- MI this-adjust harness.
 *
 * Reproduces dharpan2010's layout in-process: GetPhysicalBackBuffer
 * lives on a SECONDARY vftable at obj+16. Calling it with the primary
 * object pointer returns a sentinel FAIL. Calling with obj+16 returns
 * OK. Mirrors payload/src/ui/imgui_layer.cpp::adjust_this.
 *
 * Build (from a vcvars64 shell):
 *   cl /nologo /W3 /O2 tools\test_mi_this_adjust.c /Fe:build\test_mi_this_adjust.exe
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#  define FASTCALL __fastcall
#else
#  define FASTCALL
#endif

typedef void *(FASTCALL *pfnVGet)(void *);

/* Fake CDDisplaySwapChain-like object:
 *   [0]  primary vptr   -- GetDevice at slot 0
 *   [8]  unused
 *   [16] secondary vptr -- GetPhysicalBackBuffer at slot 0 (our "slot 28")
 */
static void *FASTCALL fake_get_device(void *thisp) {
    (void)thisp;
    return (void *)(uintptr_t)0xDE01CE;
}

static void *FASTCALL fake_get_phys_bb(void *thisp) {
    /* Real method reads members relative to the SUBOBJECT this.
     * We encode "did you pass the secondary subobject?" as: the
     * callee's this must equal the address of the secondary vptr. */
    return thisp;
}

static void *g_primary_vtbl[4];
static void *g_secondary_vtbl[4];

static void *adjust_this(void *obj, int adj) {
    if (!obj || adj <= 0) return obj;
    return (unsigned char *)obj + adj;
}

int main(void) {
    unsigned char obj[32];
    memset(obj, 0, sizeof(obj));

    g_primary_vtbl[0]   = (void *)fake_get_device;
    g_secondary_vtbl[0] = (void *)fake_get_phys_bb;

    *(void ***)(obj + 0)  = g_primary_vtbl;
    *(void ***)(obj + 16) = g_secondary_vtbl;

    pfnVGet fn = (pfnVGet)g_secondary_vtbl[0];

    void *wrong = fn(obj);                 /* v7.3.0 bug */
    void *right = fn(adjust_this(obj, 16)); /* v7.6.0 fix */

    int fail_wrong = (wrong != (obj + 16));
    int fail_right = (right != (obj + 16));

    printf("unadjusted this -> %p  (expect secondary %p) %s\n",
           wrong, (void *)(obj + 16), fail_wrong ? "FAIL (this is the bug)" : "unexpected MATCH");
    printf("adjusted   this -> %p  (expect secondary %p) %s\n",
           right, (void *)(obj + 16), fail_right ? "FAIL" : "OK");

    if (fail_right) return 2;
    if (!fail_wrong) {
        printf("harness invalid: unadjusted call accidentally matched\n");
        return 3;
    }
    printf("PASS: this-adjust required and correct\n");
    return 0;
}
