/* ================================================================== *
 * hwid.c — HWID derivation with WMIC / registry / SHA256 fallback.    *
 *                                                                    *
 * All native — no PowerShell, no child processes beyond wmic when   *
 * available. On Win11 24H2 where wmic is removed, we skip step 1    *
 * and fall through to MachineGuid. Same fallback chain as the JS    *
 * version so the resulting UUID matches across implementations.     *
 * ================================================================== */
#include "common.h"
#include "hwid.h"

#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

static char g_cache[80] = {0};

/* Run a child EXE, capture up to bufsize-1 bytes of stdout.
 * Returns bytes read or 0 on failure. Timeout is 5 seconds. */
static DWORD run_captured(const char *cmdline, char *buf, DWORD bufsize) {
    if (!cmdline || !buf || bufsize < 2) return 0;
    HANDLE r = NULL, w = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&r, &w, &sa, 0)) return 0;
    if (!SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0)) { CloseHandle(r); CloseHandle(w); return 0; }

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags   = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput= w;
    si.hStdError = w;
    si.hStdInput = INVALID_HANDLE_VALUE;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    /* Non-const command line — CreateProcess mutates it. */
    char cmd[512];
    _snprintf(cmd, sizeof(cmd) - 1, "%s", cmdline);
    cmd[sizeof(cmd) - 1] = '\0';

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(w);
    if (!ok) { CloseHandle(r); return 0; }

    DWORD total = 0;
    DWORD end = GetTickCount() + 5000;
    while (GetTickCount() < end && total < bufsize - 1) {
        DWORD avail = 0;
        if (!PeekNamedPipe(r, NULL, 0, NULL, &avail, NULL)) break;
        if (avail == 0) {
            if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) {
                /* Drain remaining. */
                if (!PeekNamedPipe(r, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
            } else continue;
        }
        DWORD toread = min(avail, bufsize - 1 - total);
        DWORD got = 0;
        if (!ReadFile(r, buf + total, toread, &got, NULL) || got == 0) break;
        total += got;
    }
    /* Ensure process ends. */
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(r);
    buf[total] = '\0';
    return total;
}

/* Read GUID from HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid. */
static int read_machine_guid(char *out, unsigned outsize) {
    HKEY k;
    /* KEY_WOW64_64KEY forces 64-bit view even when we're 32-bit. */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, sz = outsize;
    LONG r = RegQueryValueExA(k, "MachineGuid", NULL, &type, (LPBYTE)out, &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_SZ) return 0;
    /* Trim trailing NULs from REG_SZ. */
    while (sz > 0 && (out[sz - 1] == '\0' || out[sz - 1] == '\r' || out[sz - 1] == '\n')) sz--;
    if (sz == 0) return 0;
    out[sz < outsize ? sz : outsize - 1] = '\0';
    return 1;
}

/* Parse "UUID=..." out of wmic csproduct output. */
static int parse_wmic_uuid(const char *raw, char *out, unsigned outsize) {
    const char *k = strstr(raw, "UUID=");
    if (!k) k = strstr(raw, "uuid=");
    if (!k) return 0;
    k += 5;
    while (*k == ' ' || *k == '\t' || *k == '\r' || *k == '\n') k++;
    unsigned i = 0;
    while (*k && *k != '\r' && *k != '\n' && i < outsize - 1) {
        if (*k == ' ' || *k == '\t') { k++; continue; }
        out[i++] = *k++;
    }
    out[i] = '\0';
    if (i < 32) return 0;
    if (strchr(out, '-') == NULL) return 0;
    /* Reject the "FFFFFFFF-..." placeholder some VMs return. */
    if (strncmp(out, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", 36) == 0) return 0;
    return 1;
}

/* SHA-256(computer_name || volume_serial || 'salt') → formatted as UUID. */
static int fallback_uuid(char *out, unsigned outsize) {
    if (outsize < 40) return 0;
    char name[256];
    DWORD nlen = sizeof(name);
    if (!GetComputerNameA(name, &nlen)) name[0] = '\0';

    DWORD vol_serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &vol_serial, NULL, NULL, NULL, 0);

    BCRYPT_ALG_HANDLE alg;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return 0;
    BCRYPT_HASH_HANDLE h;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0); return 0;
    }
    static const char salt[] = "svcldb-hwid-fallback-v1";
    BCryptHashData(h, (PUCHAR)salt, sizeof(salt) - 1, 0);
    if (name[0]) BCryptHashData(h, (PUCHAR)name, (ULONG)strlen(name), 0);
    BCryptHashData(h, (PUCHAR)&vol_serial, sizeof(vol_serial), 0);

    UCHAR digest[32];
    BCryptFinishHash(h, digest, 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);

    _snprintf(out, outsize - 1,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        digest[0], digest[1], digest[2],  digest[3],  digest[4],  digest[5],
        digest[6], digest[7], digest[8],  digest[9],  digest[10], digest[11],
        digest[12],digest[13],digest[14], digest[15]);
    out[outsize - 1] = '\0';
    return 1;
}

int hwid_get(char *out, unsigned outsize) {
    if (!out || outsize < 40) return 0;
    out[0] = '\0';

    /* Try wmic first (matches JS version's fast path). */
    char raw[4096];
    if (run_captured("wmic csproduct get uuid /format:value", raw, sizeof(raw))) {
        if (parse_wmic_uuid(raw, out, outsize)) return 1;
    }
    /* MachineGuid. */
    if (read_machine_guid(out, outsize)) return 1;
    /* Deterministic hash fallback. */
    return fallback_uuid(out, outsize);
}

int hwid_get_cached(char *out, unsigned outsize) {
    if (!out || outsize < 40) return 0;
    if (g_cache[0] == '\0') {
        char tmp[80];
        if (!hwid_get(tmp, sizeof(tmp))) return 0;
        strncpy(g_cache, tmp, sizeof(g_cache) - 1);
        g_cache[sizeof(g_cache) - 1] = '\0';
    }
    strncpy(out, g_cache, outsize - 1);
    out[outsize - 1] = '\0';
    return 1;
}
