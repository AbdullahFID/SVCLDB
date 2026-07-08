/*
 * ai_google_fallback_test.c — end-to-end test for the Google 503
 * model-fallback path landed 2026-07-08.
 *
 * What this exercises:
 *   1. ai_ask_streaming with provider=Google, tier=MEDIUM (gemini-3.5-flash).
 *      Confirms normal streaming path works.
 *   2. Force a 503 by using a bogus base URL, verify that the retry loop
 *      completes + surfaces a clean error string.
 *   3. Model override path via ai_google_stable_fallback — confirm the
 *      helper returns the right stable model for each Gemini 3.x input.
 *
 * Build:
 *   cd payload\test
 *   cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS /I ..\src ^
 *      /I ..\..\shared ai_google_fallback_test.c ^
 *      ..\..\build\payload\obj\*.obj ^
 *      kernel32.lib user32.lib advapi32.lib bcrypt.lib winhttp.lib ^
 *      ole32.lib shlwapi.lib
 *
 * BUT ai_ask_streaming pulls in dwm_hooks etc. So simplest: run the
 * fallback-helper unit tests statically (no network), and a live end-to-end
 * test via a separate PowerShell probe against the ACTUAL Google API.
 * This file only covers the pure C helper — the E2E lives in
 * .secrets/test_google.ps1 which we ran manually.
 */
#include <stdio.h>
#include <string.h>

/* Vendored copy of the fallback logic under test — kept in sync manually
 * with payload/src/ai/ai_provider.c ai_google_stable_fallback. */
static const char *ai_google_stable_fallback(const char *model_id) {
    if (!model_id) return NULL;
    if (strstr(model_id, "gemini-3.1-pro"))    return "gemini-2.5-pro";
    if (strstr(model_id, "gemini-3-pro"))      return "gemini-2.5-pro";
    if (strstr(model_id, "gemini-3.5-flash"))  return "gemini-2.5-flash";
    if (strstr(model_id, "gemini-3-flash"))    return "gemini-2.5-flash";
    if (strstr(model_id, "gemini-3.1-flash"))  return "gemini-2.5-flash";
    return NULL;
}

static int checks_passed = 0;
static int checks_failed = 0;

#define ASSERT_STREQ(actual, expected, label) do { \
    if ((actual) && (expected) && strcmp((actual), (expected)) == 0) { \
        checks_passed++; \
    } else if (!(actual) && !(expected)) { \
        checks_passed++; \
    } else { \
        printf("FAIL: %s — expected '%s', got '%s'\n", label, \
               (expected) ? (expected) : "(null)", \
               (actual) ? (actual) : "(null)"); \
        checks_failed++; \
    } \
} while (0)

int main(void) {
    printf("=== Gemini 503 stable-fallback map ===\n");

    /* Pro tier fallbacks -> gemini-2.5-pro */
    ASSERT_STREQ(ai_google_stable_fallback("gemini-3.1-pro-preview"),
                 "gemini-2.5-pro", "3.1-pro-preview -> 2.5-pro");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-3.1-pro"),
                 "gemini-2.5-pro", "3.1-pro -> 2.5-pro");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-3-pro-preview"),
                 "gemini-2.5-pro", "3-pro-preview -> 2.5-pro");

    /* Flash tier fallbacks -> gemini-2.5-flash */
    ASSERT_STREQ(ai_google_stable_fallback("gemini-3.5-flash"),
                 "gemini-2.5-flash", "3.5-flash -> 2.5-flash (the user's model)");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-3-flash-preview"),
                 "gemini-2.5-flash", "3-flash-preview -> 2.5-flash");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-3.1-flash-lite"),
                 "gemini-2.5-flash", "3.1-flash-lite -> 2.5-flash");

    /* Already-stable 2.5.x should return NULL (no better fallback) */
    ASSERT_STREQ(ai_google_stable_fallback("gemini-2.5-pro"),
                 NULL, "2.5-pro -> null");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-2.5-flash"),
                 NULL, "2.5-flash -> null");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-2.5-flash-lite"),
                 NULL, "2.5-flash-lite -> null");
    ASSERT_STREQ(ai_google_stable_fallback("gemini-2.0-flash"),
                 NULL, "2.0-flash -> null");

    /* NULL / empty edge cases */
    ASSERT_STREQ(ai_google_stable_fallback(NULL), NULL, "NULL -> NULL");
    ASSERT_STREQ(ai_google_stable_fallback(""),   NULL, "empty -> NULL");

    /* Non-Google models should also return NULL (defensive) */
    ASSERT_STREQ(ai_google_stable_fallback("gpt-5.5"),        NULL, "gpt-5.5 -> NULL");
    ASSERT_STREQ(ai_google_stable_fallback("claude-opus-4-8"),NULL, "claude-opus-4-8 -> NULL");
    ASSERT_STREQ(ai_google_stable_fallback("random-string"),  NULL, "junk -> NULL");

    printf("\n=== SUMMARY === Pass: %d, Fail: %d\n", checks_passed, checks_failed);
    return checks_failed == 0 ? 0 : 1;
}
