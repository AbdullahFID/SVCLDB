/* ================================================================== *
 * ocr_scanner.cpp -- Windows.Media.Ocr (WinRT) redactor pipeline.      *
 *                                                                    *
 * Runs in sihost's --ocr-daemon mode. sihost is a normal PE with     *
 * full CRT init, so WinRT apartment init + activation factory work   *
 * out of the box -- this is exactly why the design puts the OCR      *
 * pipeline in sihost rather than the manual-mapped payload.          *
 *                                                                    *
 * See ocr_scanner.h for the C-callable interface + the pipe wire     *
 * format. Handoff blueprint: docs/imported/ or hooksdll/docs/        *
 * handoffs/HANDOFF_OCR_BLACKOUT_PORTABLE_REFERENCE_2026-08-01.md.    *
 * ================================================================== */

#include "ocr_scanner.h"

/* Kill the windows.h min/max macros -- they collide with std::min/std::max
 * and with parameters named max/min (breaks Levenshtein's `int max`). */
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cmath>
#include <cctype>
#include <mutex>
#include <algorithm>
#include <utility>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Globalization.h>
#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.Media.Ocr.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.Security.Cryptography.h>

#include "../../../shared/log_secure.h"

using winrt::hresult_error;
using winrt::hstring;
using winrt::init_apartment;
using winrt::apartment_type;
using winrt::com_array;
using winrt::Windows::Foundation::Rect;
using winrt::Windows::Storage::Streams::IBuffer;
using winrt::Windows::Security::Cryptography::CryptographicBuffer;
using winrt::Windows::Graphics::Imaging::SoftwareBitmap;
using winrt::Windows::Graphics::Imaging::BitmapPixelFormat;
using winrt::Windows::Media::Ocr::OcrEngine;
using winrt::Windows::Media::Ocr::OcrResult;
using winrt::Windows::Globalization::Language;

/* ── Global engine state ─────────────────────────────────────────── */

namespace {

struct Rect2D {
    float x, y, w, h;
};

struct WordEntry {
    std::string norm;   /* lowercased, edge-punct-stripped */
    int         padding;
    int         fuzzy;  /* 0=strict, 1-2=Levenshtein tolerance */
};

struct BlacklistState {
    std::vector<WordEntry>   words;
    std::vector<std::string> phrases;   /* lowercased substring needles */
    int  pad_default = 6;
    bool case_insensitive = true;

    /* File-watch metadata so we know when to reload. */
    std::string path;
    uint64_t    last_mtime100ns = 0;
    uint64_t    last_size = 0;
    bool        loaded_from_defaults = true;
};

/* Global-ish state (this TU is only touched from the daemon thread). */
OcrEngine       g_engine{ nullptr };
BlacklistState  g_bl;
int             g_lang_count = 0;
std::once_flag  g_apartment_once;

/* ── Embedded defaults (compact -- Electron ships the full JSON) ── */

const char *k_default_words[] = {
    "midterm","midterms","final","finals",
    "proctored","invigilated","invigilator",
    "quiz","quizzes","examination","examinations",
    "submit","submitted","submission",
    "attempt","attempts","retake",
    "graded","autograded","flagged",
    "violation","incident","monitored","recorded",
    "proctor","prohibited","forbidden",
    "restricted","blocked","locked","lockdown","timed",
    "cheating","plagiarism","misconduct","integrity",
    "collusion","fabrication",
    "grade","grades","rubric","marks","scored",
    /* Common LMS/proctor brand tokens as whole words too */
    "respondus","proctorio","honorlock","examsoft","examity",
    "proctoru","examplify","proctortrack","meazure","proctor360",
    "canvas","blackboard","moodle","turnitin","gradescope",
    "brightspace","d2l","instructure","schoology",
    NULL
};

const char *k_default_phrases[] = {
    /* Product-name variants */
    "lock down browser","lockdown browser","safe exam browser",
    "respondus monitor","proctor u","honor lock","exam soft",
    /* Webcam / biometric UI */
    "face not detected","no face detected","multiple faces",
    "looking away","identity verification","verify your identity",
    "photo id required","show your id","government id",
    "face match","facial recognition","room scan",
    "webcam required","camera required","microphone required",
    /* Session / lock */
    "browser locked","screen locked","session locked",
    "recording in progress","being recorded","being monitored",
    "proctored session","proctored exam","proctored test",
    "you are being monitored","monitoring active",
    /* Focus / tab warnings */
    "you left the exam","left the exam window","focus lost",
    "tab switch detected","you switched tabs","new window detected",
    /* Integrity */
    "academic integrity","honor code","academic misconduct",
    "will be reported","has been flagged","violation detected",
    "suspicious activity","integrity violation","code of conduct",
    /* Restriction banners */
    "copy disabled","paste disabled","right click disabled",
    "screen sharing","screen recording","clipboard disabled",
    "print screen disabled","screenshot disabled",
    /* Time */
    "time remaining","time left","minutes remaining",
    "auto submit","will auto-submit","time expired","time is up",
    /* LMS UI */
    "submit quiz","submit exam","submit test","submit attempt",
    "finish attempt","end attempt","save and submit",
    NULL
};

/* ── Tiny utilities ──────────────────────────────────────────────── */

void log_line(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    slog_writef("launcher.log", "ocr_daemon: %s", buf);
}

/* Strip leading/trailing non-alphanumeric bytes (ASCII scope only --
 * WinRT already handed us UTF-8 word tokens; word-level trimming
 * matches the JS reference's /^[^\p{L}\p{N}]+|.../ well enough for
 * proctor-string matching). */
std::string norm_token(std::string_view s) {
    size_t i = 0, j = s.size();
    while (i < j && !isalnum((unsigned char)s[i])) ++i;
    while (j > i && !isalnum((unsigned char)s[j - 1])) --j;
    std::string out;
    out.reserve(j - i);
    for (size_t k = i; k < j; ++k) {
        unsigned char c = (unsigned char)s[k];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        out.push_back((char)c);
    }
    return out;
}

/* Lowercase in place (ASCII). */
void ascii_lower(std::string &s) {
    for (auto &c : s) {
        unsigned char u = (unsigned char)c;
        if (u >= 'A' && u <= 'Z') c = (char)(u - 'A' + 'a');
    }
}

/* Bounded Levenshtein with row-min early exit. Returns distance or
 * `max+1` if it exceeded `max`. */
int lev_bounded(const std::string &a, const std::string &b, int max) {
    int la = (int)a.size(), lb = (int)b.size();
    if (std::abs(la - lb) > max) return max + 1;
    if (la == 0) return lb <= max ? lb : max + 1;
    if (lb == 0) return la <= max ? la : max + 1;

    std::vector<int> prev(lb + 1), cur(lb + 1);
    for (int j = 0; j <= lb; ++j) prev[j] = j;

    for (int i = 1; i <= la; ++i) {
        cur[0] = i;
        int row_min = cur[0];
        for (int j = 1; j <= lb; ++j) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int del  = prev[j] + 1;
            int ins  = cur[j - 1] + 1;
            int sub  = prev[j - 1] + cost;
            cur[j] = std::min({del, ins, sub});
            if (cur[j] < row_min) row_min = cur[j];
        }
        if (row_min > max) return max + 1;
        std::swap(prev, cur);
    }
    return prev[lb];
}

/* Rect union -- dedupe touching/overlapping rects with a cheap greedy
 * pass. O(n²) but n is tiny (typically < 30 rects per frame). */
bool rects_overlap_or_touch(const Rect2D &a, const Rect2D &b) {
    return !(a.x + a.w < b.x - 1 || b.x + b.w < a.x - 1 ||
             a.y + a.h < b.y - 1 || b.y + b.h < a.y - 1);
}
Rect2D rect_union(const Rect2D &a, const Rect2D &b) {
    float x0 = std::min(a.x, b.x);
    float y0 = std::min(a.y, b.y);
    float x1 = std::max(a.x + a.w, b.x + b.w);
    float y1 = std::max(a.y + a.h, b.y + b.h);
    return { x0, y0, x1 - x0, y1 - y0 };
}
void merge_rects_inplace(std::vector<Rect2D> &rs) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < rs.size() && !changed; ++i) {
            for (size_t j = i + 1; j < rs.size(); ++j) {
                if (rects_overlap_or_touch(rs[i], rs[j])) {
                    rs[i] = rect_union(rs[i], rs[j]);
                    rs.erase(rs.begin() + (ptrdiff_t)j);
                    changed = true;
                    break;
                }
            }
        }
    }
}

/* ── BGRA in-place black paint ──────────────────────────────────── *
 * Direct byte-fill -- never blend, never OR (see handoff §11.7 -- a
 * translucent blackout leaks text through the JPEG alpha channel). */
void paint_rects_black(uint8_t *bgra, uint32_t w, uint32_t h,
                       const std::vector<Rect2D> &rects, int pad) {
    for (const auto &r : rects) {
        int x0 = (int)std::floor(r.x) - pad;
        int y0 = (int)std::floor(r.y) - pad;
        int x1 = (int)std::ceil (r.x + r.w) + pad;
        int y1 = (int)std::ceil (r.y + r.h) + pad;
        if (x0 < 0) x0 = 0;
        if (y0 < 0) y0 = 0;
        if (x1 > (int)w) x1 = (int)w;
        if (y1 > (int)h) y1 = (int)h;
        if (x1 <= x0 || y1 <= y0) continue;
        for (int y = y0; y < y1; ++y) {
            uint8_t *row = bgra + ((size_t)y * w + (size_t)x0) * 4;
            for (int x = x0; x < x1; ++x) {
                row[0] = 0x00; row[1] = 0x00; row[2] = 0x00; row[3] = 0xFF;
                row += 4;
            }
        }
    }
}

/* ── Blacklist JSON parsing ─────────────────────────────────────── *
 * Deliberately tiny -- the reference uses ~50 words + ~350 phrases,
 * no numeric fields worth pulling in a full JSON lib for. Format:
 *   {
 *     "words":   [ "midterm", "final", { "match": "prctorio", "padding": 8, "fuzzy": 1 } ],
 *     "phrases": [ "screen recording", "session locked" ],
 *     "options": { "caseInsensitive": true, "padDefault": 6 }
 *   }
 *
 * Strings-only entries in `words` use the default padding/fuzzy.
 * Object entries can override per-word.
 *
 * Parser is intentionally permissive -- any parse failure falls back
 * to defaults + logs. The daemon must never crash on a bad JSON. */

static bool file_read_all(const char *path, std::string &out) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 4 * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    out.resize((size_t)sz.QuadPart);
    DWORD r = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)sz.QuadPart, &r, NULL);
    CloseHandle(h);
    if (!ok || r != (DWORD)sz.QuadPart) return false;
    return true;
}

/* Extract next JSON string literal starting at position `i`. Returns
 * end index (past closing quote) or SIZE_MAX on failure. Fills `out`
 * with the unescaped body. Handles \" \\ \n \r \t \/ \b \f. */
static size_t json_next_string(std::string_view s, size_t i, std::string &out) {
    out.clear();
    while (i < s.size() && s[i] != '"') ++i;
    if (i >= s.size()) return SIZE_MAX;
    ++i;
    while (i < s.size() && s[i] != '"') {
        char c = s[i++];
        if (c == '\\' && i < s.size()) {
            char e = s[i++];
            switch (e) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                default:   out.push_back(e); break;   /* skip \uXXXX for MVP */
            }
        } else {
            out.push_back(c);
        }
    }
    if (i >= s.size()) return SIZE_MAX;
    return i + 1;   /* skip closing quote */
}

/* Locate a top-level array by key. Returns [start_after_bracket, end_before_bracket]
 * or {SIZE_MAX,SIZE_MAX} on miss. Naive -- assumes well-formed JSON with the
 * key at depth 1. Good enough for the well-defined schema we ship. */
static std::pair<size_t,size_t> json_find_array(std::string_view s, const char *key) {
    std::string tag = "\"" + std::string(key) + "\"";
    size_t at = s.find(tag);
    if (at == std::string::npos) return {SIZE_MAX, SIZE_MAX};
    size_t lb = s.find('[', at);
    if (lb == std::string::npos) return {SIZE_MAX, SIZE_MAX};
    int depth = 1;
    size_t i = lb + 1;
    while (i < s.size() && depth > 0) {
        char c = s[i];
        if (c == '[') ++depth;
        else if (c == ']') --depth;
        else if (c == '"') {
            /* skip a string atomically */
            std::string sink;
            size_t next = json_next_string(s, i, sink);
            if (next == SIZE_MAX) return {SIZE_MAX, SIZE_MAX};
            i = next;
            continue;
        }
        ++i;
    }
    if (depth != 0) return {SIZE_MAX, SIZE_MAX};
    return {lb + 1, i - 1};
}

static void parse_words_array(std::string_view arr, std::vector<WordEntry> &out,
                              int pad_default) {
    size_t i = 0;
    while (i < arr.size()) {
        char c = arr[i];
        if (c == ' ' || c == ',' || c == '\n' || c == '\r' || c == '\t') { ++i; continue; }
        if (c == '"') {
            std::string s;
            size_t next = json_next_string(arr, i, s);
            if (next == SIZE_MAX) break;
            std::string n = norm_token(s);
            if (!n.empty()) out.push_back({ n, pad_default, 0 });
            i = next;
        } else if (c == '{') {
            /* Object form: {"match":"prctorio","padding":8,"fuzzy":1} */
            int depth = 1;
            size_t j = i + 1;
            std::string match; int padding = pad_default; int fuzzy = 0;
            while (j < arr.size() && depth > 0) {
                if (arr[j] == '{') ++depth;
                else if (arr[j] == '}') --depth;
                else if (arr[j] == '"') {
                    std::string key;
                    size_t k = json_next_string(arr, j, key);
                    if (k == SIZE_MAX) break;
                    /* skip whitespace + colon */
                    while (k < arr.size() && (arr[k] == ' ' || arr[k] == ':' || arr[k] == '\t')) ++k;
                    if (k < arr.size() && arr[k] == '"') {
                        std::string val;
                        k = json_next_string(arr, k, val);
                        if (k == SIZE_MAX) break;
                        if (key == "match") match = val;
                    } else {
                        /* numeric */
                        char numbuf[32] = {0};
                        size_t nb = 0;
                        while (k < arr.size() && nb < sizeof(numbuf) - 1 &&
                               (isdigit((unsigned char)arr[k]) || arr[k] == '-' || arr[k] == '.')) {
                            numbuf[nb++] = arr[k++];
                        }
                        int v = atoi(numbuf);
                        if (key == "padding") padding = v;
                        else if (key == "fuzzy") fuzzy = std::clamp(v, 0, 2);
                    }
                    j = k;
                    continue;
                }
                ++j;
            }
            if (!match.empty()) {
                std::string n = norm_token(match);
                if (!n.empty()) out.push_back({ n, padding, fuzzy });
            }
            i = j;
        } else {
            ++i;
        }
    }
}

static void parse_phrases_array(std::string_view arr, std::vector<std::string> &out) {
    size_t i = 0;
    while (i < arr.size()) {
        char c = arr[i];
        if (c == ' ' || c == ',' || c == '\n' || c == '\r' || c == '\t') { ++i; continue; }
        if (c == '"') {
            std::string s;
            size_t next = json_next_string(arr, i, s);
            if (next == SIZE_MAX) break;
            ascii_lower(s);
            if (!s.empty()) out.push_back(std::move(s));
            i = next;
        } else {
            ++i;
        }
    }
}

static void load_defaults_into(BlacklistState &bl) {
    bl.words.clear();
    bl.phrases.clear();
    for (const char **p = k_default_words; *p; ++p) {
        std::string n = norm_token(*p);
        if (!n.empty()) bl.words.push_back({ n, bl.pad_default, 0 });
    }
    for (const char **p = k_default_phrases; *p; ++p) {
        std::string s = *p;
        ascii_lower(s);
        if (!s.empty()) bl.phrases.push_back(std::move(s));
    }
    bl.loaded_from_defaults = true;
    log_line("loaded defaults: %zu words, %zu phrases",
             bl.words.size(), bl.phrases.size());
}

static void load_json_into(BlacklistState &bl, const std::string &body) {
    bl.words.clear();
    bl.phrases.clear();
    /* padDefault */
    size_t at = body.find("\"padDefault\"");
    if (at != std::string::npos) {
        size_t colon = body.find(':', at);
        if (colon != std::string::npos) {
            int v = atoi(body.c_str() + colon + 1);
            if (v > 0 && v < 32) bl.pad_default = v;
        }
    }
    auto [ws, we] = json_find_array(body, "words");
    if (ws != SIZE_MAX) {
        parse_words_array(std::string_view(body).substr(ws, we - ws),
                          bl.words, bl.pad_default);
    }
    auto [ps, pe] = json_find_array(body, "phrases");
    if (ps != SIZE_MAX) {
        parse_phrases_array(std::string_view(body).substr(ps, pe - ps),
                            bl.phrases);
    }
    bl.loaded_from_defaults = false;
    log_line("loaded json: %zu words, %zu phrases, padDefault=%d",
             bl.words.size(), bl.phrases.size(), bl.pad_default);
}

static bool stat_file(const char *path, uint64_t *mtime100ns, uint64_t *size) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d)) return false;
    if (mtime100ns) {
        *mtime100ns = ((uint64_t)d.ftLastWriteTime.dwHighDateTime << 32) |
                       (uint64_t)d.ftLastWriteTime.dwLowDateTime;
    }
    if (size) {
        *size = ((uint64_t)d.nFileSizeHigh << 32) | (uint64_t)d.nFileSizeLow;
    }
    return true;
}

/* ── WinRT engine bring-up ──────────────────────────────────────── */

static void ensure_apartment_once() {
    std::call_once(g_apartment_once, []() {
        try {
            init_apartment(apartment_type::multi_threaded);
        } catch (const hresult_error &e) {
            /* MTA already initialized by another init path -- fine. */
            (void)e;
        }
    });
}

static OcrEngine try_make_engine() {
    try {
        auto e = OcrEngine::TryCreateFromUserProfileLanguages();
        if (e) return e;
    } catch (const hresult_error &) {}
    try {
        return OcrEngine::TryCreateFromLanguage(Language(L"en-US"));
    } catch (const hresult_error &) {
        return OcrEngine{ nullptr };
    }
}

static SoftwareBitmap bgra_to_softwarebitmap(const uint8_t *bgra,
                                             uint32_t w, uint32_t h) {
    const uint32_t bytes = w * h * 4u;
    com_array<uint8_t> arr(bgra, bgra + bytes);
    IBuffer buffer = CryptographicBuffer::CreateFromByteArray(arr);
    return SoftwareBitmap::CreateCopyFromBuffer(buffer, BitmapPixelFormat::Bgra8,
                                                 (int32_t)w, (int32_t)h);
}

/* ── Matcher -- turn OcrResult into rects ────────────────────────── */

struct WordBox {
    std::string text;    /* lowercased, edge-punct-stripped */
    Rect2D      rect;
    int         line_idx;
};

static std::vector<Rect2D> match_and_collect(OcrResult const &result) {
    std::vector<WordBox> words;
    int line_idx = 0;
    try {
        for (auto const &line : result.Lines()) {
            for (auto const &w : line.Words()) {
                hstring t = w.Text();
                /* UTF-16 -> UTF-8 -> normalize */
                int need = WideCharToMultiByte(CP_UTF8, 0, t.c_str(), (int)t.size(),
                                                NULL, 0, NULL, NULL);
                std::string utf8((size_t)need, '\0');
                if (need > 0) {
                    WideCharToMultiByte(CP_UTF8, 0, t.c_str(), (int)t.size(),
                                        utf8.data(), need, NULL, NULL);
                }
                std::string norm = norm_token(utf8);
                auto r = w.BoundingRect();
                words.push_back({ std::move(norm),
                                   { (float)r.X, (float)r.Y, (float)r.Width, (float)r.Height },
                                   line_idx });
            }
            ++line_idx;
        }
    } catch (const hresult_error &e) {
        log_line("match: iteration threw hr=0x%lX", (long)e.code().value);
    }

    std::vector<Rect2D> rects;

    /* ── Single-word matches (exact + fuzzy) ─────────────── */
    for (auto const &wb : words) {
        if (wb.text.empty()) continue;
        bool hit = false;
        int hit_pad = g_bl.pad_default;
        /* exact first */
        for (auto const &e : g_bl.words) {
            if (e.norm == wb.text) { hit = true; hit_pad = e.padding; break; }
        }
        /* fuzzy if no exact hit */
        if (!hit) {
            for (auto const &e : g_bl.words) {
                if (e.fuzzy <= 0) continue;
                if ((int)std::abs((int)e.norm.size() - (int)wb.text.size()) > e.fuzzy) continue;
                if (lev_bounded(wb.text, e.norm, e.fuzzy) <= e.fuzzy) {
                    hit = true; hit_pad = e.padding; break;
                }
            }
        }
        if (hit) {
            Rect2D pr = wb.rect;
            pr.x -= (float)hit_pad; pr.y -= (float)hit_pad;
            pr.w += (float)hit_pad * 2.0f; pr.h += (float)hit_pad * 2.0f;
            rects.push_back(pr);
        }
    }

    /* ── Phrase substring matches (per-line joined-word text) ── */
    /* Group words by line index */
    std::vector<std::vector<size_t>> by_line;
    for (size_t i = 0; i < words.size(); ++i) {
        size_t li = (size_t)words[i].line_idx;
        if (by_line.size() <= li) by_line.resize(li + 1);
        by_line[li].push_back(i);
    }
    for (auto const &line_idxs : by_line) {
        if (line_idxs.empty()) continue;
        /* Build joined line + track per-word char ranges. */
        std::string joined;
        std::vector<std::pair<size_t,size_t>> word_ranges;   /* [start,end) in `joined` */
        for (size_t j = 0; j < line_idxs.size(); ++j) {
            if (j > 0) joined.push_back(' ');
            size_t s = joined.size();
            const auto &wb = words[line_idxs[j]];
            joined.append(wb.text);
            word_ranges.push_back({ s, joined.size() });
        }
        for (auto const &needle : g_bl.phrases) {
            if (needle.empty()) continue;
            size_t at = 0;
            while ((at = joined.find(needle, at)) != std::string::npos) {
                size_t end = at + needle.size();
                /* map char range -> word range, union bounding boxes */
                Rect2D u = { 0,0,0,0 };
                bool have = false;
                for (size_t j = 0; j < word_ranges.size(); ++j) {
                    auto [ws, we] = word_ranges[j];
                    if (we <= at || ws >= end) continue;
                    Rect2D r = words[line_idxs[j]].rect;
                    if (!have) { u = r; have = true; }
                    else u = rect_union(u, r);
                }
                if (have) {
                    u.x -= (float)g_bl.pad_default;
                    u.y -= (float)g_bl.pad_default;
                    u.w += (float)g_bl.pad_default * 2.0f;
                    u.h += (float)g_bl.pad_default * 2.0f;
                    rects.push_back(u);
                }
                at = end;
            }
        }
    }

    /* Dedupe */
    if (rects.size() > 1) merge_rects_inplace(rects);
    return rects;
}

} /* anon namespace */

/* ── Public C API ─────────────────────────────────────────────── */

extern "C" int ocr_daemon_init(const char *blacklist_path) {
    ensure_apartment_once();

    /* Engine */
    try {
        g_engine = try_make_engine();
    } catch (const hresult_error &e) {
        log_line("init: engine ctor threw hr=0x%lX", (long)e.code().value);
        g_engine = OcrEngine{ nullptr };
    }
    if (!g_engine) {
        log_line("init: no OCR engine -- is the Language.OCR FoD installed?");
        return -2;
    }

    /* Language count */
    try {
        auto langs = OcrEngine::AvailableRecognizerLanguages();
        g_lang_count = (int)langs.Size();
    } catch (const hresult_error &) {
        g_lang_count = 0;
    }

    /* Blacklist */
    g_bl = BlacklistState{};
    if (blacklist_path && blacklist_path[0]) {
        g_bl.path = blacklist_path;
        stat_file(blacklist_path, &g_bl.last_mtime100ns, &g_bl.last_size);
        std::string body;
        if (file_read_all(blacklist_path, body) && !body.empty()) {
            load_json_into(g_bl, body);
        } else {
            log_line("init: blacklist json missing/empty, using defaults");
            load_defaults_into(g_bl);
        }
    } else {
        load_defaults_into(g_bl);
    }

    log_line("init: OK, %d recognizer langs available", g_lang_count);
    return 0;
}

extern "C" void ocr_daemon_maybe_reload_blacklist(void) {
    if (g_bl.path.empty()) return;
    uint64_t mt = 0, sz = 0;
    if (!stat_file(g_bl.path.c_str(), &mt, &sz)) return;
    if (mt == g_bl.last_mtime100ns && sz == g_bl.last_size) return;
    std::string body;
    if (file_read_all(g_bl.path.c_str(), body) && !body.empty()) {
        load_json_into(g_bl, body);
        g_bl.last_mtime100ns = mt;
        g_bl.last_size       = sz;
    }
}

extern "C" int ocr_daemon_process_bgra(uint8_t *bgra, uint32_t width, uint32_t height) {
    if (!bgra || width == 0 || height == 0) return -1;
    if (!g_engine)                          return -3;
    ensure_apartment_once();

    ocr_daemon_maybe_reload_blacklist();

    SoftwareBitmap bmp{ nullptr };
    OcrResult      result{ nullptr };
    try {
        bmp    = bgra_to_softwarebitmap(bgra, width, height);
        result = g_engine.RecognizeAsync(bmp).get();
    } catch (const hresult_error &e) {
        log_line("process: recognize threw hr=0x%lX", (long)e.code().value);
        return -3;
    }

    std::vector<Rect2D> rects = match_and_collect(result);
    paint_rects_black(bgra, width, height, rects, 0 /* per-word pad already applied */);
    return (int)rects.size();
}

extern "C" void ocr_daemon_shutdown(void) {
    g_engine = OcrEngine{ nullptr };
    g_bl = BlacklistState{};
    g_lang_count = 0;
}

extern "C" int ocr_daemon_language_count(void) {
    return g_lang_count;
}
