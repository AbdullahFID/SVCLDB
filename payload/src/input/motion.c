/* ================================================================== *
 * motion.c -- Humanized Sigma-Lognormal mouse motion (see motion.h).   *
 * ================================================================== */
#include <windows.h>
#include <math.h>
#include "motion.h"
#include "inject.h"

static volatile LONG g_cancel = 0;
void mot_set_cancel(int on) { InterlockedExchange(&g_cancel, on ? 1 : 0); }
int  mot_cancelled(void)    { return InterlockedCompareExchange(&g_cancel, 0, 0) != 0; }

/* ── RNG (xorshift64* seeded from perf counter) ─────────────────── */
static unsigned long long g_rng;
static void rng_seed_once(void) {
    if (g_rng) return;
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    g_rng = (unsigned long long)t.QuadPart ^ (0x9E3779B97F4A7C15ULL * (GetTickCount64() + 1));
    if (!g_rng) g_rng = 0x1234567890ABCDEFULL;
}
static double rnd(void) { /* [0,1) */
    rng_seed_once();
    unsigned long long x = g_rng;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    g_rng = x;
    unsigned long long r = x * 0x2545F4914F6CDD1DULL;
    return (double)(r >> 11) * (1.0 / 9007199254740992.0);
}
static double gauss(void) { /* Box-Muller */
    double u = 0, v = 0;
    while (u <= 1e-12) u = rnd();
    while (v <= 1e-12) v = rnd();
    return sqrt(-2.0 * log(u)) * cos(6.283185307179586 * v);
}

double mot_lognormal_ms(double median, double sigma, double lo, double hi) {
    double v = median * exp(sigma * gauss());
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    return v;
}

/* ── precise sleep (QPC hybrid; avoids winmm dependency) ─────────── */
void mot_precise_sleep(double ms) {
    if (ms <= 0.0) return;
    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    double target = ms / 1000.0 * (double)freq.QuadPart;
    /* Coarse-sleep the bulk (leave ~1.5ms for the spin) to save CPU. */
    if (ms > 3.0) Sleep((DWORD)(ms - 1.5));
    for (;;) {
        QueryPerformanceCounter(&now);
        if ((double)(now.QuadPart - start.QuadPart) >= target) break;
        YieldProcessor();
    }
}

/* ── math ───────────────────────────────────────────────────────── */
static double cubic(double p0, double p1, double p2, double p3, double t) {
    double u = 1.0 - t;
    return u*u*u*p0 + 3*u*u*t*p1 + 3*u*t*t*p2 + t*t*t*p3;
}
#define PEAK_U 0.35
static double ballistic_ease(double u) {
    double A = PEAK_U;
    if (u <= A) return (u * u) / A;
    return A + (2.0 / (1.0 - A)) * (u - 0.5 * u * u - A + 0.5 * A * A);
}

#define JITTER_DRIFT  0.55
#define JITTER_REVERT 0.22
#define JITTER_CLAMP  2.0

static void ballistic_glide(double sx, double sy, double gx, double gy) {
    double dx = gx - sx, dy = gy - sy;
    double dist = sqrt(dx*dx + dy*dy);
    if (dist < 0.5) return;

    double nx = -dy / dist, ny = dx / dist;
    double offset = (rnd() - 0.5) * 0.30 * dist;
    double cp1x = sx + dx * 0.25 + nx * offset * 0.75;
    double cp1y = sy + dy * 0.25 + ny * offset * 0.75;
    double cp2x = sx + dx * 0.65 + nx * offset * 0.20;
    double cp2y = sy + dy * 0.65 + ny * offset * 0.20;

    int steps = (int)(10 + (log(dist / 8.0 > 2.0 ? dist / 8.0 : 2.0) / 0.6931471805599453) * 6.0 + 0.5);
    if (steps < 10) steps = 10;
    if (steps > 45) steps = 45;

    double jx = 0, jy = 0, prevX = sx, prevY = sy;
    for (int i = 1; i <= steps; i++) {
        if (mot_cancelled()) return;
        double u = (double)i / steps;
        double t = ballistic_ease(u);
        double px = cubic(sx, cp1x, cp2x, gx, t);
        double py = cubic(sy, cp1y, cp2y, gy, t);

        double v = sqrt((px - prevX)*(px - prevX) + (py - prevY)*(py - prevY));
        prevX = px; prevY = py;
        double tremorScale = 1.5 - v / 25.0;
        if (tremorScale < 0.25) tremorScale = 0.25;
        if (tremorScale > 1.5)  tremorScale = 1.5;

        jx = (jx + gauss() * JITTER_DRIFT * tremorScale) * (1.0 - JITTER_REVERT);
        jy = (jy + gauss() * JITTER_DRIFT * tremorScale) * (1.0 - JITTER_REVERT);
        if (jx >  JITTER_CLAMP) jx =  JITTER_CLAMP; else if (jx < -JITTER_CLAMP) jx = -JITTER_CLAMP;
        if (jy >  JITTER_CLAMP) jy =  JITTER_CLAMP; else if (jy < -JITTER_CLAMP) jy = -JITTER_CLAMP;

        double decay = 1.0 - u;
        int emitX = (int)(px + jx * decay + 0.5);
        int emitY = (int)(py + jy * decay + 0.5);
        inj_move_screen(emitX, emitY);

        double peakDist = fabs(u - PEAK_U);
        double peakDistMax = (PEAK_U > 1.0 - PEAK_U) ? PEAK_U : (1.0 - PEAK_U);
        double peakBias = 1.0 - peakDist / peakDistMax;
        double base = 4.0 + (1.0 - peakBias) * 12.0;
        double stepDelay = base * exp(0.20 * gauss());
        if (stepDelay < 2.0) stepDelay = 2.0;
        mot_precise_sleep(stepDelay);
    }
}

static void cursor_pos(int *x, int *y) {
    POINT p;
    if (GetCursorPos(&p)) { *x = p.x; *y = p.y; }
    else { *x = 0; *y = 0; }
}

void mot_glide_to_screen(int gx, int gy, int humanize) {
    int sx, sy; cursor_pos(&sx, &sy);
    if (!humanize) {
        inj_move_screen(gx, gy);
        mot_precise_sleep(15);
        return;
    }
    double dx = gx - sx, dy = gy - sy;
    double dist = sqrt(dx*dx + dy*dy);
    if (dist < 15.0) {
        inj_move_screen(gx, gy);
        mot_precise_sleep(10 + rnd() * 20);
        return;
    }

    int canOvershoot = dist >= 200.0;
    int willOvershoot = canOvershoot && (rnd() < 0.15);
    double overshootPct = willOvershoot ? (0.02 + rnd() * 0.06) : 0.0;
    double ballisticFrac = willOvershoot ? (1.0 + overshootPct) : 0.95;

    double bx = sx + dx * ballisticFrac;
    double by = sy + dy * ballisticFrac;
    ballistic_glide(sx, sy, bx, by);
    if (mot_cancelled()) return;

    mot_precise_sleep(mot_lognormal_ms(80, 0.35, 35, 220));
    if (mot_cancelled()) return;

    double fdx = gx - bx, fdy = gy - by;
    if (sqrt(fdx*fdx + fdy*fdy) >= 2.0) {
        ballistic_glide(bx, by, gx, gy);
        if (mot_cancelled()) return;
    }
    inj_move_screen(gx, gy);   /* exact landing */
}

static void btn(int button, int down) {
    if (button == 1)      inj_rbtn(down);
    else if (button == 2) inj_mbtn(down);
    else                  inj_lbtn(down);
}

void mot_click_in_place(int button, int count, int humanize) {
    if (count < 1) count = 1;
    for (int i = 0; i < count; i++) {
        if (mot_cancelled()) return;
        double dwell = humanize ? mot_lognormal_ms(85, 0.30, 48, 240)
                                : (50.0 + rnd() * 80.0);
        btn(button, 1);
        mot_precise_sleep(dwell);
        btn(button, 0);              /* always release */
        if (i < count - 1) mot_precise_sleep(mot_lognormal_ms(95, 0.25, 55, 180));
    }
}

void mot_scroll_ticks(const char *direction, int amount) {
    int up = (direction && (direction[0] == 'u' || direction[0] == 'U'));
    int delta = up ? 120 : -120;
    if (amount < 1) amount = 1;
    for (int i = 0; i < amount; i++) {
        if (mot_cancelled()) return;
        inj_wheel(delta);
        mot_precise_sleep(60 + rnd() * 60);
    }
}

void mot_drag_screen(int x1, int y1, int x2, int y2, int humanize) {
    mot_glide_to_screen(x1, y1, humanize);
    if (mot_cancelled()) return;
    mot_precise_sleep(120 + rnd() * 180);
    inj_lbtn(1);
    mot_precise_sleep(mot_lognormal_ms(85, 0.30, 60, 200));
    if (mot_cancelled()) { inj_lbtn(0); return; }
    ballistic_glide(x1, y1, x2, y2);
    if (mot_cancelled()) { inj_lbtn(0); return; }
    mot_precise_sleep(mot_lognormal_ms(60, 0.30, 30, 150));
    inj_lbtn(0);
    mot_precise_sleep(80);
}
