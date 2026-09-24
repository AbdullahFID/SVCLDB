# dwmcore.dll multi-build compatibility matrix

Generated: 2026-09-24 16:54:36 -04:00
Samples:   23
Tool:      `tools/dwmcore_multi/` (pick + download + probe + aggregate)

| WinTag  | Version         | TDS         | Present   | Prologue                | IOP       | Shape       | PN1       | PN2       | SCP       | FFD       | GPB       | GD3D      | ACC       | Verdict |
|---------|-----------------|-------------|-----------|-------------------------|-----------|-------------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|---------|
| 11-21H2 | 10.0.22000.1042 | 0x46F96A3B | 0x79BD0 | REX push rbx (medium fn) | MISS | MISS | 0x1DDE18 | MISS | 0xD9968 | MISS | MISS | MISS | 0x103FB0 | SAFE-MODE (critical MISS) |
| 11-21H2 | 10.0.22000.194 | 0x85663CAB | 0x79810 | REX push rbx (medium fn) | MISS | MISS | 0x1DD928 | MISS | 0xD9D48 | MISS | MISS | MISS | 0x102900 | SAFE-MODE (critical MISS) |
| 11-21H2 | 10.0.22000.3147 | 0xB9184488 | 0xBD2E0 | REX push rbx (medium fn) | 0x104130 | OLD-GETTER | 0x1DF128 | MISS | 0xDCE98 | MISS | MISS | MISS | 0x108D60 | DEGRADED (no backbuffer chain) |
| 11-22H2 | 10.0.22621.169 | 0x76271961 | 0x81D70 | REX push rbx (medium fn) | 0x107A40 | OLD-GETTER | 0x1284FA | MISS | 0xF5DCC | MISS | MISS | MISS | 0x117320 | DEGRADED (no backbuffer chain) |
| 11-22H2 | 10.0.22621.3672 | 0xF8A2940E | 0xC9938 | REX push rbx (medium fn) | 0x107C00 | OLD-GETTER | 0x12A3BA | MISS | 0xF2518 | MISS | MISS | MISS | 0x119040 | DEGRADED (no backbuffer chain) |
| 11-22H2 | 10.0.22621.6060 | 0x610B3AB4 | 0xC9BC8 | REX push rbx (medium fn) | 0x107A90 | OLD-GETTER | 0x13159A | MISS | 0xF2828 | MISS | MISS | MISS | 0x120220 | DEGRADED (no backbuffer chain) |
| 11-23H2 | 10.0.22621.2215 | 0x69D28BD4 | 0x6A568 | REX push rbx (medium fn) | 0x101BF0 | OLD-GETTER | 0x1232BA | MISS | 0xEB118 | MISS | MISS | MISS | 0x111760 | DEGRADED (no backbuffer chain) |
| 11-23H2 | 10.0.22621.6489 | 0x43E5A0DE | 0xC9B78 | REX push rbx (medium fn) | 0x107910 | OLD-GETTER | 0x13116A | MISS | 0xF26A8 | MISS | MISS | MISS | 0x11FDF0 | DEGRADED (no backbuffer chain) |
| 11-23H2 | 10.0.22621.6931 | 0x9DB65844 | 0x79ED4 | REX push rbx (medium fn) | 0x107E30 | OLD-GETTER | 0x131E2A | MISS | 0xEB9E8 | MISS | MISS | MISS | 0x120B20 | DEGRADED (no backbuffer chain) |
| 11-24H2 | 10.0.26100.1 | 0x8C20FDE3 | 0x473C0 | REX push rbx (medium fn) | 0x1DBFE0 | OLD-GETTER | 0x2698DC | 0x1CC9AC | 0x46190 | 0x3E7669 | 0x1D80F0 | 0x1ED3E0 | 0x1D80C0 | FULL SUPPORT |
| 11-24H2 | 10.0.26100.5074 | 0xAED68C9C | 0x1BF7C0 | mov r11,rsp (frame stub) | 0x1FE540 | OLD-GETTER | 0x1E10E0 | 0x1E1114 | 0xC5BD8 | 0x406749 | 0x1FB190 | 0x20CAC0 | 0x419E0 | FULL SUPPORT |
| 11-24H2 | 10.0.26100.9278 | 0x9A1AF3BA | 0x22DD10 | REX push rbp (large fn) | 0x1EB470 | OLD-GETTER | 0x1100A8 | 0x1100DC | 0x11000C | 0x40E9C9 | 0x1E6740 | 0x1F9E90 | 0xCD100 | FULL SUPPORT |
| 11-26H1 | 10.0.28000.2113 | 0x02E408C6 | 0x1E476C | REX push rbp (large fn) | 0x1A8370 | OLD-GETTER | 0x1039E8 | 0x103A1C | 0x10A230 | 0x3E36B9 | 0x19D880 | 0x1B1A40 | 0x1ABF50 | FULL SUPPORT |
| 11-26H1 | 10.0.28000.2525 | 0xA01746A5 | 0x1E1DDC | REX push rbp (large fn) | 0x19F880 | OLD-GETTER | 0x3E648 | 0x3E67C | 0xD55E8 | 0x3E5669 | 0x195B00 | 0x1AB750 | 0x1A59E0 | FULL SUPPORT |
| 20H2 | 10.0.19041.1806 | 0x50C90657 | 0xE6AC4 | mov [rsp+X],rbx | MISS | MISS | 0xDA7F4 | MISS | 0xCF52C | MISS | MISS | MISS | 0xF0120 | SAFE-MODE (critical MISS) |
| 20H2 | 10.0.19041.2913 | 0x93C8D3E4 | 0xE6C1C | mov [rsp+X],rbx | MISS | MISS | 0x3C9C8 | MISS | 0xD3E74 | MISS | MISS | MISS | 0xF0400 | SAFE-MODE (critical MISS) |
| 20H2 | 10.0.19041.488 | 0x5EB75ED2 | 0xE1D44 | mov [rsp+X],rbx | MISS | MISS | 0xD83C8 | MISS | 0xCA604 | MISS | MISS | MISS | 0xE75D0 | SAFE-MODE (critical MISS) |
| 21H2 | 10.0.19041.1288 | 0x20EC5E90 | 0xE6210 | mov [rsp+X],rbx | MISS | MISS | 0x32E98 | MISS | 0xD42AC | MISS | MISS | MISS | 0xF11A0 | SAFE-MODE (critical MISS) |
| 21H2 | 10.0.19041.5854 | 0x863FC0EC | 0xEBA18 | mov [rsp+X],rbx | MISS | MISS | 0x2FC98 | MISS | 0xD8864 | MISS | MISS | MISS | 0xF5610 | SAFE-MODE (critical MISS) |
| 21H2 | 10.0.19041.7725 | 0xF1A0D9C4 | 0xEC128 | mov [rsp+X],rbx | MISS | MISS | 0x3D1D0 | MISS | 0xD9334 | MISS | MISS | MISS | 0xF7010 | SAFE-MODE (critical MISS) |
| 22H2 | 10.0.19041.1949 | 0x900808F9 | 0xE6B24 | mov [rsp+X],rbx | MISS | MISS | 0xDA854 | MISS | 0xCF55C | MISS | MISS | MISS | 0xF0490 | SAFE-MODE (critical MISS) |
| 22H2 | 10.0.19041.4597 | 0xAAFB1C6B | 0xEBCF8 | mov [rsp+X],rbx | MISS | MISS | 0x333B8 | MISS | 0xD7BFC | MISS | MISS | MISS | 0xF6220 | SAFE-MODE (critical MISS) |
| 22H2 | 10.0.19041.6328 | 0x3CE5B7F5 | 0xEBBD8 | mov [rsp+X],rbx | MISS | MISS | 0x2FC98 | MISS | 0xD8A44 | MISS | MISS | MISS | 0xF5A40 | SAFE-MODE (critical MISS) |

## Verdict summary

- **SAFE-MODE (critical MISS)** &mdash; 11 build(s)
- **DEGRADED (no backbuffer chain)** &mdash; 7 build(s)
- **FULL SUPPORT** &mdash; 5 build(s)

## IsOverlayPrevented prologue distribution

- **OLD-GETTER** &mdash; 12 build(s)
- **MISS** &mdash; 11 build(s)

## Present prologue distribution

- **REX push rbx (medium fn)** &mdash; 10 build(s)
- **mov [rsp+X],rbx** &mdash; 9 build(s)
- **REX push rbp (large fn)** &mdash; 3 build(s)
- **mov r11,rsp (frame stub)** &mdash; 1 build(s)
